//! Background local-proxy management for application access.
//!
//! Teleport apps behind an L7 load balancer need a local proxy
//! (`tsh proxy app`) to be reachable. Unlike SSH/kube (which take over the
//! terminal), an app proxy runs in the **background** while the user works in
//! their browser; the TUI stays up and stops the proxy on demand.

use std::io::{self, BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError, mpsc};
use std::thread::{self, sleep};
use std::time::Duration;

use application::command as cmd;
use domain::value::{ClusterName, Hostname, Identifier, Login, ResourceName};

/// How many fresh ports to try when an auto-allocated one is lost to the TOCTOU
/// race (see [`start_listening_proxy`]). Small: a real collision is rare, and a
/// genuine failure (login/MFA) is diagnosed and stops the loop after one try.
const PORT_RETRIES: usize = 3;

/// Outcome of one proxy-start attempt, so the caller can tell a lost-port race
/// (worth retrying on a new port) from a real failure (retrying won't help).
enum Attempt<T> {
    Ready(T),
    /// The child exited before it was ready - the auto-allocated port was almost
    /// certainly taken between `free_port()` releasing it and the child binding
    /// it. Retrying on a fresh port should succeed.
    PortLost,
    /// The child is alive but never became ready (stuck on a login/MFA prompt it
    /// can't answer with detached stdin, say) - not a port problem, so surface it.
    Failed(io::Error),
}

/// Wait until the child accepts a TCP connection on `port`. A child that exits
/// first lost the port ([`Attempt::PortLost`], retryable); one still alive after
/// the grace period is stuck on something a new port wouldn't fix
/// ([`Attempt::Failed`]).
///
/// "Something answers on the port" alone is not proof the answer is *our*
/// proxy: a process that grabbed the port first would answer while the child
/// fails to bind and exits. Callers check the port is free before spawning, and
/// a connect only counts while the child is still running.
fn await_listen(child: &mut Child, port: u16) -> Attempt<()> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for _ in 0..30 {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return Attempt::PortLost;
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return match child.try_wait() {
                Ok(None) => Attempt::Ready(()),
                // Exited (or unknowable): whatever answered is not our proxy.
                _ => Attempt::PortLost,
            };
        }
        sleep(Duration::from_millis(100));
    }
    Attempt::Failed(io::Error::new(
        io::ErrorKind::TimedOut,
        "proxy did not start in time (log into the app/db first, or MFA may be required)",
    ))
}

/// Spawn a background proxy that becomes ready by *listening* on a local port
/// (app / db). For an explicit `port` a single attempt is made - a conflict on
/// the user's chosen port is theirs to resolve, not silently relocated. For an
/// auto port the OS-picked number can be stolen in the TOCTOU window between
/// `free_port()` and the child's own bind, so a lost race retries on a fresh one.
/// Returns the live child plus the port it is actually listening on.
fn start_listening_proxy(
    port: Option<u16>,
    spawn: impl Fn(u16) -> io::Result<Child>,
) -> io::Result<(Child, u16)> {
    if let Some(p) = port {
        // Refuse up front if something already listens there: otherwise it would
        // answer the readiness probe and the browser would be sent to it.
        if !port_is_free(p) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "the requested local port is already in use",
            ));
        }
        let mut child = spawn(p)?;
        return match await_listen(&mut child, p) {
            Attempt::Ready(()) => Ok((child, p)),
            Attempt::PortLost => {
                stop_child(&mut child);
                Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "the requested local port is already in use",
                ))
            }
            Attempt::Failed(e) => {
                stop_child(&mut child);
                Err(e)
            }
        };
    }
    let mut last: Option<io::Error> = None;
    for _ in 0..PORT_RETRIES {
        let port = free_port()?;
        let mut child = spawn(port)?;
        match await_listen(&mut child, port) {
            Attempt::Ready(()) => return Ok((child, port)),
            // Racey port: the child already exited - reap it and try another.
            Attempt::PortLost => {
                stop_child(&mut child);
                last = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "proxy did not start (a free local port kept being taken)",
                ));
            }
            // Real failure: stop retrying and surface it.
            Attempt::Failed(e) => {
                stop_child(&mut child);
                return Err(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "proxy did not start")))
}

/// Start `tsh proxy app` ([`cmd::proxy_app`]) in the background, wait until it
/// is listening, open the browser at the local URL, and return the child handle
/// (to stop it later) plus the URL.
///
/// SECURITY: argv only (built by [`cmd`] from validated value objects), no
/// shell. The URL is a fixed `http://127.0.0.1:<port>` we control.
///
/// `port` is the caller-requested local port; `None` allocates a random free
/// one (retried on a fresh port if it loses the TOCTOU race - see
/// [`start_listening_proxy`]). A requested port already in use is an error.
///
/// # Errors
/// Returns an error if a port can't be allocated, the proxy can't be spawned,
/// or it doesn't start listening in time.
pub(crate) fn open_app(
    tsh: &Path,
    name: &ResourceName,
    cluster: &ClusterName,
    port: Option<u16>,
) -> io::Result<(Child, String)> {
    let (child, port) = start_listening_proxy(port, |p| {
        spawn_tracked(
            Command::new(tsh)
                .args(cmd::proxy_app(cluster, name, p))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
    })?;
    let url = format!("http://127.0.0.1:{port}");
    open_browser(&url);
    Ok((child, url))
}

/// Start `tsh proxy db --tunnel` ([`cmd::proxy_db`]) in the background and
/// return the child plus the local endpoint (`127.0.0.1:<port>`) for the
/// user to point a DB client at. `--tunnel` authenticates via the database's
/// client certificate, so the GUI tool connects without extra credentials.
///
/// `port` is the requested local port; `None` allocates a random free one
/// (retried on a fresh port if it loses the TOCTOU race).
///
/// # Errors
/// Returns an error if a port can't be allocated, the proxy can't spawn, or it
/// doesn't start listening in time.
pub(crate) fn open_db(
    tsh: &Path,
    name: &ResourceName,
    cluster: &ClusterName,
    port: Option<u16>,
) -> io::Result<(Child, String)> {
    let (child, port) = start_listening_proxy(port, |p| {
        spawn_tracked(
            Command::new(tsh)
                .args(cmd::proxy_db(cluster, name, p))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
    })?;
    Ok((child, format!("127.0.0.1:{port}")))
}

/// Start `tsh proxy kube` ([`cmd::proxy_kube`]) in the background and return
/// the child plus the `KUBECONFIG` path it printed.
///
/// Unlike `tsh proxy kube --exec`, the proxy stays silent in the background and
/// we hand off a clean shell ourselves - so `tsh`'s raw-mode preamble never
/// corrupts the user's terminal (no "staircase" output, resize works).
///
/// The auto-allocated local port can be lost to the TOCTOU race between
/// `free_port()` and the child's bind, so a lost race retries on a fresh port
/// (see [`kube_proxy_attempt`]).
///
/// # Errors
/// Returns an error if a port can't be allocated, the proxy can't spawn, or it
/// doesn't print its kubeconfig path in time.
pub(crate) fn start_kube_proxy(
    tsh: &Path,
    kube: &ResourceName,
    cluster: &ClusterName,
    user: Option<&Identifier>,
) -> io::Result<(Child, String)> {
    let mut last: Option<io::Error> = None;
    for _ in 0..PORT_RETRIES {
        let port = free_port()?;
        match kube_proxy_attempt(tsh, kube, cluster, user, port) {
            Attempt::Ready(ok) => return Ok(ok),
            // Racey port (child already gone): try another.
            Attempt::PortLost => {
                last = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "kube proxy could not bind a free local port",
                ));
            }
            // Real failure (login/MFA, spawn error): stop and surface it.
            Attempt::Failed(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "kube proxy did not start")))
}

/// One `tsh proxy kube` start attempt on a specific `port`. Readiness is the
/// `KUBECONFIG` line printed on stdout. If the wait fails, a child that has
/// *exited* lost the port ([`Attempt::PortLost`], retryable); one still *alive*
/// is stuck on login/MFA it can't answer with detached stdin ([`Attempt::Failed`]).
fn kube_proxy_attempt(
    tsh: &Path,
    kube: &ResourceName,
    cluster: &ClusterName,
    user: Option<&Identifier>,
    port: u16,
) -> Attempt<(Child, String)> {
    let mut command = Command::new(tsh);
    command
        .args(cmd::proxy_kube(cluster, kube, user, port))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = match spawn_tracked(&mut command) {
        Ok(c) => c,
        Err(e) => return Attempt::Failed(e),
    };

    let Some(stdout) = child.stdout.take() else {
        stop_child(&mut child);
        return Attempt::Failed(io::Error::other("proxy stdout unavailable"));
    };

    // Read the proxy's output on a thread; report the kubeconfig path once seen,
    // then keep draining so the pipe never blocks the proxy.
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let mut sent = false;
        for line in reader.lines().map_while(Result::ok) {
            if !sent && let Some(path) = parse_kubeconfig(&line) {
                let _ = tx.send(path);
                sent = true;
            }
        }
    });

    if let Ok(path) = rx.recv_timeout(Duration::from_secs(8)) {
        return Attempt::Ready((child, path));
    }
    // A taken port makes tsh exit at once (stdout EOF ends the reader, so the
    // recv fails fast); a still-alive child is stuck on something a new port
    // won't fix.
    let exited = matches!(child.try_wait(), Ok(Some(_)));
    stop_child(&mut child);
    if exited {
        Attempt::PortLost
    } else {
        Attempt::Failed(io::Error::new(
            io::ErrorKind::TimedOut,
            "kube proxy did not report its kubeconfig in time",
        ))
    }
}

/// Start `tsh ssh -L <spec> -N` ([`cmd::ssh_forward`]) in the background (no
/// shell - a pure local port-forward) and return the child once the tunnel is
/// up. `spec` is a validated `[bind:]port:host:hostport` forward; no `user` lets
/// tsh pick the default login.
///
/// Readiness: see [`start_forward`].
///
/// SECURITY: argv only, no shell; `cluster`/`user`/`host` are validated value
/// objects and `spec` is checked by the form.
///
/// # Errors
/// Returns an error if the child can't spawn or the tunnel doesn't come up.
pub(crate) fn start_ssh_forward(
    tsh: &Path,
    cluster: &ClusterName,
    user: Option<&Login>,
    host: &Hostname,
    spec: &str,
) -> io::Result<Child> {
    start_forward(local_forward_port(spec), || {
        spawn_tracked(
            Command::new(tsh)
                .args(cmd::ssh_forward(cluster, user, host, spec))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
    })
}

/// Spawn a forward and wait until it is up. With a localhost bind (`local`), the
/// port must be free beforehand (else a squatter would answer the probe) and the
/// forward is ready only once the port answers *while the child is alive*; a
/// child still alive but never listening (stuck on a login/MFA prompt it can't
/// get with a detached stdin) is an error, not a silent "forward up". A
/// non-local bind can't be probed by connecting, so a child that survives a
/// short grace period counts as up. A child that exits early is always an error.
fn start_forward(
    local: Option<u16>,
    spawn: impl FnOnce() -> io::Result<Child>,
) -> io::Result<Child> {
    let exited = || {
        io::Error::other(
            "forward exited immediately (not logged in / MFA required, or port in use)",
        )
    };
    if let Some(port) = local {
        if !port_is_free(port) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "the forward's local port is already in use",
            ));
        }
        let mut child = spawn()?;
        return match await_listen(&mut child, port) {
            Attempt::Ready(()) => Ok(child),
            Attempt::PortLost => {
                stop_child(&mut child);
                Err(exited())
            }
            Attempt::Failed(_) => {
                stop_child(&mut child);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "forward did not start listening in time (log in first, or MFA may be required)",
                ))
            }
        };
    }
    let mut child = spawn()?;
    for _ in 0..20 {
        match child.try_wait() {
            Ok(None) => {}
            Ok(Some(_)) => {
                stop_child(&mut child);
                return Err(exited());
            }
            Err(e) => {
                stop_child(&mut child);
                return Err(e);
            }
        }
        sleep(Duration::from_millis(100));
    }
    Ok(child)
}

/// The local (bind-side) port of a `-L` spec, but only when it binds localhost -
/// `port:host:hostport` (implicit localhost) or `127.0.0.1:port:host:hostport`.
/// Returns `None` for a non-local bind (we can't confirm those by connecting).
fn local_forward_port(spec: &str) -> Option<u16> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.as_slice() {
        [port, _host, _hostport] => port.parse().ok(),
        [bind, port, _host, _hostport] if matches!(*bind, "127.0.0.1" | "localhost" | "::1") => {
            port.parse().ok()
        }
        _ => None,
    }
}

/// Extract the path from a `export KUBECONFIG="..."` (or `KUBECONFIG=...`) line.
fn parse_kubeconfig(line: &str) -> Option<String> {
    let l = line.trim();
    let rest = l
        .strip_prefix("export KUBECONFIG=")
        .or_else(|| l.strip_prefix("KUBECONFIG="))?;
    Some(rest.trim().trim_matches('"').to_owned())
}

/// Resolve the program + args for a Kubernetes launcher tool. `shell` opens the
/// user's login shell; any other value runs that command directly.
#[must_use]
pub(crate) fn tool_command(tool: &str) -> (String, Vec<String>) {
    if tool == "shell" {
        let prog = default_shell();
        (prog, Vec::new())
    } else {
        (tool.to_owned(), Vec::new())
    }
}

#[cfg(unix)]
fn default_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned())
}

#[cfg(windows)]
fn default_shell() -> String {
    std::env::var("ComSpec").unwrap_or_else(|_| "cmd".to_owned())
}

/// Ask the OS to allocate a free localhost port (bind to :0, then release). The
/// port can be re-taken before the child binds it, so callers that use this for
/// an auto port go through [`start_listening_proxy`] / [`start_kube_proxy`],
/// which retry on a fresh port when that race is lost.
fn free_port() -> io::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

/// Whether nothing is bound to localhost `port` right now (a bind succeeds and
/// is released at once). A listener on the wildcard address also makes this
/// bind fail, so it counts as taken.
fn port_is_free(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

/// Put a background proxy child in its **own process group** (leader = the child)
/// so its whole tree can be signalled together by [`stop_child`]. `tsh proxy`
/// may fork helper processes; without this, killing only the direct child would
/// orphan those grandchildren and leak the port/tunnel. No-op off Unix (job
/// control differs; there is no argv/no-shell concern here either way).
fn own_group(cmd: &mut Command) -> &mut Command {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd
}

/// Pids of the live background proxy children, each the leader of its own
/// process group ([`own_group`]). A worker thread blocked in a start-up wait
/// owns its `Child`, and quitting just abandons that thread (std's `Child` drop
/// doesn't kill), so the event loop can't reach those children - this registry
/// can: [`ChildRegistry::shutdown`] kills every group still listed.
///
/// A pid stays listed until [`stop_child`] reaps it, so it cannot have been
/// recycled for an unrelated process when the shutdown signals it.
#[derive(Debug)]
struct ChildRegistry(Mutex<Tracked>);

#[derive(Debug)]
struct Tracked {
    /// Set by [`ChildRegistry::shutdown`]: a worker still retrying after it
    /// must not start a fresh child nobody would stop.
    closed: bool,
    pids: Vec<u32>,
}

impl ChildRegistry {
    const fn new() -> Self {
        Self(Mutex::new(Tracked {
            closed: false,
            pids: Vec::new(),
        }))
    }

    fn lock(&self) -> MutexGuard<'_, Tracked> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Spawn `cmd` in its own process group and list it. Spawning under the lock
    /// means a concurrent [`Self::shutdown`] either sees the child or refuses it.
    fn spawn(&self, cmd: &mut Command) -> io::Result<Child> {
        let mut tracked = self.lock();
        if tracked.closed {
            return Err(io::Error::other("shutting down"));
        }
        let child = own_group(cmd).spawn()?;
        tracked.pids.push(child.id());
        // End of the critical section: the child is listed, so a shutdown
        // taking the lock from here on will see it.
        drop(tracked);
        Ok(child)
    }

    /// Drop `pid` from the list (the caller is about to reap it).
    fn forget(&self, pid: u32) {
        self.lock().pids.retain(|&p| p != pid);
    }

    /// Refuse further spawns and kill the process group of every listed child.
    fn shutdown(&self) {
        let mut tracked = self.lock();
        tracked.closed = true;
        for pid in tracked.pids.drain(..) {
            kill_group(pid);
        }
    }
}

/// Every background proxy child of this process (see [`ChildRegistry`]).
static CHILDREN: ChildRegistry = ChildRegistry::new();

/// Spawn a background proxy child in its own process group, registered so
/// [`shutdown`] can stop it even while a worker thread still holds it.
fn spawn_tracked(cmd: &mut Command) -> io::Result<Child> {
    CHILDREN.spawn(cmd)
}

/// Kill every background proxy child still running - including those owned by
/// worker threads mid start-up - and refuse to start new ones. Called once as
/// the TUI exits.
pub(crate) fn shutdown() {
    CHILDREN.shutdown();
}

/// SIGKILL the process group led by `pid`. Errors (already gone) are ignored.
/// Off Unix there is no process-group signal without extra dependencies, so
/// this is a no-op; the direct child is still killed by [`stop_child`].
fn kill_group(pid: u32) {
    #[cfg(unix)]
    {
        // The leader's pgid equals its pid.
        if let Some(pgid) = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
        }
    }
    #[cfg(not(unix))]
    let _ = pid;
}

/// Stop a background proxy child **and its whole process group**, then reap it.
/// Because the child was spawned as its own group leader ([`own_group`]), a
/// signal to the group (`kill(-pgid)`) also reaches any helper `tsh` forked, so
/// nothing is orphaned. The direct `kill`/`wait` still run as a fallback (and to
/// reap the leader). Off Unix, only the direct child is killed.
pub(crate) fn stop_child(child: &mut Child) {
    // Unlist first, so a concurrent shutdown never signals a reaped (recyclable)
    // pid; signal the group before reaping, while the pid is still valid.
    CHILDREN.forget(child.id());
    kill_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

/// Open the default browser at `url` (best-effort, per-OS, no shell metachars -
/// the URL is a controlled localhost address).
fn open_browser(url: &str) {
    let mut cmd = browser_command(url);
    let _ = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[cfg(target_os = "linux")]
fn browser_command(url: &str) -> Command {
    let mut c = Command::new("xdg-open");
    c.arg(url);
    c
}

#[cfg(target_os = "macos")]
fn browser_command(url: &str) -> Command {
    let mut c = Command::new("open");
    c.arg(url);
    c
}

#[cfg(target_os = "windows")]
fn browser_command(url: &str) -> Command {
    // `cmd /C start "" <url>` - empty title arg so the URL isn't taken as title.
    let mut c = Command::new("cmd");
    c.args(["/C", "start", "", url]);
    c
}

#[cfg(test)]
mod tests {
    use super::local_forward_port;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    /// Serialises the tests that pick and probe localhost ports: a port one test
    /// releases (`free_port`) could otherwise be handed to another test's `:0`
    /// bind, which would answer the first test's readiness probe.
    static PORTS: Mutex<()> = Mutex::new(());

    fn ports() -> MutexGuard<'static, ()> {
        PORTS.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // A child that exits at once never listens, so every auto-port attempt reads
    // as a lost port (`PortLost`); the loop should exhaust `PORT_RETRIES` and then
    // give up with an error rather than hang or succeed. `true` fits: it exits 0
    // immediately and binds nothing.
    #[cfg(unix)]
    #[test]
    fn auto_port_gives_up_after_retries_when_child_never_listens() {
        use super::{PORT_RETRIES, start_listening_proxy};
        use std::process::{Command, Stdio};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let _ports = ports();
        let attempts = AtomicUsize::new(0);
        let result = start_listening_proxy(None, |_port| {
            attempts.fetch_add(1, Ordering::Relaxed);
            Command::new("true")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        });
        assert!(result.is_err(), "should give up, not succeed");
        assert_eq!(attempts.load(Ordering::Relaxed), PORT_RETRIES);
    }

    // A requested port that something already listens on is refused before any
    // child is spawned: the squatter must not be mistaken for the proxy.
    #[cfg(unix)]
    #[test]
    fn explicit_port_already_in_use_is_refused_without_spawning() {
        use super::start_listening_proxy;
        use std::net::{Ipv4Addr, TcpListener};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let _ports = ports();
        let squatter = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = squatter.local_addr().expect("addr").port();
        let spawns = AtomicUsize::new(0);
        let result = start_listening_proxy(Some(port), |_| {
            spawns.fetch_add(1, Ordering::Relaxed);
            std::process::Command::new("true").spawn()
        });
        let err = result.expect_err("port in use must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        assert_eq!(spawns.load(Ordering::Relaxed), 0);
    }

    // Something answers on the port but the child has already died (it lost the
    // bind): that answer is not our proxy, so it must not read as ready.
    #[cfg(unix)]
    #[test]
    fn a_dead_child_is_not_ready_even_if_the_port_answers() {
        use super::{Attempt, await_listen};
        use std::net::{Ipv4Addr, TcpListener};
        use std::process::{Command, Stdio};

        let _ports = ports();
        let squatter = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = squatter.local_addr().expect("addr").port();
        let mut child = Command::new("true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn true");
        // Reaped: `try_wait` now reports the cached exit status deterministically.
        child.wait().expect("wait");
        assert!(matches!(await_listen(&mut child, port), Attempt::PortLost));
    }

    // Proof that stop_child reaches grandchildren: the direct child forks a
    // `sleep` (a grandchild) and prints its pid. Killing only the direct child
    // would orphan it; a process-group kill takes it down too. Linux-only (uses
    // /proc for a liveness probe on a process that isn't ours to waitpid).
    // A localhost forward whose child stays alive but never listens (stuck on an
    // MFA prompt, say) must fail rather than report "forward up".
    #[cfg(unix)]
    #[test]
    fn forward_that_never_listens_is_an_error() {
        use super::{free_port, start_forward};
        use std::process::{Command, Stdio};

        let _ports = ports();
        let port = free_port().expect("port");
        let result = start_forward(Some(port), || {
            Command::new("sleep")
                .arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        });
        let err = result.expect_err("never listening must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    // A forward whose local port is already taken is refused before spawning.
    #[cfg(unix)]
    #[test]
    fn forward_on_a_taken_port_is_refused_without_spawning() {
        use super::start_forward;
        use std::net::{Ipv4Addr, TcpListener};

        let _ports = ports();
        let squatter = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = squatter.local_addr().expect("addr").port();
        let mut spawned = false;
        let result = start_forward(Some(port), || {
            spawned = true;
            std::process::Command::new("true").spawn()
        });
        let err = result.expect_err("port in use must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        assert!(!spawned);
    }

    // A forward that answers on its port while alive is ready.
    #[cfg(unix)]
    #[test]
    fn forward_listening_while_alive_is_ready() {
        use super::{free_port, start_forward, stop_child};
        use std::net::{Ipv4Addr, TcpListener};
        use std::process::{Command, Stdio};

        let _ports = ports();
        let port = free_port().expect("port");
        let mut listener = None;
        let mut child = start_forward(Some(port), || {
            let child = Command::new("sleep")
                .arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            // Stand in for the tunnel's listener once the port was checked free.
            listener = Some(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("bind"));
            child
        })
        .expect("ready");
        assert!(listener.is_some());
        stop_child(&mut child);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stop_child_kills_the_whole_process_group() {
        use super::{own_group, stop_child};
        use std::io::{BufRead, BufReader};
        use std::path::Path;
        use std::process::{Command, Stdio};
        use std::thread::sleep;
        use std::time::Duration;

        let mut child = own_group(
            Command::new("sh")
                .args(["-c", "sleep 30 & echo $!; sleep 30"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null()),
        )
        .spawn()
        .expect("spawn sh");

        let stdout = child.stdout.take().expect("stdout");
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .expect("read grandchild pid");
        let gpid: u32 = line.trim().parse().expect("grandchild pid");
        let alive = format!("/proc/{gpid}");
        assert!(Path::new(&alive).exists(), "grandchild should start alive");

        stop_child(&mut child);

        // Signalled via the group, the grandchild exits and init reaps it, so its
        // /proc entry disappears. Poll briefly to absorb the reap race.
        let gone = (0..100).any(|_| {
            if Path::new(&alive).exists() {
                sleep(Duration::from_millis(20));
                false
            } else {
                true
            }
        });
        assert!(gone, "grandchild {gpid} should die with the group");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn registry_shutdown_kills_tracked_groups_and_refuses_new_spawns() {
        use super::ChildRegistry;
        use std::io::{BufRead, BufReader};
        use std::path::Path;
        use std::process::{Command, Stdio};
        use std::thread::sleep;
        use std::time::Duration;

        // A local registry: shutting down the global one would break other tests.
        let registry = ChildRegistry::new();
        let mut child = registry
            .spawn(
                Command::new("sh")
                    .args(["-c", "sleep 30 & echo $!; sleep 30"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null()),
            )
            .expect("spawn sh");
        let stdout = child.stdout.take().expect("stdout");
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .expect("read grandchild pid");
        let gpid: u32 = line.trim().parse().expect("grandchild pid");
        let alive = format!("/proc/{gpid}");
        assert!(Path::new(&alive).exists(), "grandchild should start alive");

        // As if a worker thread still held `child` when the TUI quit.
        registry.shutdown();

        let status = child.wait().expect("reap leader");
        assert!(!status.success(), "leader should have been killed");
        let gone = (0..100).any(|_| {
            if Path::new(&alive).exists() {
                sleep(Duration::from_millis(20));
                false
            } else {
                true
            }
        });
        assert!(gone, "grandchild {gpid} should die with the group");
        assert!(
            registry.spawn(&mut Command::new("true")).is_err(),
            "no new child once shut down"
        );
    }

    #[test]
    fn local_forward_port_parses_localhost_binds_only() {
        // Implicit localhost: port:host:hostport.
        assert_eq!(local_forward_port("8080:localhost:80"), Some(8080));
        // Explicit localhost bind.
        assert_eq!(local_forward_port("127.0.0.1:9090:db:5432"), Some(9090));
        assert_eq!(local_forward_port("localhost:9090:db:5432"), Some(9090));
        // Non-local bind: can't confirm by connecting → None.
        assert_eq!(local_forward_port("0.0.0.0:9090:db:5432"), None);
        assert_eq!(local_forward_port("192.168.1.5:9090:db:5432"), None);
        // Malformed → None.
        assert_eq!(local_forward_port("nonsense"), None);
    }
}
