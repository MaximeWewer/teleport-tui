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
use std::sync::mpsc;
use std::thread::{self, sleep};
use std::time::Duration;

/// How many fresh ports to try when an auto-allocated one is lost to the TOCTOU
/// race (see [`start_listening_proxy`]). Small: a real collision is rare, and a
/// genuine failure (login/MFA) is diagnosed and stops the loop after one try.
const PORT_RETRIES: usize = 3;

/// Outcome of one proxy-start attempt, so the caller can tell a lost-port race
/// (worth retrying on a new port) from a real failure (retrying won't help).
enum Attempt<T> {
    Ready(T),
    /// The child exited before it was ready — the auto-allocated port was almost
    /// certainly taken between `free_port()` releasing it and the child binding
    /// it. Retrying on a fresh port should succeed.
    PortLost,
    /// The child is alive but never became ready (stuck on a login/MFA prompt it
    /// can't answer with detached stdin, say) — not a port problem, so surface it.
    Failed(io::Error),
}

/// Wait until the child accepts a TCP connection on `port`. A child that exits
/// first lost the port ([`Attempt::PortLost`], retryable); one still alive after
/// the grace period is stuck on something a new port wouldn't fix
/// ([`Attempt::Failed`]).
fn await_listen(child: &mut Child, port: u16) -> Attempt<()> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for _ in 0..30 {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return Attempt::PortLost;
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return Attempt::Ready(());
        }
        sleep(Duration::from_millis(100));
    }
    Attempt::Failed(io::Error::new(
        io::ErrorKind::TimedOut,
        "proxy did not start in time (log into the app/db first, or MFA may be required)",
    ))
}

/// Spawn a background proxy that becomes ready by *listening* on a local port
/// (app / db). For an explicit `port` a single attempt is made — a conflict on
/// the user's chosen port is theirs to resolve, not silently relocated. For an
/// auto port the OS-picked number can be stolen in the TOCTOU window between
/// `free_port()` and the child's own bind, so a lost race retries on a fresh one.
/// Returns the live child plus the port it is actually listening on.
fn start_listening_proxy(
    port: Option<u16>,
    spawn: impl Fn(u16) -> io::Result<Child>,
) -> io::Result<(Child, u16)> {
    if let Some(p) = port {
        let mut child = spawn(p)?;
        return match await_listen(&mut child, p) {
            Attempt::Ready(()) => Ok((child, p)),
            Attempt::PortLost => {
                let _ = child.wait();
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
            // Racey port: the child already exited — reap it and try another.
            Attempt::PortLost => {
                let _ = child.wait();
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

/// Start `tsh proxy app <name> -c <cluster> -p <port>` in the background, wait
/// until it is listening, open the browser at the local URL, and return the
/// child handle (to stop it later) plus the URL.
///
/// SECURITY: `name`/`cluster` are validated value objects upstream; argv only,
/// no shell. The URL is a fixed `http://127.0.0.1:<port>` we control.
///
/// `port` is the caller-requested local port; `None` allocates a random free
/// one (retried on a fresh port if it loses the TOCTOU race — see
/// [`start_listening_proxy`]). A requested port already in use is an error.
///
/// # Errors
/// Returns an error if a port can't be allocated, the proxy can't be spawned,
/// or it doesn't start listening in time.
pub(crate) fn open_app(
    tsh: &Path,
    name: &str,
    cluster: &str,
    port: Option<u16>,
) -> io::Result<(Child, String)> {
    let (child, port) = start_listening_proxy(port, |p| {
        own_group(
            Command::new(tsh)
                .args(["proxy", "app", name, "-c", cluster, "-p", &p.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
        .spawn()
    })?;
    let url = format!("http://127.0.0.1:{port}");
    open_browser(&url);
    Ok((child, url))
}

/// Start `tsh proxy db <name> -c <cluster> --tunnel -p <port>` in the background
/// and return the child plus the local endpoint (`127.0.0.1:<port>`) for the
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
    name: &str,
    cluster: &str,
    port: Option<u16>,
) -> io::Result<(Child, String)> {
    let (child, port) = start_listening_proxy(port, |p| {
        own_group(
            Command::new(tsh)
                .args([
                    "proxy",
                    "db",
                    name,
                    "-c",
                    cluster,
                    "--tunnel",
                    "-p",
                    &p.to_string(),
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
        .spawn()
    })?;
    Ok((child, format!("127.0.0.1:{port}")))
}

/// Start `tsh proxy kube <kube> -c <cluster> [--as <user>] -p <port>` in the
/// background and return the child plus the `KUBECONFIG` path it printed.
///
/// Unlike `tsh proxy kube --exec`, the proxy stays silent in the background and
/// we hand off a clean shell ourselves — so `tsh`'s raw-mode preamble never
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
    kube: &str,
    cluster: &str,
    user: Option<&str>,
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
    kube: &str,
    cluster: &str,
    user: Option<&str>,
    port: u16,
) -> Attempt<(Child, String)> {
    let port_s = port.to_string();
    let mut cmd = Command::new(tsh);
    cmd.args(["proxy", "kube", kube, "-c", cluster, "-p", &port_s]);
    if let Some(u) = user {
        cmd.args(["--as", u]);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    own_group(&mut cmd);
    let mut child = match cmd.spawn() {
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

/// Start `tsh ssh -c <cluster> -L <spec> -N [<user>@]<host>` in the background
/// (no shell — a pure local port-forward) and return the child once the tunnel is
/// up. `spec` is a validated `[bind:]port:host:hostport` forward; a blank `user`
/// lets tsh pick the default login.
///
/// Readiness: when the local bind is on localhost we poll its port until it
/// accepts a connection; otherwise we wait a short grace period. If the child
/// exits early (e.g. it needed an interactive MFA prompt it can't get with a
/// detached stdin, or the port is taken) that surfaces as an error.
///
/// SECURITY: argv only, no shell; `cluster`/`user`/`host`/`spec` are validated
/// upstream.
///
/// # Errors
/// Returns an error if the child can't spawn or the tunnel doesn't come up.
pub(crate) fn start_ssh_forward(
    tsh: &Path,
    cluster: &str,
    user: &str,
    host: &str,
    spec: &str,
) -> io::Result<Child> {
    let target = if user.is_empty() {
        host.to_owned()
    } else {
        format!("{user}@{host}")
    };
    let mut child = own_group(
        Command::new(tsh)
            .args(["ssh", "-c", cluster, "-L", spec, "-N", &target])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .spawn()?;

    let local = local_forward_port(spec);
    // ~4s: bail out the moment the child dies; otherwise confirm the local port
    // (when known) or fall through to "assumed up" after the grace period.
    for _ in 0..40 {
        if child.try_wait()?.is_some() {
            let _ = child.wait();
            return Err(io::Error::other(
                "forward exited immediately (not logged in / MFA required, or port in use)",
            ));
        }
        if let Some(port) = local
            && TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                Duration::from_millis(80),
            )
            .is_ok()
        {
            return Ok(child);
        }
        sleep(Duration::from_millis(100));
    }
    Ok(child)
}

/// The local (bind-side) port of a `-L` spec, but only when it binds localhost —
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

/// Stop a background proxy child **and its whole process group**, then reap it.
/// Because the child was spawned as its own group leader ([`own_group`]), a
/// signal to the group (`kill(-pgid)`) also reaches any helper `tsh` forked, so
/// nothing is orphaned. The direct `kill`/`wait` still run as a fallback (and to
/// reap the leader). Off Unix, only the direct child is killed.
pub(crate) fn stop_child(child: &mut Child) {
    #[cfg(unix)]
    {
        // The leader's pgid equals its pid; signal the group before reaping, while
        // the pid is still valid. Errors (already gone) are ignored.
        if let Some(pgid) = i32::try_from(child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Open the default browser at `url` (best-effort, per-OS, no shell metachars —
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
    // `cmd /C start "" <url>` — empty title arg so the URL isn't taken as title.
    let mut c = Command::new("cmd");
    c.args(["/C", "start", "", url]);
    c
}

#[cfg(test)]
mod tests {
    use super::local_forward_port;

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

    // Proof that stop_child reaches grandchildren: the direct child forks a
    // `sleep` (a grandchild) and prints its pid. Killing only the direct child
    // would orphan it; a process-group kill takes it down too. Linux-only (uses
    // /proc for a liveness probe on a process that isn't ours to waitpid).
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
