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

/// Start `tsh proxy app <name> -c <cluster> -p <port>` in the background, wait
/// until it is listening, open the browser at the local URL, and return the
/// child handle (to stop it later) plus the URL.
///
/// SECURITY: `name`/`cluster` are validated value objects upstream; argv only,
/// no shell. The URL is a fixed `http://127.0.0.1:<port>` we control.
///
/// `port` is the caller-requested local port; `None` allocates a random free
/// one. A requested port already in use surfaces as a normal spawn/listen error.
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
    let port = match port {
        Some(p) => p,
        None => free_port()?,
    };
    let port_s = port.to_string();
    let mut child = Command::new(tsh)
        .args(["proxy", "app", name, "-c", cluster, "-p", &port_s])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    if !wait_ready(port) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "app proxy did not start in time (try logging into the app first)",
        ));
    }

    let url = format!("http://127.0.0.1:{port}");
    open_browser(&url);
    Ok((child, url))
}

/// Start `tsh proxy db <name> -c <cluster> --tunnel -p <port>` in the background
/// and return the child plus the local endpoint (`127.0.0.1:<port>`) for the
/// user to point a DB client at. `--tunnel` authenticates via the database's
/// client certificate, so the GUI tool connects without extra credentials.
///
/// `port` is the requested local port; `None` allocates a random free one.
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
    let port = match port {
        Some(p) => p,
        None => free_port()?,
    };
    let port_s = port.to_string();
    let mut child = Command::new(tsh)
        .args([
            "proxy", "db", name, "-c", cluster, "--tunnel", "-p", &port_s,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    if !wait_ready(port) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "db proxy did not start in time (try `tsh db login` first)",
        ));
    }

    Ok((child, format!("127.0.0.1:{port}")))
}

/// Start `tsh proxy kube <kube> -c <cluster> [--as <user>] -p <port>` in the
/// background and return the child plus the `KUBECONFIG` path it printed.
///
/// Unlike `tsh proxy kube --exec`, the proxy stays silent in the background and
/// we hand off a clean shell ourselves — so `tsh`'s raw-mode preamble never
/// corrupts the user's terminal (no "staircase" output, resize works).
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
    let port = free_port()?;
    let port_s = port.to_string();
    let mut cmd = Command::new(tsh);
    cmd.args(["proxy", "kube", kube, "-c", cluster, "-p", &port_s]);
    if let Some(u) = user {
        cmd.args(["--as", u]);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn()?;

    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("proxy stdout unavailable"));
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
        Ok((child, path))
    } else {
        let _ = child.kill();
        let _ = child.wait();
        Err(io::Error::new(
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
    let mut child = Command::new(tsh)
        .args(["ssh", "-c", cluster, "-L", spec, "-N", &target])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

/// Ask the OS to allocate a free localhost port (bind to :0, then release).
fn free_port() -> io::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

/// Poll until the proxy accepts a TCP connection (or give up after ~3s).
fn wait_ready(port: u16) -> bool {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for _ in 0..30 {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return true;
        }
        sleep(Duration::from_millis(100));
    }
    false
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
