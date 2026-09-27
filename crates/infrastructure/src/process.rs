//! Subprocess execution seam.
//!
//! SECURITY: commands are built as an **argv vector** and run via
//! `std::process::Command` - never a shell, never string concatenation. This
//! eliminates command injection. The `CommandRunner` trait lets tests inject
//! canned output without spawning a process.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

/// Upper bound on how long a single read-path CLI call may run before it is
/// killed. Generous enough for a slow-but-working `tsh`/`tctl` listing, low
/// enough that a wedged command (dead network, stuck proxy) frees its worker
/// thread instead of hanging the pool forever.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// A command to execute: an absolute binary path plus discrete arguments.
#[derive(Debug, Clone)]
pub struct CommandRequest {
    pub bin: PathBuf,
    pub args: Vec<String>,
}

impl CommandRequest {
    pub fn new(bin: impl Into<PathBuf>, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            bin: bin.into(),
            args: args.into_iter().collect(),
        }
    }

    /// Raw, **unredacted** rendering of the argv (NOT for exec). The name is
    /// deliberate: this may contain secrets (e.g. a `--token` value). Callers
    /// that log it MUST pipe it through [`crate::redact::redact_command`] first.
    #[must_use]
    pub fn unredacted_display(&self) -> String {
        let mut s = self.bin.display().to_string();
        for a in &self.args {
            s.push(' ');
            s.push_str(a);
        }
        s
    }
}

#[derive(Debug, Clone)]
pub struct CommandOutcome {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutcome {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.status == Some(0)
    }
}

/// Seam over process execution.
pub trait CommandRunner: std::fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns an `io::Error` if the process could not be spawned.
    fn run(&self, req: &CommandRequest) -> std::io::Result<CommandOutcome>;
}

/// Real implementation backed by `std::process::Command`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, req: &CommandRequest) -> std::io::Result<CommandOutcome> {
        run_with_timeout(req, COMMAND_TIMEOUT)
    }
}

/// Run `req` to completion, bounded by `timeout` (a parameter so tests can use a
/// short one).
fn run_with_timeout(req: &CommandRequest, timeout: Duration) -> std::io::Result<CommandOutcome> {
    // No shell (argv vector). `stdin` is detached so a read-path command can
    // never block on - or steal keystrokes from - the terminal the TUI owns on
    // another thread. `LC_ALL=C` pins tsh's human-readable messages to the
    // English form `classify_failure` matches, regardless of the user's locale.
    let mut cmd = Command::new(&req.bin);
    cmd.args(&req.args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Own process group: any helper the command forks (which inherits our pipes)
    // can be killed together with it.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn()?;

    // Drain both pipes on their own threads: a command whose output fills the
    // pipe buffer would otherwise block on write and never exit while we wait.
    let out_rx = drain(child.stdout.take());
    let err_rx = drain(child.stderr.take());

    // Wait with a deadline; kill a command that overruns so its worker frees.
    // A `try_wait` error kills it too, rather than returning with it running.
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Ok(st),
            Ok(None) if Instant::now() >= deadline => {
                break Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "command timed out",
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => break Err(e),
        }
    };
    if status.is_err() {
        kill_tree(&mut child);
    }

    // The readers finish at EOF, i.e. once every holder of the pipes' write end
    // is gone. That is normally the command itself, but a helper it forked may
    // outlive it with the pipes inherited. Once the command has exited, give
    // such a helper only a short grace (not the rest of the timeout) to close
    // them, then kill the group and keep the output. Never block unbounded on a
    // reader - if one is still stuck (a helper escaped the group) it is
    // abandoned rather than hanging the worker.
    let readers_deadline = if status.is_ok() {
        deadline.min(Instant::now() + EXIT_GRACE)
    } else {
        deadline
    };
    let (stdout, stderr) = match (
        recv_until(&out_rx, readers_deadline),
        recv_until(&err_rx, readers_deadline),
    ) {
        (Some(out), Some(err)) => (out, err),
        (out, err) => {
            kill_tree(&mut child);
            let grace = Instant::now() + READER_GRACE;
            match (
                out.or_else(|| recv_until(&out_rx, grace)),
                err.or_else(|| recv_until(&err_rx, grace)),
            ) {
                (Some(out), Some(err)) => (out, err),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "command output did not close",
                    ));
                }
            }
        }
    };

    let status = status?;
    Ok(CommandOutcome {
        status: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// How long a command that has exited may leave its output pipes open (held
/// by a forked helper) before the process group is killed.
const EXIT_GRACE: Duration = Duration::from_secs(2);

/// How long to wait for the output readers after killing the process group.
const READER_GRACE: Duration = Duration::from_secs(2);

/// Read a pipe to EOF on its own thread; the bytes arrive on the returned channel.
fn drain(pipe: Option<impl Read + Send + 'static>) -> Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

/// A reader's output, if it finishes by `deadline`.
fn recv_until(rx: &Receiver<Vec<u8>>, deadline: Instant) -> Option<Vec<u8>> {
    rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()
}

/// SIGKILL the command's whole process group (Unix), then the command itself,
/// and reap it. Errors (already gone) are ignored. Off Unix only the direct
/// child is killed.
fn kill_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        // The leader's pgid equals its pid (`process_group(0)` at spawn).
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

#[cfg(all(test, unix))]
mod tests {
    use super::{CommandRequest, run_with_timeout};
    use std::time::{Duration, Instant};

    fn sh(script: &str) -> CommandRequest {
        CommandRequest::new("/bin/sh", ["-c".to_owned(), script.to_owned()])
    }

    #[test]
    fn timeout_kills_the_whole_group_even_with_a_forked_helper() {
        // The backgrounded `sleep` inherits the pipes: killing only `sh` would
        // leave the readers waiting on it forever.
        let started = Instant::now();
        let err = run_with_timeout(&sh("sleep 100 & sleep 100"), Duration::from_millis(300))
            .expect_err("should time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(10), "must not hang");
    }

    #[test]
    fn helper_holding_the_pipes_after_exit_is_killed_and_output_kept() {
        let started = Instant::now();
        let out = run_with_timeout(&sh("echo hi; sleep 100 &"), Duration::from_millis(300))
            .expect("the command itself succeeded");
        assert!(out.succeeded());
        assert_eq!(out.stdout, "hi\n");
        assert!(started.elapsed() < Duration::from_secs(10), "must not hang");
    }

    #[test]
    fn helper_holding_the_pipes_does_not_wait_for_the_full_timeout() {
        // The command exits at once but its helper keeps the pipes: we must
        // return after the short exit grace, not the (long) command timeout.
        let started = Instant::now();
        let out = run_with_timeout(&sh("echo hi; sleep 100 &"), Duration::from_secs(60))
            .expect("the command itself succeeded");
        assert!(out.succeeded());
        assert_eq!(out.stdout, "hi\n");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "waited {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_quick_command_returns_its_output() {
        let out = run_with_timeout(
            &sh("echo out; echo err >&2; exit 3"),
            Duration::from_secs(10),
        )
        .expect("runs");
        assert_eq!(out.status, Some(3));
        assert_eq!(out.stdout, "out\n");
        assert_eq!(out.stderr, "err\n");
    }
}
