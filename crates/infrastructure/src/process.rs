//! Subprocess execution seam.
//!
//! SECURITY: commands are built as an **argv vector** and run via
//! `std::process::Command` — never a shell, never string concatenation. This
//! eliminates command injection. The `CommandRunner` trait lets tests inject
//! canned output without spawning a process.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
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
        // No shell (argv vector). `stdin` is detached so a read-path command can
        // never block on — or steal keystrokes from — the terminal the TUI owns on
        // another thread. `LC_ALL=C` pins tsh's human-readable messages to the
        // English form `classify_failure` matches, regardless of the user's locale.
        let mut child = Command::new(&req.bin)
            .args(&req.args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Drain both pipes on their own threads: a command whose output fills the
        // pipe buffer would otherwise block on write and never exit while we wait.
        let mut out_pipe = child.stdout.take();
        let mut err_pipe = child.stderr.take();
        let out_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(p) = out_pipe.as_mut() {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        });
        let err_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(p) = err_pipe.as_mut() {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        });

        // Wait with a deadline; kill a command that overruns so its worker frees.
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break Some(st);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };

        // Killing (or the child exiting) closes the pipes, so the readers finish.
        let stdout = out_reader.join().unwrap_or_default();
        let stderr = err_reader.join().unwrap_or_default();

        let Some(status) = status else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "command timed out",
            ));
        };
        Ok(CommandOutcome {
            status: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}
