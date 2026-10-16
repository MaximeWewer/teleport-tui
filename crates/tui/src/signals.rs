//! Process-signal handling. Background proxies/forwards run in their own process
//! group, so a closed terminal (SIGHUP) or a `kill` (SIGTERM) never reaches them:
//! if the TUI simply died, those authenticated tunnels would keep running. Instead
//! the handlers only raise a flag; the event loop sees it, returns normally, and
//! the regular `Drop` path stops every child and restores the terminal.
//!
//! Flags are process-global because signals are. Off Unix nothing is installed:
//! Ctrl-C reaches the TUI as a key in raw mode and there is no SIGHUP/SIGTERM.
//!
//! SIGHUP is not always delivered when the terminal goes away (some emulators
//! and multiplexers just revoke the tty). An orphaned TUI would then keep
//! polling a dead terminal, which on macOS spins a core. So [`terminal_lost`]
//! also counts as a termination request: the parent process changed (we were
//! reparented) or a stdio stream that was a terminal at start-up no longer is.

use std::sync::Arc;
use std::sync::LazyLock;
#[cfg(unix)]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Raised by SIGHUP / SIGTERM: the TUI must shut down.
static TERMINATE: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));
/// Raised by SIGINT. In raw mode Ctrl-C is a key, so a SIGINT outside a hand-off
/// is an external `kill -INT` (quit); during a hand-off it is the user's Ctrl-C
/// meant for the child and is discarded by [`clear_interrupt`].
static INTERRUPT: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));

/// Install the handlers. A second SIGHUP/SIGTERM while the first is still being
/// handled exits immediately (exit code 1), so a wedged TUI can still be killed.
///
/// # Errors
/// Returns an error if a handler cannot be registered.
#[cfg(unix)]
pub(crate) fn install() -> std::io::Result<()> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    use signal_hook::flag;

    for sig in [SIGHUP, SIGTERM] {
        // Order matters: the conditional shutdown sees the flag *before* this
        // delivery raises it, so only a repeated signal takes the hard exit.
        flag::register_conditional_shutdown(sig, 1, Arc::clone(&TERMINATE))?;
        flag::register(sig, Arc::clone(&TERMINATE))?;
    }
    flag::register(SIGINT, Arc::clone(&INTERRUPT))?;
    let _ = ORIGIN.set(current_origin());
    Ok(())
}

/// No signals to hook off Unix.
#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    clippy::missing_const_for_fn,
    reason = "no-op stub must keep the fallible, non-const Unix signature"
)]
pub(crate) fn install() -> std::io::Result<()> {
    Ok(())
}

/// Parent pid and which of stdin/stdout were terminals, captured by [`install`].
#[cfg(unix)]
static ORIGIN: OnceLock<Origin> = OnceLock::new();

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
struct Origin {
    ppid: Option<rustix::process::Pid>,
    stdin_tty: bool,
    stdout_tty: bool,
}

#[cfg(unix)]
fn current_origin() -> Origin {
    Origin {
        ppid: rustix::process::getppid(),
        stdin_tty: rustix::termios::isatty(std::io::stdin()),
        stdout_tty: rustix::termios::isatty(std::io::stdout()),
    }
}

/// Whether `now` shows the terminal is gone relative to `start`: the parent
/// changed (it died and we were reparented), or a stream that was a terminal
/// at start-up no longer is (the tty was hung up or revoked).
#[cfg(unix)]
fn lost_since(start: Origin, now: Origin) -> bool {
    now.ppid != start.ppid
        || (start.stdin_tty && !now.stdin_tty)
        || (start.stdout_tty && !now.stdout_tty)
}

/// The controlling terminal went away without a SIGHUP reaching us. Cheap (two
/// `isatty` calls and a `getppid`), so it is checked on every loop iteration.
#[cfg(unix)]
pub(crate) fn terminal_lost() -> bool {
    ORIGIN
        .get()
        .is_some_and(|&start| lost_since(start, current_origin()))
}

/// Off Unix a closed console ends the process, so there is nothing to detect.
#[cfg(not(unix))]
pub(crate) const fn terminal_lost() -> bool {
    false
}

/// A SIGHUP/SIGTERM arrived, or the terminal is gone: stop any hand-off and
/// shut down.
pub(crate) fn terminate_requested() -> bool {
    TERMINATE.load(Ordering::Relaxed) || terminal_lost()
}

/// The event loop should exit (termination, or a SIGINT outside a hand-off).
pub(crate) fn shutdown_requested() -> bool {
    terminate_requested() || INTERRUPT.load(Ordering::Relaxed)
}

/// Forget a SIGINT received while a child owned the terminal: the user's Ctrl-C
/// was for that child (which got it too, sharing our process group), not for us.
pub(crate) fn clear_interrupt() {
    INTERRUPT.store(false, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn a_new_parent_or_a_lost_tty_means_the_terminal_is_gone() {
        use super::{Origin, lost_since};
        use rustix::process::Pid;

        let start = Origin {
            ppid: Pid::from_raw(4242),
            stdin_tty: true,
            stdout_tty: true,
        };
        assert!(!lost_since(start, start));
        let reparented = Origin {
            ppid: Pid::from_raw(1),
            ..start
        };
        assert!(lost_since(start, reparented));
        let hung_up = Origin {
            stdin_tty: false,
            ..start
        };
        assert!(lost_since(start, hung_up));
        // A stream that was never a terminal (e.g. redirected) is not a loss.
        let piped = Origin {
            stdout_tty: false,
            ..start
        };
        assert!(!lost_since(piped, piped));
    }

    // SIGINT only: a delivered SIGTERM/SIGHUP would arm the hard-exit path for
    // the whole test binary.
    #[cfg(unix)]
    #[test]
    fn sigint_raises_the_flag_and_a_handoff_clears_it() {
        use super::{clear_interrupt, install, shutdown_requested};
        use rustix::process::{Signal, getpid, kill_process};
        use std::thread::sleep;
        use std::time::Duration;

        install().expect("install handlers");
        kill_process(getpid(), Signal::INT).expect("raise SIGINT");
        let seen = (0..100).any(|_| {
            if shutdown_requested() {
                true
            } else {
                sleep(Duration::from_millis(10));
                false
            }
        });
        assert!(seen, "SIGINT should request shutdown, not kill the process");
        clear_interrupt();
        assert!(!shutdown_requested());
    }
}
