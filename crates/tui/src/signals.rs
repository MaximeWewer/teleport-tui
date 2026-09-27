//! Process-signal handling. Background proxies/forwards run in their own process
//! group, so a closed terminal (SIGHUP) or a `kill` (SIGTERM) never reaches them:
//! if the TUI simply died, those authenticated tunnels would keep running. Instead
//! the handlers only raise a flag; the event loop sees it, returns normally, and
//! the regular `Drop` path stops every child and restores the terminal.
//!
//! Flags are process-global because signals are. Off Unix nothing is installed:
//! Ctrl-C reaches the TUI as a key in raw mode and there is no SIGHUP/SIGTERM.

use std::sync::Arc;
use std::sync::LazyLock;
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
    Ok(())
}

/// No signals to hook off Unix.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn install() -> std::io::Result<()> {
    Ok(())
}

/// A SIGHUP/SIGTERM arrived: stop any hand-off and shut down.
pub(crate) fn terminate_requested() -> bool {
    TERMINATE.load(Ordering::Relaxed)
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
