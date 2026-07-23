//! Interactive command launching: suspend the TUI, hand the real terminal to a
//! child process (SSH), then resume. stdio is inherited so MFA prompts, PTY,
//! and escape sequences work natively on every OS.

use std::io::{self, Stdout, Write};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::cursor::{MoveTo, Show};
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyCode, KeyEventKind, KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::style::{
    Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor,
};
use ratatui::crossterm::terminal::{
    Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
    enable_raw_mode, size,
};

use infrastructure::redact::redact_text;

type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Run `<program> <args>` with the terminal handed over, restoring the TUI
/// after. `envs` are extra environment variables for the child (e.g.
/// `KUBECONFIG` for a kube shell).
///
/// The child is handed the screen with no banner of ours, so nothing lingers
/// once the session starts: the user sees only `tsh`'s own output (its
/// connection progress, an MFA prompt, then the remote shell). We tried a
/// transient banner, but with stdio inherited (no PTY, by design) there is no
/// "connected" signal to erase it on — and letting `tsh`'s shorter first line
/// overwrite ours left a visible tail on the prompt row. `label` is unused for
/// on-screen output here; the connection delay is covered by `tsh`'s own
/// progress/prompts.
///
/// We **leave the alternate screen** for the hand-off so the child writes into
/// the terminal's *main* buffer. The alternate buffer has no scrollback, so a
/// session whose output overflows the window could not be scrolled back at all
/// (neither the wheel nor Shift-PgUp). Running in the main buffer restores the
/// terminal's native scrollback for the whole session. Trade-off: the session's
/// output stays in the terminal's history after the TUI exits. We re-enter the
/// alternate screen when the child returns, so the TUI itself still leaves no
/// trace of its own rendering.
///
/// Nothing is cleared on the way out: wiping the main buffer would destroy the
/// scrollback we just went there for.
///
/// SECURITY: `args` is an argv vector (no shell); every element is built from
/// validated value objects upstream. `label` is non-secret.
///
/// Returns the child's [`ExitStatus`] so the caller can surface a non-zero exit
/// (e.g. a failed `tsh ssh`/login) in the status bar instead of silently
/// treating it as success.
///
/// # Errors
/// Returns an error if suspending/resuming the terminal or spawning fails.
///
/// `pause_on_exit` holds the child's output on screen after it exits, waiting for
/// a keypress before wiping the screen and resuming the TUI. Use it for one-off
/// commands (which finish on their own, so their output would otherwise flash by);
/// leave it `false` for interactive shells the user ends themselves.
pub(crate) fn run_interactive(
    terminal: &mut Tui,
    program: &Path,
    args: &[String],
    _label: &str,
    envs: &[(&str, &str)],
    pause_on_exit: bool,
) -> io::Result<ExitStatus> {
    // Drop raw mode for the child's cooked-mode prompt and return to the main
    // screen buffer, which is the one with scrollback (see the fn doc). Show the
    // cursor (ratatui hides it while rendering) so the child's shell/prompt
    // cursor is visible when typing. Release mouse capture too, so the child
    // session gets the terminal's native mouse (wheel scrolls the scrollback,
    // click-drag selects) instead of our tracking sequences.
    disable_raw_mode()?;
    let mut out = io::stdout();
    execute!(
        out,
        DisableBracketedPaste,
        DisableMouseCapture,
        LeaveAlternateScreen,
        Show
    )?;
    out.flush()?;

    // Hand over stdin/stdout/stderr to the child (inherited by default).
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let spawn = cmd.status();

    // A one-off command exits on its own: pause on its output so the user can read
    // it before we wipe the screen. Raw mode lets a single keypress dismiss it.
    if pause_on_exit {
        enable_raw_mode()?;
        let note = match spawn.as_ref().ok().and_then(ExitStatus::code) {
            Some(0) => "ok".to_owned(),
            Some(c) => format!("exit {c}"),
            None => "terminated".to_owned(),
        };
        execute!(
            out,
            SetForegroundColor(Color::DarkGrey),
            Print(format!(
                "\r\n— command finished ({note}) · press any key to return —"
            )),
            ResetColor,
        )?;
        out.flush()?;
        wait_any_key()?;
    }

    // Resume the TUI regardless of the child's exit status: back into the
    // alternate screen (the session's output stays behind in the main buffer's
    // scrollback), then re-arm mouse capture — released for the child above — so
    // the wheel scrolls the lists again.
    enable_raw_mode()?;
    execute!(
        io::stdout(),
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    )?;
    terminal.clear()?;

    spawn
}

/// Block until the user presses a key (any key). Used to pause on a finished
/// one-off command's output. Assumes raw mode is on (single keypress, no Enter).
fn wait_any_key() -> io::Result<()> {
    loop {
        if let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
        {
            return Ok(());
        }
    }
}

/// Play a recorded session (`tsh play`) interruptibly: unlike [`run_interactive`],
/// the TUI keeps the keyboard so **Esc / q / Ctrl-C stops the replay and returns
/// to the TUI** — `tsh play` itself only quits on SIGINT, which is unintuitive.
///
/// Raw mode stays **on** (so a bare Esc is one byte, and Ctrl-C is a key rather
/// than a signal that would kill the TUI); the child renders the replay to the
/// inherited stdout while its stdin is detached, so our poll loop is the only
/// keyboard reader. Returns `Some(status)` on natural completion, `None` when the
/// user stopped it.
///
/// # Errors
/// Returns an error if terminal setup or spawning fails.
pub(crate) fn play_recording(
    terminal: &mut Tui,
    program: &Path,
    args: &[String],
    label: &str,
) -> io::Result<Option<ExitStatus>> {
    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, Clear(ClearType::All), MoveTo(0, 0), Show)?;
    let width = size().map_or(80, |(w, _)| w as usize).max(20);
    let rule = "─".repeat(width);
    let label = redact_text(label);
    // Raw mode is on, so emit explicit CRLF.
    execute!(
        out,
        SetForegroundColor(Color::Cyan),
        Print(format!("{rule}\r\n")),
        SetAttribute(Attribute::Bold),
        Print(format!("  {label}\r\n")),
        SetAttribute(Attribute::Reset),
        SetForegroundColor(Color::DarkGrey),
        Print("  Press Esc or q to stop and return to teleport-tui.\r\n"),
        SetForegroundColor(Color::Cyan),
        Print(format!("{rule}\r\n\r\n")),
        ResetColor,
    )?;
    out.flush()?;

    // Detach the child's stdin: playback is output-only, and it lets us own the
    // keyboard for the stop key without racing the child for stdin bytes.
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .spawn()?;

    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st); // finished on its own
        }
        if event::poll(Duration::from_millis(80))?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
        {
            let stop = matches!(k.code, KeyCode::Esc | KeyCode::Char('q'))
                || (k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL));
            if stop {
                let _ = child.kill();
                let _ = child.wait();
                break None; // user-stopped
            }
        }
    };

    terminal.clear()?;
    Ok(status)
}
