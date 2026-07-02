//! teleport-tui — a terminal UI wrapping the Teleport client CLIs.
//!
//! Composition root: locates `tsh`, wires concrete adapters into the `App`
//! (dependency injection), runs the event loop, and restores the terminal on
//! every exit path (quit, error, panic).

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

mod app;
mod forms;
mod proxy;
mod ssh;
mod ui;

use std::io::{self, Stdout};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyEvent, KeyEventKind, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use std::time::Duration;

use domain::port::{AdminRepository, CapabilityProbe};
use infrastructure::capability::TshCapabilityProbe;
use infrastructure::config::{Config, default_kube_tools};
use infrastructure::logging::NdjsonLogger;
use infrastructure::platform::{locate_tctl, locate_tsh};
use infrastructure::process::SystemCommandRunner;
use infrastructure::tctl::{TctlAdminRepository, UnavailableAdmin};
use infrastructure::tsh::{
    TshAppRepository, TshAuthGateway, TshClusterRepository, TshDatabaseRepository,
    TshKubeRepository, TshNodeRepository, TshRecordingRepository, TshRequestRepository,
    TshSessionRepository,
};

use crate::app::{App, Outcome, Repositories};

type Tui = Terminal<CrosstermBackend<Stdout>>;

fn main() -> ExitCode {
    install_panic_hook();
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Fatal setup/teardown error: the TUI never started (or already tore
            // down), so writing to stderr is safe — the alternate screen isn't up.
            #[allow(clippy::print_stderr)]
            {
                eprintln!("teleport-tui: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<(), String> {
    let config = Config::load_default();
    let tsh: PathBuf = locate_tsh(config.tsh_path.clone()).map_err(|e| e.to_string())?;
    // tctl is optional — admin features degrade gracefully if it's absent.
    let tctl: Option<PathBuf> = locate_tctl(config.tctl_path.clone()).ok();
    let admin: Box<dyn AdminRepository> = match &tctl {
        Some(path) => Box::new(TctlAdminRepository::new(
            SystemCommandRunner,
            path.clone(),
            tsh.clone(),
        )),
        None => Box::new(UnavailableAdmin),
    };

    // Dependency injection: concrete adapters behind the domain ports.
    let repos = Repositories {
        clusters: Box::new(TshClusterRepository::new(SystemCommandRunner, tsh.clone())),
        nodes: Box::new(TshNodeRepository::new(SystemCommandRunner, tsh.clone())),
        kube: Box::new(TshKubeRepository::new(SystemCommandRunner, tsh.clone())),
        databases: Box::new(TshDatabaseRepository::new(SystemCommandRunner, tsh.clone())),
        apps: Box::new(TshAppRepository::new(SystemCommandRunner, tsh.clone())),
        requests: Box::new(TshRequestRepository::new(SystemCommandRunner, tsh.clone())),
        recordings: Box::new(TshRecordingRepository::new(
            SystemCommandRunner,
            tsh.clone(),
        )),
        sessions: Box::new(TshSessionRepository::new(SystemCommandRunner, tsh.clone())),
        auth: Box::new(TshAuthGateway::new(SystemCommandRunner, tsh.clone())),
        admin,
    };
    let logger = NdjsonLogger::at_default_path();

    let kube_tools = if config.kube_tools.is_empty() {
        default_kube_tools()
    } else {
        config.kube_tools.clone()
    };
    let settings = app::Settings {
        kube_tools,
        login_proxy: config.proxy.clone(),
        login_user: config.user.clone(),
        login_auth: config.auth.clone(),
        login_mfa: config.mfa.clone(),
        default_login: config.default_login.clone(),
        default_kube_user: config.kube_user.clone(),
        default_db_user: config.db_user.clone(),
        refresh_seconds: config.refresh_seconds,
        config_path: infrastructure::platform::config_path(),
        // Probe the installed tsh once so the UI hides unsupported actions.
        capabilities: TshCapabilityProbe::new(SystemCommandRunner, tsh.clone()).probe(),
    };
    let mut application = App::new(repos, logger, run_id(), tsh, settings, false);
    application.bootstrap();

    let refresh = config.refresh_seconds.map(Duration::from_secs);

    let _guard = TerminalGuard::enter().map_err(|e| e.to_string())?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|e| e.to_string())?;
    run(&mut terminal, &mut application, refresh).map_err(|e| e.to_string())
}

fn run(terminal: &mut Tui, app: &mut App, refresh: Option<Duration>) -> io::Result<()> {
    let mut last_refresh = Instant::now();
    // Redraw only when something changed (a key, a resize, an auto-refresh, or a
    // background result/spinner tick), instead of unconditionally every poll
    // cycle — saves the ~8 idle redraws/sec the 120ms poll would otherwise force.
    let mut dirty = true;
    loop {
        // Apply any finished background jobs and animate the spinner.
        if app.tick() {
            dirty = true;
        }
        // Handle any background proxy launches that have completed.
        for ev in app.drain_proxy_events() {
            handle_proxy_event(terminal, app, ev);
            dirty = true;
        }
        if dirty {
            terminal.draw(|f| ui::render(f, app))?;
            dirty = false;
        }

        // Optional auto-refresh of the active tab (opt-in via config).
        if let Some(interval) = refresh
            && last_refresh.elapsed() >= interval
        {
            app.refresh();
            last_refresh = Instant::now();
            dirty = true;
        }

        // Short poll so the spinner animates and background results land promptly.
        if event::poll(Duration::from_millis(120))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    // Any handled key may change the view → redraw next loop.
                    dirty = true;
                    if handle_key(terminal, app, key) {
                        return Ok(());
                    }
                }
                // Mouse wheel scrolls the focused list — routed through the same
                // path as ↑/↓ so every mode (table, pickers, sessions/MFA) reacts.
                Event::Mouse(m) => {
                    let scroll = match m.kind {
                        MouseEventKind::ScrollDown => Some(true),
                        MouseEventKind::ScrollUp => Some(false),
                        _ => None,
                    };
                    if let Some(down) = scroll {
                        app.on_scroll(down);
                        dirty = true;
                    }
                }
                // A resize invalidates the rendered layout.
                Event::Resize(_, _) => dirty = true,
                _ => {}
            }
        }
    }
}

/// Hand the terminal to an interactive `tsh` subcommand, then refresh and surface
/// a non-zero exit. `pause` holds a finished command's output until a keypress.
fn run_and_report(terminal: &mut Tui, app: &mut App, args: &[String], label: &str, pause: bool) {
    let result = ssh::run_interactive(terminal, &app.tsh, args, label, &[], pause);
    app.after_action();
    if let Ok(status) = result
        && !status.success()
    {
        app.note_command_exit(status.code());
    }
}

/// Dispatch the [`Outcome`] of a key press. Returns `true` when the app should
/// quit; every other outcome is handled here (interactive handoff, background
/// proxy launches, kube exec, recording replay) and returns `false`.
fn handle_key(terminal: &mut Tui, app: &mut App, key: KeyEvent) -> bool {
    match app.on_key(key) {
        Outcome::Quit => return true,
        Outcome::Continue => {}
        Outcome::Run { args, label } => run_and_report(terminal, app, &args, &label, false),
        // A one-off command finishes on its own — pause on its output (a keypress
        // returns) so a fast command's result isn't wiped by the TUI redraw.
        Outcome::RunCommand { args, label } => run_and_report(terminal, app, &args, &label, true),
        // Proxy launches block (port wait / kubeconfig handshake) for up to
        // several seconds — run them on a worker thread and handle completion in
        // `drain_proxy_events`, so the UI never freezes.
        Outcome::OpenApp {
            name,
            cluster,
            port,
        } => {
            app.note_connecting(&format!("Connecting to app {name}…"));
            let tx = app.proxy_sender();
            let tsh = app.tsh.clone();
            thread::spawn(move || {
                let result = proxy::open_app(&tsh, &name, &cluster, port);
                let _ = tx.send(app::ProxyEvent::AppReady {
                    name,
                    kind: app::ProxyKind::App,
                    result,
                });
            });
        }
        Outcome::OpenDbProxy { name, cluster } => {
            app.note_connecting(&format!("Starting db proxy for {name}…"));
            let tx = app.proxy_sender();
            let tsh = app.tsh.clone();
            thread::spawn(move || {
                // Random local port; the endpoint is shown in the overlay.
                let result = proxy::open_db(&tsh, &name, &cluster, None);
                let _ = tx.send(app::ProxyEvent::AppReady {
                    name,
                    kind: app::ProxyKind::Db,
                    result,
                });
            });
        }
        Outcome::OpenKube {
            kube,
            cluster,
            user,
            tool,
        } => {
            app.note_connecting(&format!("Opening {tool} on {kube}…"));
            let tx = app.proxy_sender();
            let tsh = app.tsh.clone();
            thread::spawn(move || {
                let result = proxy::start_kube_proxy(&tsh, &kube, &cluster, user.as_deref());
                let _ = tx.send(app::ProxyEvent::KubeReady { kube, tool, result });
            });
        }
        Outcome::OpenForward {
            cluster,
            user,
            host,
            spec,
            label,
        } => {
            app.note_connecting(&label);
            let tx = app.proxy_sender();
            let tsh = app.tsh.clone();
            let target = if user.is_empty() {
                host.clone()
            } else {
                format!("{user}@{host}")
            };
            thread::spawn(move || {
                let result = proxy::start_ssh_forward(&tsh, &cluster, &user, &host, &spec);
                let _ = tx.send(app::ProxyEvent::ForwardReady {
                    spec,
                    target,
                    cluster,
                    result,
                });
            });
        }
        Outcome::KubeExec {
            cluster,
            kube,
            exec,
            label,
        } => handle_kube_exec(terminal, app, &cluster, &kube, &exec, &label),
        Outcome::PlayRecording { args, label } => {
            handle_play(terminal, app, &args, &label);
        }
    }
    false
}

/// Replay a recording interruptibly (Esc/q returns to the TUI); surface a
/// non-zero natural exit in the status bar.
fn handle_play(terminal: &mut Tui, app: &mut App, args: &[String], label: &str) {
    if let Ok(Some(status)) = ssh::play_recording(terminal, &app.tsh, args, label)
        && !status.success()
    {
        app.note_command_exit(status.code());
    }
    app.after_action();
}

/// `tsh kube exec` has no cluster flag, so select the kube context first
/// (`tsh kube login`); only run the exec if that succeeds. Two sequential
/// terminal hand-offs, both on the UI thread (they own the terminal).
fn handle_kube_exec(
    terminal: &mut Tui,
    app: &mut App,
    cluster: &str,
    kube: &str,
    exec: &[String],
    label: &str,
) {
    let login = application::command::kube_login(cluster, kube);
    let login_label = format!("Selecting kube cluster {kube}…");
    let logged_in = matches!(
        ssh::run_interactive(terminal, &app.tsh, &login, &login_label, &[], false),
        Ok(status) if status.success()
    );
    if logged_in {
        // The exec is a one-off command → pause on its output before resuming.
        if let Ok(status) = ssh::run_interactive(terminal, &app.tsh, exec, label, &[], true)
            && !status.success()
        {
            app.note_command_exit(status.code());
        }
    } else {
        app.report_app_error(&format!("could not select kube cluster {kube}"));
    }
    app.after_action();
}

/// React to a completed background proxy launch. Runs on the UI thread, which
/// owns the terminal — required for the kube shell handoff (`run_interactive`).
fn handle_proxy_event(terminal: &mut Tui, app: &mut App, ev: app::ProxyEvent) {
    match ev {
        app::ProxyEvent::AppReady { name, kind, result } => match result {
            Ok((child, url)) => app.attach_proxy(app::AppProxy::new(child, name, url, kind)),
            Err(e) => app.report_app_error(&e.to_string()),
        },
        app::ProxyEvent::KubeReady { kube, tool, result } => match result {
            Ok((mut child, kubeconfig)) => {
                let (program, pargs) = proxy::tool_command(&tool);
                let label = format!("Opening {tool} on {kube} (proxy ready)…");
                let r = ssh::run_interactive(
                    terminal,
                    Path::new(&program),
                    &pargs,
                    &label,
                    &[("KUBECONFIG", kubeconfig.as_str())],
                    false,
                );
                let _ = child.kill();
                let _ = child.wait();
                match r {
                    Ok(status) if !status.success() => app.note_command_exit(status.code()),
                    _ => app.note_session_ended(),
                }
            }
            Err(e) => app.report_app_error(&e.to_string()),
        },
        app::ProxyEvent::ForwardReady {
            spec,
            target,
            cluster,
            result,
        } => match result {
            Ok(child) => app.attach_forward(app::Forward::new(child, spec, target, cluster)),
            Err(e) => app.report_forward_error(&e.to_string()),
        },
    }
}

/// Best-effort unique id for correlating log lines within a run.
fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{:x}", nanos ^ u128::from(std::process::id()))
}

#[derive(Debug)]
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        // Mouse capture lets the wheel scroll the lists. Trade-off: the terminal's
        // native click-drag text selection is intercepted, so copy/paste needs the
        // usual Shift-modifier. Disabled during any `tsh` handoff (see ssh.rs) so
        // the child session keeps native mouse behaviour.
        execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
        let _ = disable_raw_mode();
        original(info);
    }));
}
