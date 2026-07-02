//! Modal form/prompt rendering (login, proxy, db-user, app-port, settings,
//! scp, kube-exec, add-user) and their shared line/label helpers.
//!
//! Split out of `ui`; imports and shared render helpers arrive via `super::*`.

#[allow(clippy::wildcard_imports)]
use super::*;

/// One editable form row: (label, current value, is-focused, hint).
type FormRow<'a> = (&'a str, String, bool, &'a str);

/// Render a vertical form (header, focused rows, footer lines) into `lines`.
/// Dropdown rows show `‹ value ›`; the focused text row gets a cursor block.
/// Extra footer lines (e.g. a security note) are appended after the main footer.
fn form_lines(
    header: &str,
    rows: &[FormRow],
    focus: usize,
    footers: &[&str],
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            header.to_owned(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    for (i, (label, value, dropdown, hint)) in rows.iter().enumerate() {
        let focused = i == focus;
        let value_style = if focused {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        let marker = if focused { "▶ " } else { "  " };
        let shown = if *dropdown {
            format!("‹ {value} ›")
        } else if focused {
            format!("{value}█")
        } else {
            value.clone()
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{marker}{label}: "),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(shown, value_style),
        ]));
        if focused {
            lines.push(Line::from(Span::styled(
                format!("      {hint}"),
                Style::default().fg(Color::DarkGray),
            )));
        }
    }
    lines.push(Line::from(""));
    for footer in footers {
        lines.push(Line::from(Span::styled(
            (*footer).to_owned(),
            Style::default().fg(Color::DarkGray),
        )));
    }
    lines
}

/// "(default)" placeholder for an empty dropdown/text value.
fn or_default(v: &str) -> String {
    if v.is_empty() {
        "(default)".to_owned()
    } else {
        v.to_owned()
    }
}

pub(super) fn render_login_form(frame: &mut Frame, app: &App) {
    let f = &app.login_form;
    let area = centered(frame.area(), 64, 45);
    frame.render_widget(Clear, area);
    let rows: [FormRow; 4] = [
        (
            "Proxy   ",
            f.proxy.clone(),
            false,
            "host[:port], e.g. root.example.com",
        ),
        (
            "User    ",
            f.user.clone(),
            false,
            "Teleport user (blank = local user)",
        ),
        (
            "Auth    ",
            or_default(f.auth_str()),
            true,
            "←/→ choose · local=password · passwordless=key · sso=browser",
        ),
        (
            "MFA mode",
            or_default(f.mfa_str()),
            true,
            "←/→ choose · otp typed · platform=TPM · webauthn/sso/browser",
        ),
    ];
    let lines = form_lines(
        "Log in to Teleport",
        &rows,
        f.field,
        &[
            "Tab/↑↓ move · type or ←/→ to edit · Enter login · Esc cancel",
            "password & MFA are prompted by tsh in the terminal (not stored)",
        ],
    );
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Login ")),
        area,
    );
}

pub(super) fn render_proxy(frame: &mut Frame, app: &App) {
    let Some(proxy) = &app.proxy else { return };
    let area = centered(frame.area(), 64, 30);
    frame.render_widget(Clear, area);
    let (title, heading, addr_label, note) = match proxy.kind {
        crate::app::ProxyKind::App => (
            " Application access ",
            "App proxy running",
            "URL:      ",
            "A browser was opened. Keep this proxy running while you use the app.",
        ),
        crate::app::ProxyKind::Db => (
            " Database access ",
            "DB proxy running",
            "Endpoint: ",
            "Point your database client at this local address (no extra credentials needed).",
        ),
    };
    let text = vec![
        Line::from(Span::styled(
            format!("{heading} — {}", proxy.name),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw(addr_label),
            Span::styled(
                proxy.url.clone(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::UNDERLINED),
            ),
        ]),
        Line::from(note),
        Line::from(""),
        Line::from(Span::styled(
            "Esc / q to stop the proxy and return to the menu.",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::bordered().title(title)),
        area,
    );
}

pub(super) fn render_db_user(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 60, 22);
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from("Connect to database"),
        Line::from(vec![
            Span::raw("db user: "),
            Span::styled(
                format!("{}\u{2588}", app.input),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(Span::styled(
            "Enter to connect (blank = default user)  Esc cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::bordered().title(" Database connect ")),
        area,
    );
}

pub(super) fn render_app_port(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 60, 22);
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from("Open application proxy"),
        Line::from(vec![
            Span::raw("local port: "),
            Span::styled(
                format!("{}\u{2588}", app.input),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(Span::styled(
            "Enter to open (blank = random free port)  Esc cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::bordered().title(" App proxy port ")),
        area,
    );
}

pub(super) fn render_settings(frame: &mut Frame, app: &App) {
    let f = &app.settings_form;
    let area = centered(frame.area(), 76, 80);
    frame.render_widget(Clear, area);
    let rows: [FormRow; 9] = [
        (
            "SSH login    ",
            f.ssh_login.clone(),
            false,
            "default SSH user — set = connect without the picker",
        ),
        (
            "Kube user    ",
            f.kube_user.clone(),
            false,
            "default kube user (--as) — set = skip the picker",
        ),
        (
            "DB user      ",
            f.db_user.clone(),
            false,
            "default db user (--db-user) — set = skip the prompt",
        ),
        (
            "Login proxy  ",
            f.proxy.clone(),
            false,
            "pre-fills the login form proxy",
        ),
        (
            "Login user   ",
            f.user.clone(),
            false,
            "pre-fills the login form user",
        ),
        (
            "Login auth   ",
            or_default(f.auth_str()),
            true,
            "←/→ — login connector default",
        ),
        (
            "Login MFA    ",
            or_default(f.mfa_str()),
            true,
            "←/→ — login MFA mode default",
        ),
        (
            "Refresh secs ",
            f.refresh.clone(),
            false,
            "auto-refresh interval (blank/0 = off) — applies next launch",
        ),
        (
            "Kube tools   ",
            f.kube_tools.clone(),
            false,
            "comma-separated launchers, e.g. shell, k9s, lens",
        ),
    ];
    let lines = form_lines(
        "Settings — default behaviours (persisted to config.toml)",
        &rows,
        f.field,
        &["Tab/↑↓ move · type or ←/→ to edit · Enter save · Esc cancel"],
    );
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Settings ")),
        area,
    );
}

pub(super) fn render_scp(frame: &mut Frame, app: &App) {
    let f = &app.scp_form;
    let area = centered(frame.area(), 70, 55);
    frame.render_widget(Clear, area);
    let dir = if f.download {
        "Download (remote → local)"
    } else {
        "Upload (local → remote)"
    };
    let rec = if f.recursive { "yes (-r)" } else { "no" };
    let rows: [FormRow; 5] = [
        (
            "Direction",
            dir.to_owned(),
            true,
            "←/→ switch · copy from the node, or send to it",
        ),
        (
            "Login    ",
            f.login.clone(),
            false,
            "SSH user on the node (blank = default)",
        ),
        (
            "Remote   ",
            f.remote.clone(),
            false,
            "path ON the node, e.g. /var/log/app.log",
        ),
        (
            "Local    ",
            f.local.clone(),
            false,
            "path on THIS machine, e.g. ./download/",
        ),
        (
            "Recursive",
            rec.to_owned(),
            true,
            "←/→ toggle · required for directories",
        ),
    ];
    let lines = form_lines(
        &format!("Transfer files — {} ({})", f.host, f.cluster),
        &rows,
        f.field,
        &["Tab/↑↓ move · type or ←/→ to edit · Enter transfer · Esc cancel"],
    );
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" SCP file transfer ")),
        area,
    );
}

pub(super) fn render_ssh_options(frame: &mut Frame, app: &App) {
    let f = &app.ssh_options_form;
    let area = centered(frame.area(), 70, 55);
    frame.render_widget(Clear, area);
    let tunnel = if f.tunnel_only {
        "yes (-N, no shell)"
    } else {
        "no"
    };
    let rows: [FormRow; 4] = [
        (
            "Login   ",
            f.login.clone(),
            false,
            "SSH user on the node (blank = default)",
        ),
        (
            "Forward ",
            f.forward.clone(),
            false,
            "-L local port-forward, e.g. 8080:localhost:80",
        ),
        (
            "Tunnel  ",
            tunnel.to_owned(),
            true,
            "←/→ toggle · open the forward without a shell (needs Forward)",
        ),
        (
            "Command ",
            f.command.clone(),
            false,
            "optional — run this instead of a shell (blank = shell)",
        ),
    ];
    let lines = form_lines(
        &format!("SSH options — {} ({})", f.host, f.cluster),
        &rows,
        f.field,
        &["Tab/↑↓ move · type or ←/→ to edit · Enter connect · Esc cancel"],
    );
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" SSH options ")),
        area,
    );
}

pub(super) fn render_add_user(frame: &mut Frame, app: &App) {
    let f = &app.add_user_form;
    let rows: Vec<FormRow> = vec![
        (
            "username",
            f.username.clone(),
            false,
            "the new user's login name",
        ),
        (
            "roles",
            f.roles.clone(),
            false,
            "comma-separated, e.g. access,editor",
        ),
    ];
    let lines = form_lines(
        "Create user (tctl users add)",
        &rows,
        f.field,
        &["Tab/↑↓ move · type to edit · Enter create · Esc cancel"],
    );
    let area = centered(frame.area(), 64, 40);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Add user ")),
        area,
    );
}

pub(super) fn render_kube_exec(frame: &mut Frame, app: &App) {
    let f = &app.kube_exec_form;
    let rows: Vec<FormRow> = vec![
        ("pod / deployment", f.pod.clone(), false, "target name"),
        (
            "command",
            f.command.clone(),
            false,
            "space-separated, e.g. sh -c 'echo hi' → no shell, tokens only",
        ),
        (
            "container",
            f.container.clone(),
            false,
            "optional — defaults to the pod's first/annotated container",
        ),
        (
            "namespace",
            f.namespace.clone(),
            false,
            "optional — defaults to the configured namespace",
        ),
    ];
    let lines = form_lines(
        "Exec in pod (tsh kube exec)",
        &rows,
        f.field,
        &["Tab/↑↓ move · type to edit · Enter run · Esc cancel"],
    );
    let area = centered(frame.area(), 70, 50);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Kube exec ")),
        area,
    );
}
