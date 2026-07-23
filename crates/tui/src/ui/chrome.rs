//! Frame chrome: the tab bar, the top status/profile line, and the bottom
//! footer/hints. Rendered around the body by [`super::render`].
//!
//! Split out of `ui`; imports and shared render helpers arrive via `super::*`.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn render_tabs(frame: &mut Frame, app: &App, area: Rect) {
    // Only show tabs the installed `tsh` supports (and admin tabs only with
    // rights) — hidden tabs never appear rather than erroring on use.
    let access: Vec<Tab> = Tab::ACCESS
        .into_iter()
        .filter(|t| app.tab_visible(*t))
        .collect();
    let admin: Vec<Tab> = Tab::ADMIN
        .into_iter()
        .filter(|t| app.tab_visible(*t))
        .collect();
    let audit: Vec<Tab> = Tab::AUDIT
        .into_iter()
        .filter(|t| app.tab_visible(*t))
        .collect();
    let mut spans: Vec<Span> = Vec::new();
    push_group(&mut spans, "Access:", &access, app.tab);
    if !admin.is_empty() {
        spans.push(Span::styled("  |  ", Style::default().fg(Color::DarkGray)));
        push_group(&mut spans, "Admin:", &admin, app.tab);
    }
    if !audit.is_empty() {
        spans.push(Span::styled("  |  ", Style::default().fg(Color::DarkGray)));
        push_group(&mut spans, "Audit:", &audit, app.tab);
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn push_group(spans: &mut Vec<Span<'static>>, label: &'static str, tabs: &[Tab], active: Tab) {
    spans.push(Span::styled(
        format!("{label} "),
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    ));
    for (i, t) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        let style = if *t == active {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        spans.push(Span::styled(format!(" {} ", t.title()), style));
    }
}

pub(super) fn cluster_label(c: &ClusterContext) -> Span<'static> {
    let color = match c.kind {
        ClusterKind::Root => Color::Cyan,
        ClusterKind::Leaf => Color::Yellow,
    };
    let tag = match c.kind {
        ClusterKind::Root => "root",
        ClusterKind::Leaf => "leaf",
    };
    Span::styled(
        format!("{} [{tag}]", c.name),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

pub(super) fn render_status(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans: Vec<Span> = vec![Span::raw("Cluster: ")];
    if let Some(topo) = &app.topology {
        spans.push(Span::styled(
            format!("{}", topo.root().name),
            Style::default().fg(Color::Cyan),
        ));
        spans.push(Span::raw("  ▸  "));
        if app.aggregate {
            spans.push(Span::styled(
                "★ ALL CLUSTERS",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(cluster_label(topo.selected()));
            let (txt, col) = match topo.selected().status {
                ClusterStatus::Online => ("online", Color::Green),
                ClusterStatus::Offline => ("offline", Color::Red),
            };
            spans.push(Span::raw("  "));
            spans.push(Span::styled(txt, Style::default().fg(col)));
        }
    } else {
        spans.push(Span::styled(
            "(loading…)",
            Style::default().fg(Color::DarkGray),
        ));
    }

    let mut lines = vec![Line::from(spans)];
    lines.push(profile_line(app));
    if app.loading {
        lines.push(Line::from(Span::styled(
            format!("{} loading…", app.spinner_frame()),
            Style::default().fg(Color::Yellow),
        )));
    } else if let Some(msg) = &app.status {
        lines.push(Line::from(Span::styled(
            msg.clone(),
            Style::default().fg(Color::DarkGray),
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" teleport-tui ");
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn profile_line(app: &App) -> Line<'static> {
    match &app.profile {
        Some(p) => {
            let exp: String = p.valid_until.chars().take(19).collect();
            Line::from(vec![
                Span::styled(
                    p.username.clone(),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  logins: "),
                Span::raw(p.logins.join(",")),
                Span::raw("  cert valid until "),
                Span::styled(exp, Style::default().fg(Color::DarkGray)),
            ])
        }
        None => Line::from(Span::styled(
            "not logged in — press L to login",
            Style::default().fg(Color::Red),
        )),
    }
}

/// Build the Normal-mode footer from context: the active tab's actions, the
/// all-clusters prefix, and only the shortcuts the installed `tsh` supports
/// (e.g. `s scp` appears only when `tsh scp` exists).
fn normal_footer(app: &App) -> String {
    let aggregate = app.aggregating();
    let mut segs: Vec<&str> = vec!["↑/↓ move"];
    match app.tab {
        Tab::Requests => {
            segs.extend(["Enter show", "a approve", "d deny", "D drop", "n new"]);
        }
        Tab::Users => segs.extend(["n new user", "R reset"]),
        Tab::Tokens => segs.extend(["g generate", "d remove"]),
        Tab::Roles | Tab::Bots | Tab::Inventory => {} // read-only / no extra actions
        Tab::Recordings => segs.push("Enter play (Esc/q stops)"),

        Tab::Ssh => {
            segs.push("Enter connect");
            segs.push("o options");
            if app.caps.supports("scp") {
                segs.push("s scp");
            }
        }
        Tab::Db => segs.extend(["Enter connect", "P db-proxy", "l login", "u logout"]),
        Tab::Apps => segs.extend(["Enter open", "l login", "u logout"]),
        Tab::Kube => segs.extend(["Enter open", "e exec"]),
    }
    segs.push("/ search");
    segs.push("Tab switch");
    if !app.tab.is_admin() {
        segs.push("c cluster");
    }
    segs.push("r refresh");
    // Advertise the forwards popup only while tunnels are live (the count shows
    // inside it); the `F` shortcut still works from anywhere.
    if !app.forwards.is_empty() {
        segs.push("F forwards");
    }
    // The aggregate footer stays compact (session shortcuts omitted on purpose).
    if !aggregate {
        if app.caps.supports("sessions") {
            segs.push("S sessions");
        }
        if app.caps.supports("mfa") {
            segs.push("M mfa");
        }
        segs.extend(["L login", "p settings", "O logout", "? help"]);
    } else if app.tab.serial_aggregation() {
        // All-clusters admin/recordings: `L` logs into the highlighted cluster's
        // proxy so its rows can join the aggregate.
        segs.push("L login");
    }
    segs.push("q quit");
    let body = segs.join("  ");
    if aggregate {
        format!("ALL CLUSTERS  {body}")
    } else {
        body
    }
}

pub(super) fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    // The Normal-mode footer is assembled from segments gated by the active tab
    // and the installed `tsh`'s capabilities; other modes use a fixed prompt.
    let hint: String = if app.mode == Mode::Normal {
        normal_footer(app)
    } else {
        match &app.mode {
            Mode::Search => "type to filter  ↑/↓ select  Enter connect  Esc cancel",
            Mode::Picker => "↑/↓ choose cluster  Enter select  Esc/c close",
            Mode::Login(_) => "type login  Enter connect  Esc cancel",
            Mode::CreateRequest => "type roles (comma-separated)  Enter create  Esc cancel",
            Mode::ConfirmLogout => "log out of Teleport?  y/Enter confirm  Esc cancel",
            Mode::ConfirmTokenRm => "remove this join token?  y/Enter confirm  Esc cancel",
            Mode::ConfirmUserReset(_) => {
                "reset this user's credentials?  y/Enter confirm  Esc cancel"
            }
            Mode::AddUser => "Tab/↑↓ move  type to edit  Enter create  Esc cancel",
            Mode::ShowInvite => "copy the setup URL now — any key to close (it is not stored)",
            Mode::ShowMfa => "↑/↓ select · a add · d remove · Esc/q close",
            Mode::ConfirmMfaRm(_) => "remove this MFA device?  y/Enter confirm  Esc cancel",
            Mode::ShowSessions => "↑/↓ select · Enter join · Esc/q close",
            Mode::ShowDetail { .. } => "↑/↓ scroll · Esc/q/Enter close",
            Mode::CreateToken => {
                "type token type (node, app, db, kube…)  Enter generate  Esc cancel"
            }
            Mode::ShowToken => "copy the token now — any key to close (it is not stored)",
            Mode::UserPicker(_) => "↑/↓ choose user  Enter connect  Esc cancel",
            Mode::ToolPicker { .. } => "↑/↓ choose tool  Enter open  Esc cancel",
            Mode::DbUser { .. } => "type db user (blank = default)  Enter connect  Esc cancel",
            Mode::AppPort { .. } => "type local port (blank = random)  Enter open  Esc cancel",
            Mode::Scp => "Tab move · ←/→ direction · Enter transfer · Esc cancel",
            Mode::SshOptions => "Tab/↑↓ move · type or ←/→ toggle · Enter connect · Esc cancel",
            Mode::Forwards => "↑/↓ select · Enter/d stop · Esc close",
            Mode::KubeExec { .. } => "Tab/↑↓ move · type to edit · Enter run · Esc cancel",
            Mode::Settings => "Tab/↑↓ move · type or ←/→ edit · Enter save · Esc cancel",
            Mode::AppProxy => "app proxy running — Esc/q to stop and return",
            Mode::LoginForm => "Tab/↑↓ move  type to edit  Enter login  Esc cancel",
            Mode::Help => "press any key to close help",
            // The base view's footer is built elsewhere; no modal hint to show.
            Mode::Normal => "",
        }
        .to_owned()
    };
    let mut line = vec![Span::styled(hint, Style::default().fg(Color::DarkGray))];
    if app.mode == Mode::Search {
        line.push(Span::raw("   /"));
        line.push(Span::styled(
            app.input.clone(),
            Style::default().fg(Color::White),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(line)), area);
}
