//! Popup overlays: pickers, confirmations, one-time secret views, MFA/session
//! lists, and the help screen — drawn centred over the frame.
//!
//! Split out of `ui`; imports and shared render helpers arrive via `super::*`.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn render_tool_picker(frame: &mut Frame, app: &mut App) {
    let items: Vec<ListItem> = app
        .tool_choices
        .iter()
        .map(|t| ListItem::new(Line::from(t.clone())))
        .collect();
    let area = centered(frame.area(), 50, 40);
    frame.render_widget(Clear, area);
    let list = List::new(items)
        .block(Block::bordered().title(" Open Kubernetes with (auto-proxy) "))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(list, area, &mut app.tool_picker);
}

pub(super) fn render_user_picker(frame: &mut Frame, app: &mut App) {
    let items: Vec<ListItem> = app
        .user_choices
        .iter()
        .map(|u| ListItem::new(Line::from(u.clone())))
        .collect();
    let area = centered(frame.area(), 50, 40);
    frame.render_widget(Clear, area);
    let list = List::new(items)
        .block(Block::bordered().title(" Connect as "))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(list, area, &mut app.user_picker);
}

pub(super) fn render_picker(frame: &mut Frame, app: &mut App) {
    let Some(topo) = &app.topology else { return };
    // Entry 0 is the all-clusters aggregate view.
    let mut items: Vec<ListItem> = vec![ListItem::new(Line::from(Span::styled(
        "★ All clusters (aggregate)",
        Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD),
    )))];
    items.extend(topo.all().iter().map(|c| {
        let dot = match c.status {
            ClusterStatus::Online => Span::styled("●", Style::default().fg(Color::Green)),
            ClusterStatus::Offline => Span::styled("●", Style::default().fg(Color::Red)),
        };
        ListItem::new(Line::from(vec![dot, Span::raw(" "), cluster_label(c)]))
    }));

    let area = centered(frame.area(), 50, 50);
    frame.render_widget(Clear, area);
    let list = List::new(items)
        .block(Block::bordered().title(" Switch cluster / All "))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(list, area, &mut app.picker);
}

pub(super) fn render_login(frame: &mut Frame, app: &App) {
    let host = app
        .selected_node()
        .map_or_else(|| "?".to_owned(), |n| n.hostname.to_string());
    let area = centered(frame.area(), 50, 20);
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from(format!("SSH to {host}")),
        Line::from(vec![
            Span::raw("login: "),
            Span::styled(
                format!("{}\u{2588}", app.input),
                Style::default().fg(Color::White),
            ),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::bordered().title(" Connect ")),
        area,
    );
}

pub(super) fn render_create(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 60, 20);
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from("New access request"),
        Line::from(vec![
            Span::raw("roles: "),
            Span::styled(
                format!("{}\u{2588}", app.input),
                Style::default().fg(Color::White),
            ),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::bordered().title(" Create request ")),
        area,
    );
}

pub(super) fn render_token_result(frame: &mut Frame, app: &App) {
    let Some(tv) = &app.token_view else { return };
    let area = centered(frame.area(), 80, 50);
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::from(Span::styled(
            "Join token generated",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("token:   "),
            Span::styled(
                tv.token.as_str().to_owned(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(format!("roles:   {}", tv.roles.join(", "))),
        Line::from(format!("expires: {}", tv.expires)),
    ];
    for (i, pin) in tv.ca_pins.iter().enumerate() {
        let label = if i == 0 { "ca pins: " } else { "         " };
        lines.push(Line::from(format!("{label}{pin}")));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "copy it now — it is shown once and not stored or logged.  any key to close.",
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Token (secret) ")),
        area,
    );
}

pub(super) fn render_invite(frame: &mut Frame, app: &App) {
    let Some(iv) = &app.invite_view else { return };
    let area = centered(frame.area(), 90, 40);
    frame.render_widget(Clear, area);
    let lines = vec![
        Line::from(Span::styled(
            "Account setup URL",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("user: {}", iv.user)),
        Line::from(vec![
            Span::raw("url:  "),
            Span::styled(
                iv.url.as_str().to_owned(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "share it now — it is shown once and not stored or logged.  any key to close.",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Setup URL (secret) ")),
        area,
    );
}

pub(super) fn render_mfa(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 80, 50);
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::from(Span::styled(
            "Your MFA devices",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    if app.mfa_devices.is_empty() {
        lines.push(Line::from("No MFA devices registered."));
    } else {
        for (i, d) in app.mfa_devices.iter().enumerate() {
            let selected = i == app.mfa_sel;
            let marker = if selected { "▶ " } else { "  " };
            let name_style = if selected {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(format!("{}  ", d.name), name_style),
                Span::styled(format!("[{}]", d.kind), Style::default().fg(Color::Cyan)),
            ]));
            lines.push(Line::from(Span::styled(
                format!("    added {}   ·   last used {}", d.added, d.last_used),
                Style::default().fg(Color::DarkGray),
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "↑/↓ select · a add · d remove · Esc/q close",
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" MFA devices (tsh mfa ls) ")),
        area,
    );
}

pub(super) fn render_sessions(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 88, 50);
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::from(Span::styled(
            "Active sessions",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    if app.sessions.is_empty() {
        lines.push(Line::from("No active sessions on this cluster."));
    } else {
        for (i, s) in app.sessions.iter().enumerate() {
            let selected = i == app.sessions_sel;
            let marker = if selected { "▶ " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(format!("{:<5} {}", s.kind, s.host), style),
                Span::styled(
                    format!("   login={} · by {} · {}", s.login, s.started_by, s.created),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "↑/↓ select · Enter join · Esc/q close",
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Active sessions (tsh sessions ls) ")),
        area,
    );
}

pub(super) fn render_forwards(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 88, 50);
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::from(Span::styled(
            "Active SSH forwards",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    if app.forwards.is_empty() {
        lines.push(Line::from(
            "No active forwards. Open one from an SSH node (o).",
        ));
    } else {
        for (i, f) in app.forwards.iter().enumerate() {
            let selected = i == app.forwards_sel;
            let marker = if selected { "▶ " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(format!("-L {:<24}", f.spec), style),
                Span::styled(
                    format!("   {} · {}", f.target, f.cluster),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "↑/↓ select · Enter/d stop · Esc close",
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" SSH forwards (tsh ssh -L … -N) ")),
        area,
    );
}

pub(super) fn render_confirm_mfa_rm(frame: &mut Frame, app: &App) {
    let name = match &app.mode {
        Mode::ConfirmMfaRm(n) => n.as_str(),
        _ => "",
    };
    let area = centered(frame.area(), 60, 18);
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from(format!("Remove MFA device \"{name}\"?")),
        Line::from(Span::styled(
            "y / Enter = remove    Esc = cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::bordered().title(" Confirm MFA removal ")),
        area,
    );
}

pub(super) fn render_confirm_user_reset(frame: &mut Frame, app: &App) {
    let user = match &app.mode {
        Mode::ConfirmUserReset(u) => u.as_str(),
        _ => "",
    };
    let area = centered(frame.area(), 64, 20);
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from(format!("Reset password and 2FA for \"{user}\"?")),
        Line::from(Span::styled(
            "Invalidates their current credentials; issues a one-time setup URL.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "y / Enter = reset    Esc = cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::bordered().title(" Confirm user reset ")),
        area,
    );
}

/// The keybinding rows shown in the help overlay, gated by capabilities/rights.
fn help_action_rows(
    app: &App,
    visible_tabs: &[String],
    enter_acts: &[&str],
) -> Vec<(&'static str, String)> {
    let mut rows: Vec<(&str, String)> = vec![
        ("Tab / Shift-Tab", "next / previous visible tab".to_owned()),
        (
            "1 – 0",
            format!("jump to tab — {}", visible_tabs.join("  ")),
        ),
        ("↑/↓  j/k", "move selection".to_owned()),
        ("/", "incremental search/filter".to_owned()),
        ("Enter", format!("open: {}", enter_acts.join(" • "))),
    ];
    rows.push((
        "o",
        "SSH: options — -L port-forward, -N tunnel, or a one-off command".to_owned(),
    ));
    rows.push((
        "F",
        "list/stop active background SSH forwards (tunnels)".to_owned(),
    ));
    if app.caps.supports("scp") {
        rows.push((
            "s",
            "SSH: scp file/folder transfer (upload or download)".to_owned(),
        ));
    }
    rows.push((
        "P",
        "Db: start a local tsh proxy db tunnel for a GUI client".to_owned(),
    ));
    rows.push((
        "l / u",
        "Db/Apps: retrieve / remove certificate (tsh db|apps login/logout)".to_owned(),
    ));
    rows.push((
        "e",
        "Kube: exec a command in a pod (tsh kube login + kube exec)".to_owned(),
    ));
    if app.tab_visible(Tab::Recordings) {
        rows.push((
            "Enter",
            "Recordings: replay the selected session (tsh play; Esc/q stops it)".to_owned(),
        ));
    }
    rows.push(("c", "switch root / leaf cluster".to_owned()));
    rows.push(("r", "refresh current tab".to_owned()));
    if app.caps.supports("mfa") {
        rows.push(("M", "MFA devices: list / add / remove (tsh mfa)".to_owned()));
    }
    if app.caps.supports("sessions") {
        rows.push((
            "S",
            "active sessions: list / join (tsh sessions, join)".to_owned(),
        ));
    }
    if app.tab_visible(Tab::Requests) {
        rows.push(("a / d", "Requests: approve / deny selected".to_owned()));
        rows.push(("D", "Requests: drop (un-assume) selected".to_owned()));
        rows.push(("n", "Requests: new access request".to_owned()));
    }
    if app.admin_allowed {
        rows.push((
            "g / d",
            "Tokens: generate / remove join token (tctl)".to_owned(),
        ));
        rows.push((
            "n / R",
            "Users: new user / reset selected user (tctl)".to_owned(),
        ));
    }
    rows.push(("L", "login (tsh login)".to_owned()));
    rows.push((
        "p",
        "settings — edit & persist default behaviours".to_owned(),
    ));
    rows.push(("O", "logout (with confirmation)".to_owned()));
    rows.push(("?", "this help".to_owned()));
    rows.push(("q / Esc", "quit".to_owned()));
    rows
}

pub(super) fn render_help(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 70, 80);
    frame.render_widget(Clear, area);
    // Only list tabs/actions reachable on this install (capabilities + rights).
    let mut visible_tabs: Vec<String> = [
        (1, Tab::Ssh, "SSH"),
        (2, Tab::Kube, "Kube"),
        (3, Tab::Db, "Db"),
        (4, Tab::Apps, "Apps"),
        (5, Tab::Users, "Users"),
        (6, Tab::Roles, "Roles"),
        (7, Tab::Requests, "Requests"),
        (8, Tab::Tokens, "Tokens"),
        (9, Tab::Bots, "Bots"),
        (0, Tab::Inventory, "Inventory"),
    ]
    .into_iter()
    .filter(|(_, t, _)| app.tab_visible(*t))
    .map(|(n, _, name)| format!("{n} {name}"))
    .collect();
    // Recordings has no number key (11th tab); reachable via Tab cycling.
    if app.tab_visible(Tab::Recordings) {
        visible_tabs.push("Tab→ Recordings".to_owned());
    }

    let mut enter_acts = vec!["SSH login"];
    if app.tab_visible(Tab::Kube) {
        enter_acts.push("kube login");
    }
    if app.tab_visible(Tab::Db) {
        enter_acts.push("db connect");
    }
    if app.tab_visible(Tab::Apps) {
        enter_acts.push("app login");
    }
    if app.tab_visible(Tab::Requests) {
        enter_acts.push("request show");
    }

    let rows = help_action_rows(app, &visible_tabs, &enter_acts);

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            "teleport-tui — keybindings",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    for (k, v) in rows {
        lines.push(Line::from(vec![
            Span::styled(format!("{k:16}"), Style::default().fg(Color::Cyan)),
            Span::raw(v),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Help ")),
        area,
    );
}

pub(super) fn render_token(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 60, 22);
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from("Generate join token (tctl)"),
        Line::from(vec![
            Span::raw("type: "),
            Span::styled(
                format!("{}\u{2588}", app.input),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(Span::styled(
            "the token will print to your terminal (not logged)",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::bordered().title(" Generate token ")),
        area,
    );
}

pub(super) fn render_confirm_logout(frame: &mut Frame) {
    let area = centered(frame.area(), 50, 18);
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from("Log out of Teleport?"),
        Line::from(Span::styled(
            "y / Enter = logout    Esc = cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::bordered().title(" Confirm logout ")),
        area,
    );
}

pub(super) fn render_confirm_token_rm(frame: &mut Frame) {
    let area = centered(frame.area(), 56, 18);
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from("Remove the selected join token?"),
        Line::from(Span::styled(
            "This revokes it immediately and cannot be undone.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "y / Enter = remove    Esc = cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::bordered().title(" Confirm token removal ")),
        area,
    );
}

/// Read-only full-field detail popup for the selected admin row. Labels are
/// left-aligned to a common width; long values wrap instead of truncating.
pub(super) fn render_detail(frame: &mut Frame, app: &App) {
    let Mode::ShowDetail {
        title,
        rows,
        scroll,
    } = &app.mode
    else {
        return;
    };
    let area = centered(frame.area(), 72, 70);
    frame.render_widget(Clear, area);
    let label_w = rows
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    let label_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    // Continuation lines of a multi-valued field align under the value column.
    let pad = " ".repeat(label_w + 2);
    let mut lines: Vec<Line> = Vec::new();
    for (label, values) in rows {
        // A field with no values still gets a row, shown as "-".
        if values.is_empty() {
            lines.push(Line::from(vec![
                Span::styled(format!("{label:<label_w$}  "), label_style),
                Span::raw("-"),
            ]));
            continue;
        }
        // One line per value; only the first carries the label.
        for (i, v) in values.iter().enumerate() {
            let head = if i == 0 {
                Span::styled(format!("{label:<label_w$}  "), label_style)
            } else {
                Span::raw(pad.clone())
            };
            let value = if v.is_empty() { "-" } else { v.as_str() };
            lines.push(Line::from(vec![head, Span::raw(value.to_owned())]));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(format!(" {title} ")))
            .wrap(ratatui::widgets::Wrap { trim: false })
            .scroll((*scroll, 0)),
        area,
    );
}
