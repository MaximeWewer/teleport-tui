//! Rendering (the "view"). Reads `App` state; never mutates business data.

use domain::cluster::{ClusterContext, ClusterKind, ClusterStatus};
use domain::resource::Resource;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table};

use crate::app::{App, Mode, Tab};

mod body;
mod chrome;
mod forms;
mod overlays;
// Bring the child render fns into scope for the `render` dispatcher below, and —
// since the children `use super::*` — for cross-module calls between them.
#[allow(clippy::wildcard_imports)]
use body::*;
#[allow(clippy::wildcard_imports)]
use chrome::*;
#[allow(clippy::wildcard_imports)]
use forms::*;
#[allow(clippy::wildcard_imports)]
use overlays::*;

pub(crate) fn render(frame: &mut Frame, app: &mut App) {
    let [tabs_area, status_area, body_area, footer_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(4),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    render_tabs(frame, app, tabs_area);
    render_status(frame, app, status_area);
    render_body(frame, app, body_area);
    render_footer(frame, app, footer_area);

    match &app.mode {
        Mode::Picker => render_picker(frame, app),
        Mode::Login(_) => render_login(frame, app),
        Mode::CreateRequest => render_create(frame, app),
        Mode::ConfirmLogout => render_confirm_logout(frame),
        Mode::ConfirmTokenRm => render_confirm_token_rm(frame),
        Mode::ConfirmUserReset(_) => render_confirm_user_reset(frame, app),
        Mode::AddUser => render_add_user(frame, app),
        Mode::ShowInvite => render_invite(frame, app),
        Mode::ShowMfa => render_mfa(frame, app),
        Mode::ConfirmMfaRm(_) => render_confirm_mfa_rm(frame, app),
        Mode::ShowSessions => render_sessions(frame, app),
        Mode::ShowDetail { .. } => render_detail(frame, app),
        Mode::CreateToken => render_token(frame, app),
        Mode::ShowToken => render_token_result(frame, app),
        Mode::UserPicker(_) => render_user_picker(frame, app),
        Mode::ToolPicker { .. } => render_tool_picker(frame, app),
        Mode::DbUser { .. } => render_db_user(frame, app),
        Mode::AppPort { .. } => render_app_port(frame, app),
        Mode::Scp => render_scp(frame, app),
        Mode::SshOptions => render_ssh_options(frame, app),
        Mode::Forwards => render_forwards(frame, app),
        Mode::KubeExec { .. } => render_kube_exec(frame, app),
        Mode::Settings => render_settings(frame, app),
        Mode::LoginForm => render_login_form(frame, app),
        Mode::AppProxy => render_proxy(frame, app),
        Mode::Help => render_help(frame, app),
        _ => {}
    }
}

/// A centred rectangle covering `pct_x` × `pct_y` percent of `area`.
fn centered(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let [_, vmid, _] = Layout::vertical([
        Constraint::Percentage((100 - pct_y) / 2),
        Constraint::Percentage(pct_y),
        Constraint::Percentage((100 - pct_y) / 2),
    ])
    .areas(area);
    let [_, hmid, _] = Layout::horizontal([
        Constraint::Percentage((100 - pct_x) / 2),
        Constraint::Percentage(pct_x),
        Constraint::Percentage((100 - pct_x) / 2),
    ])
    .areas(vmid);
    hmid
}
