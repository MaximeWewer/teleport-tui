//! Rendering (the "view"). Reads `App` state; never mutates business data.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};

use crate::app::{App, Mode};

mod body;
mod chrome;
mod forms;
mod overlays;

use body::render_body;
use chrome::{render_footer, render_status, render_tabs};
use forms::{
    render_add_user, render_app_port, render_db_user, render_kube_exec, render_login_form,
    render_proxy, render_scp, render_settings, render_ssh_options,
};
use overlays::{
    render_confirm_logout, render_confirm_mfa_rm, render_confirm_token_rm,
    render_confirm_user_reset, render_create, render_detail, render_forwards, render_help,
    render_invite, render_login, render_mfa, render_picker, render_sessions, render_token,
    render_token_result, render_tool_picker, render_user_picker,
};

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
