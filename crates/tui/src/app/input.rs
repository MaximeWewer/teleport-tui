//! Per-mode keyboard handling: the top-level [`super::App::on_key`] dispatcher
//! and every `on_key_*` handler for the modal screens (normal, search, pickers,
//! login/scp/settings/kube-exec forms, confirmations, token/user/MFA/session
//! flows), plus the small submit/confirm action helpers they drive.
//!
//! A child module of `app`: this is a second `impl super::App` block, so its
//! methods share `App`'s private fields and can call the update/dispatch methods
//! that stay in [`super`]. Model types and imports come in via `super::*`.

#[allow(clippy::wildcard_imports)]
use super::*;

impl App {
    /// Mouse-wheel scroll: reuse the active mode's ↑/↓ handling so the wheel moves
    /// the focused list (table, pickers, sessions/MFA) exactly like the arrows. A
    /// scroll never yields an actionable [`Outcome`] (those come from Enter/keys),
    /// so the result is discarded.
    pub(crate) fn on_scroll(&mut self, down: bool) {
        let code = if down { KeyCode::Down } else { KeyCode::Up };
        let _ = self.on_key(KeyEvent::from(code));
    }

    pub(crate) fn on_key(&mut self, key: KeyEvent) -> Outcome {
        // Reset before dispatch; only login/logout set it back to true.
        self.last_was_auth = false;
        // Clone the mode for dispatch: it isn't `Copy` (some variants own data),
        // and a couple of arms below reassign `self.mode`. Dispatch only routes on
        // the variant; each handler re-reads the carried data from `self.mode`.
        match self.mode.clone() {
            Mode::Normal => self.on_key_normal(key),
            Mode::Search => self.on_key_search(key),
            Mode::Picker => self.on_key_picker(key),
            Mode::Login(_) => self.on_key_login(key),
            Mode::CreateRequest => self.on_key_create(key),
            Mode::ConfirmLogout => self.on_key_confirm_logout(key),
            Mode::ConfirmTokenRm => self.on_key_confirm_token_rm(key),
            Mode::CreateToken => self.on_key_token(key),
            Mode::UserPicker(_) => self.on_key_user_picker(key),
            Mode::ToolPicker { .. } => self.on_key_tool_picker(key),
            Mode::DbUser { .. } => self.on_key_db_user(key),
            Mode::AppPort { .. } => self.on_key_app_port(key),
            Mode::Scp => self.on_key_scp(key),
            Mode::SshOptions => self.on_key_ssh_options(key),
            Mode::Forwards => self.on_key_forwards(key),
            Mode::KubeExec { .. } => self.on_key_kube_exec(key),
            Mode::Settings => self.on_key_settings(key),
            Mode::LoginForm => self.on_key_login_form(key),
            Mode::AppProxy => self.on_key_proxy(key),
            Mode::ShowToken => {
                // Any key dismisses; drop the token so it is zeroized.
                self.token_view = None;
                self.mode = Mode::Normal;
                Outcome::Continue
            }
            Mode::ShowInvite => {
                // Any key dismisses; drop the URL so it is zeroized.
                self.invite_view = None;
                self.mode = Mode::Normal;
                Outcome::Continue
            }
            Mode::ShowMfa => self.on_key_mfa(key),
            Mode::ConfirmMfaRm(_) => self.on_key_confirm_mfa_rm(key),
            Mode::ShowSessions => self.on_key_sessions(key),
            Mode::ShowDetail { .. } => {
                // Read-only popup: any key closes it.
                self.mode = Mode::Normal;
                Outcome::Continue
            }
            Mode::AddUser => self.on_key_add_user(key),
            Mode::ConfirmUserReset(_) => self.on_key_confirm_user_reset(key),
            Mode::Help => {
                self.mode = Mode::Normal;
                Outcome::Continue
            }
        }
    }

    /// Public refresh hook for the event loop's optional auto-refresh.
    pub(crate) fn refresh(&mut self) {
        self.force_reload();
    }

    /// Drop the active tab's caches (scoped and aggregate) and refetch. Used by
    /// `r` and auto-refresh so they always pull fresh data.
    ///
    /// Coalesces: if a load for the active tab is already in flight, do nothing —
    /// that load already yields fresh data. This stops mashing `r` (or a short
    /// auto-refresh interval over a large topology) from piling up overlapping
    /// `tsh` fan-outs / subprocesses.
    fn force_reload(&mut self) {
        if self.loading {
            return;
        }
        // No topology (initial `tsh clusters` failed): retry loading it, so `r`
        // recovers the cluster context instead of only refreshing the active tab.
        if self.topology.is_none() {
            self.status = Some("retrying tsh clusters…".to_owned());
            self.dispatch_aux(Job::Clusters);
            return;
        }
        self.cache_key.remove(&self.tab);
        // Drop every cluster's cached slice for this tab so `r` re-fetches them all.
        let tab = self.tab;
        self.agg_cache.retain(|(t, _), _| *t != tab);
        self.reload_active();
    }

    fn on_key_normal(&mut self, key: KeyEvent) -> Outcome {
        let ctrl_c =
            key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c');
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Outcome::Quit,
            _ if ctrl_c => return Outcome::Quit,
            KeyCode::Tab => self.switch_tab(self.next_visible_tab(true)),
            KeyCode::BackTab => self.switch_tab(self.next_visible_tab(false)),
            // Number keys jump to a tab only when it's visible (capability +
            // rights). An unsupported/hidden tab key is a no-op.
            KeyCode::Char('1') => self.switch_tab(Tab::Ssh),
            KeyCode::Char('2') if self.tab_visible(Tab::Kube) => self.switch_tab(Tab::Kube),
            KeyCode::Char('3') if self.tab_visible(Tab::Db) => self.switch_tab(Tab::Db),
            KeyCode::Char('4') if self.tab_visible(Tab::Apps) => self.switch_tab(Tab::Apps),
            KeyCode::Char('5') if self.tab_visible(Tab::Users) => self.switch_tab(Tab::Users),
            KeyCode::Char('6') if self.tab_visible(Tab::Roles) => self.switch_tab(Tab::Roles),
            KeyCode::Char('7') if self.tab_visible(Tab::Requests) => self.switch_tab(Tab::Requests),
            KeyCode::Char('8') if self.tab_visible(Tab::Tokens) => self.switch_tab(Tab::Tokens),
            KeyCode::Char('9') if self.tab_visible(Tab::Bots) => self.switch_tab(Tab::Bots),
            KeyCode::Char('0') if self.tab_visible(Tab::Inventory) => {
                self.switch_tab(Tab::Inventory);
            }
            // Token generation lives only on the Tokens tab.
            KeyCode::Char('g') if self.tab == Tab::Tokens => {
                self.mode = Mode::CreateToken;
                self.input.clear();
            }
            // Users tab: create a user (form) or reset the selected user.
            KeyCode::Char('n') if self.tab == Tab::Users => {
                self.add_user_form = AddUserForm::default();
                self.mode = Mode::AddUser;
            }
            KeyCode::Char('R') if self.tab == Tab::Users => {
                if let Some(name) = self.selected_user_name() {
                    self.mode = Mode::ConfirmUserReset(name);
                }
            }
            // Show this user's MFA devices (tsh, any logged-in user).
            KeyCode::Char('M') if self.profile.is_some() && self.caps.supports("mfa") => {
                self.status = Some("loading MFA devices…".to_owned());
                self.dispatch_aux(Job::Mfa);
            }
            // Show active sessions on the selected cluster (Enter to join one).
            KeyCode::Char('S') if self.profile.is_some() && self.caps.supports("sessions") => {
                if let Some(ctx) = self.topology.as_ref().map(|t| t.selected().clone()) {
                    self.status = Some("loading active sessions…".to_owned());
                    self.dispatch_aux(Job::Sessions(ctx));
                }
            }
            KeyCode::Char('L') => return self.login_action(),
            KeyCode::Char('p') => self.open_settings_form(),
            KeyCode::Char('O') => self.mode = Mode::ConfirmLogout,
            KeyCode::Char('?') => self.mode = Mode::Help,
            // Active background SSH forwards popup (stop them here).
            KeyCode::Char('F') => self.open_forwards(),
            KeyCode::Char('a') if self.tab == Tab::Requests => return self.review_selected(true),
            KeyCode::Char('d') if self.tab == Tab::Requests => return self.review_selected(false),
            KeyCode::Char('D') if self.tab == Tab::Requests => return self.drop_selected(),
            KeyCode::Char('n') if self.tab == Tab::Requests => {
                self.mode = Mode::CreateRequest;
                self.input.clear();
            }
            // Tokens tab: remove the selected token (`tctl tokens rm <name>`).
            KeyCode::Char('d') if self.tab == Tab::Tokens && self.selected_index().is_some() => {
                self.mode = Mode::ConfirmTokenRm;
            }
            // SCP file transfer for the selected SSH node (needs `tsh scp`).
            KeyCode::Char('s') if self.tab == Tab::Ssh && self.caps.supports("scp") => {
                self.open_scp_form();
            }
            // SSH options (forward / tunnel / one-off command) for the selected node.
            KeyCode::Char('o') if self.tab == Tab::Ssh => self.open_ssh_options_form(),
            // Background `tsh proxy db` tunnel for a GUI client (Db tab).
            KeyCode::Char('P') if self.tab == Tab::Db => return self.db_proxy_selected(),
            // Certificate lifecycle (`l` login / `u` logout) on Db and Apps.
            KeyCode::Char('l') if self.tab == Tab::Db => return self.db_login_selected(),
            KeyCode::Char('u') if self.tab == Tab::Db => return self.db_logout_selected(),
            KeyCode::Char('l') if self.tab == Tab::Apps => return self.app_login_selected(),
            KeyCode::Char('u') if self.tab == Tab::Apps => return self.app_logout_selected(),
            // `tsh kube exec` a command in a pod (Kube tab).
            KeyCode::Char('e') if self.tab == Tab::Kube => self.open_kube_exec_form(),
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(true),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(false),
            KeyCode::Char('r') => self.force_reload(),
            KeyCode::Char('/') => {
                self.mode = Mode::Search;
                self.input.clear();
            }
            KeyCode::Char('c') => {
                // The picker lists the topology; without it (clusters not loaded
                // yet, or `tsh clusters` failed — e.g. an expired session) there's
                // nothing to show, so give feedback instead of entering an empty,
                // invisible Picker mode.
                let Some(topo) = self.topology.as_ref() else {
                    self.status =
                        Some("clusters not loaded — press L to log in, or r to retry".to_owned());
                    return Outcome::Continue;
                };
                // Index 0 = "All clusters"; real clusters are offset by 1.
                let sel = if self.aggregate {
                    0
                } else {
                    topo.all()
                        .iter()
                        .position(|c| c == topo.selected())
                        .unwrap_or(0)
                        + 1
                };
                self.mode = Mode::Picker;
                self.picker.select(Some(sel));
            }
            KeyCode::Enter => return self.activate(),
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_search(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => {
                self.input.clear();
                self.mode = Mode::Normal;
                self.recompute_visible();
            }
            // Move the highlight through the filtered results without leaving
            // search — `j`/`k` can't be used here (they're search characters), so
            // the arrows drive navigation while the filter stays live.
            KeyCode::Down => self.move_selection(true),
            KeyCode::Up => self.move_selection(false),
            // Act on the highlighted result (connect / open / show). `activate`
            // transitions the mode out of search as the action proceeds.
            KeyCode::Enter => return self.activate(),
            KeyCode::Backspace => {
                self.input.pop();
                self.recompute_visible();
            }
            KeyCode::Char(c) => {
                self.input.push(c);
                self.recompute_visible();
            }
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_picker(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc | KeyCode::Char('c') => self.mode = Mode::Normal,
            KeyCode::Char('j') | KeyCode::Down => self.move_picker(true),
            KeyCode::Char('k') | KeyCode::Up => self.move_picker(false),
            KeyCode::Enter => self.confirm_picker(),
            _ => {}
        }
        Outcome::Continue
    }

    /// Apply a key to the shared `input` buffer for a single-line text prompt,
    /// reporting whether the user edited, submitted, or cancelled. `accept`
    /// filters which typed characters are inserted (e.g. digits-only for a port).
    fn text_key(&mut self, key: KeyEvent, accept: impl Fn(char) -> bool) -> TextEvent {
        match key.code {
            KeyCode::Esc => return TextEvent::Cancel,
            KeyCode::Enter => return TextEvent::Submit,
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(c) if accept(c) => self.input.push(c),
            _ => {}
        }
        TextEvent::Edited
    }

    fn on_key_login(&mut self, key: KeyEvent) -> Outcome {
        match self.text_key(key, |_| true) {
            TextEvent::Cancel => {
                self.input.clear();
                self.mode = Mode::Normal;
            }
            TextEvent::Submit => return self.start_ssh(),
            TextEvent::Edited => {}
        }
        Outcome::Continue
    }

    fn on_key_user_picker(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
            }
            KeyCode::Char('j') | KeyCode::Down => self.move_user_picker(true),
            KeyCode::Char('k') | KeyCode::Up => self.move_user_picker(false),
            KeyCode::Enter => {
                if let Some(user) = self
                    .user_picker
                    .selected()
                    .and_then(|i| self.user_choices.get(i).cloned())
                {
                    let Mode::UserPicker(pending) = std::mem::replace(&mut self.mode, Mode::Normal)
                    else {
                        return Outcome::Continue;
                    };
                    return self.connect_with_user(pending, &user);
                }
            }
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_proxy(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                // Dropping the proxy stops it (kills the child).
                let name = self.proxy.as_ref().map(|p| p.name.clone());
                self.proxy = None;
                self.mode = Mode::Normal;
                self.status = Some(match name {
                    Some(n) => format!("app proxy stopped ({n})"),
                    None => "app proxy stopped".to_owned(),
                });
            }
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_login_form(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => {
                self.relogin_root = None; // cancelled: no pending leaf re-login
                self.mode = Mode::Normal;
            }
            KeyCode::Enter => return self.submit_login(),
            KeyCode::Tab | KeyCode::Down => self.login_form.next_field(),
            KeyCode::BackTab | KeyCode::Up => self.login_form.prev_field(),
            // ←/→ cycle the focused dropdown (auth/mfa); no-op on text fields.
            KeyCode::Left => self.login_form.cycle(false),
            KeyCode::Right => self.login_form.cycle(true),
            KeyCode::Backspace => {
                if let Some(s) = self.login_form.text_mut() {
                    s.pop();
                }
            }
            KeyCode::Char(' ') if self.login_form.text_mut().is_none() => {
                self.login_form.cycle(true); // space also cycles a dropdown
            }
            KeyCode::Char(c) => {
                if let Some(s) = self.login_form.text_mut() {
                    s.push(c);
                }
            }
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_scp(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Enter => return self.submit_scp(),
            KeyCode::Tab | KeyCode::Down => self.scp_form.next_field(),
            KeyCode::BackTab | KeyCode::Up => self.scp_form.prev_field(),
            // ←/→ flip the focused toggle (direction/recursive); no-op on text.
            KeyCode::Left | KeyCode::Right => self.scp_form.toggle(),
            KeyCode::Backspace => {
                if let Some(s) = self.scp_form.text_mut() {
                    s.pop();
                }
            }
            KeyCode::Char(' ') if self.scp_form.text_mut().is_none() => {
                self.scp_form.toggle(); // space also flips a toggle row
            }
            KeyCode::Char(c) => {
                if let Some(s) = self.scp_form.text_mut() {
                    s.push(c);
                }
            }
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_forwards(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Down | KeyCode::Char('j') => self.move_forward_sel(true),
            KeyCode::Up | KeyCode::Char('k') => self.move_forward_sel(false),
            // Enter/d stop the highlighted forward (kills its child).
            KeyCode::Enter | KeyCode::Char('d') => self.stop_selected_forward(),
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_ssh_options(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Enter => return self.submit_ssh_options(),
            KeyCode::Tab | KeyCode::Down => self.ssh_options_form.next_field(),
            KeyCode::BackTab | KeyCode::Up => self.ssh_options_form.prev_field(),
            // ←/→ flip the tunnel-only toggle; no-op on the text rows.
            KeyCode::Left | KeyCode::Right => self.ssh_options_form.toggle(),
            KeyCode::Backspace => {
                if let Some(s) = self.ssh_options_form.text_mut() {
                    s.pop();
                }
            }
            KeyCode::Char(' ') if self.ssh_options_form.text_mut().is_none() => {
                self.ssh_options_form.toggle(); // space also flips the toggle row
            }
            KeyCode::Char(c) => {
                if let Some(s) = self.ssh_options_form.text_mut() {
                    s.push(c);
                }
            }
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_kube_exec(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
            }
            KeyCode::Enter => return self.submit_kube_exec(),
            KeyCode::Tab | KeyCode::Down => self.kube_exec_form.next_field(),
            KeyCode::BackTab | KeyCode::Up => self.kube_exec_form.prev_field(),
            KeyCode::Backspace => {
                if let Some(s) = self.kube_exec_form.text_mut() {
                    s.pop();
                }
            }
            KeyCode::Char(c) => {
                if let Some(s) = self.kube_exec_form.text_mut() {
                    s.push(c);
                }
            }
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_settings(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Enter => return self.submit_settings(),
            KeyCode::Tab | KeyCode::Down => self.settings_form.next_field(),
            KeyCode::BackTab | KeyCode::Up => self.settings_form.prev_field(),
            // ←/→ cycle the auth/mfa dropdowns; no-op on text rows.
            KeyCode::Left => self.settings_form.cycle(false),
            KeyCode::Right => self.settings_form.cycle(true),
            KeyCode::Backspace => {
                if let Some(s) = self.settings_form.text_mut() {
                    s.pop();
                }
            }
            KeyCode::Char(' ') if self.settings_form.text_mut().is_none() => {
                self.settings_form.cycle(true); // space also cycles a dropdown
            }
            KeyCode::Char(c) => {
                // The refresh row accepts digits only; other text rows take any char.
                let numeric = self.settings_form.numeric_field();
                if let Some(s) = self.settings_form.text_mut()
                    && (!numeric || c.is_ascii_digit())
                {
                    s.push(c);
                }
            }
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_db_user(&mut self, key: KeyEvent) -> Outcome {
        match self.text_key(key, |_| true) {
            TextEvent::Cancel => {
                self.input.clear();
                self.mode = Mode::Normal;
            }
            TextEvent::Submit => return self.connect_db(),
            TextEvent::Edited => {}
        }
        Outcome::Continue
    }

    fn on_key_app_port(&mut self, key: KeyEvent) -> Outcome {
        // Only digits make a valid port; ignore everything else.
        match self.text_key(key, |c| c.is_ascii_digit()) {
            TextEvent::Cancel => {
                self.input.clear();
                self.mode = Mode::Normal;
            }
            TextEvent::Submit => return self.connect_app(),
            TextEvent::Edited => {}
        }
        Outcome::Continue
    }

    fn on_key_tool_picker(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
            }
            KeyCode::Char('j') | KeyCode::Down => self.move_tool_picker(true),
            KeyCode::Char('k') | KeyCode::Up => self.move_tool_picker(false),
            KeyCode::Enter => {
                let tool = self
                    .tool_picker
                    .selected()
                    .and_then(|i| self.tool_choices.get(i).cloned());
                if let Some(tool) = tool {
                    let Mode::ToolPicker {
                        cluster,
                        name,
                        user,
                    } = std::mem::replace(&mut self.mode, Mode::Normal)
                    else {
                        return Outcome::Continue;
                    };
                    return Self::launch_kube(&cluster, &name, user.as_deref(), &tool);
                }
            }
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_create(&mut self, key: KeyEvent) -> Outcome {
        match self.text_key(key, |_| true) {
            TextEvent::Cancel => {
                self.input.clear();
                self.mode = Mode::Normal;
            }
            TextEvent::Submit => return self.create_request(),
            TextEvent::Edited => {}
        }
        Outcome::Continue
    }

    fn on_key_confirm_logout(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y' | 'Y') => return self.logout(),
            _ => self.mode = Mode::Normal,
        }
        Outcome::Continue
    }

    fn on_key_confirm_token_rm(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y' | 'Y') => self.confirm_token_rm(),
            _ => self.mode = Mode::Normal,
        }
        Outcome::Continue
    }

    /// Dispatch removal of the selected token. The secret value is read from the
    /// zeroizing store only for this call (and the resulting argv); it is never
    /// logged. A leading `-` is rejected as a defensive argument-injection guard.
    fn confirm_token_rm(&mut self) {
        self.mode = Mode::Normal;
        let Some(name) = self
            .selected_index()
            .and_then(|i| self.tokens.get(i))
            .map(|t| t.name.clone())
        else {
            return;
        };
        if name.is_empty() || name.starts_with('-') {
            self.report(&DomainError::InvalidValue { field: "token" });
            return;
        }
        self.status = Some("removing token…".to_owned());
        self.dispatch_aux(Job::RemoveToken(name));
    }

    fn on_key_token(&mut self, key: KeyEvent) -> Outcome {
        match self.text_key(key, |_| true) {
            TextEvent::Cancel => {
                self.input.clear();
                self.mode = Mode::Normal;
            }
            TextEvent::Submit => self.generate_token(),
            TextEvent::Edited => {}
        }
        Outcome::Continue
    }

    /// Name of the selected user on the Users tab (for `tctl users reset`).
    fn selected_user_name(&self) -> Option<String> {
        self.selected_index()
            .and_then(|i| self.users.get(i))
            .map(|u| u.name.to_string())
    }

    fn on_key_add_user(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Enter => return self.submit_add_user(),
            KeyCode::Tab | KeyCode::Down => self.add_user_form.next_field(),
            KeyCode::BackTab | KeyCode::Up => self.add_user_form.prev_field(),
            KeyCode::Backspace => {
                if let Some(s) = self.add_user_form.text_mut() {
                    s.pop();
                }
            }
            KeyCode::Char(c) => {
                if let Some(s) = self.add_user_form.text_mut() {
                    s.push(c);
                }
            }
            _ => {}
        }
        Outcome::Continue
    }

    /// Validate and dispatch `tctl users add`. The invite URL returns via
    /// [`JobResult::Invite`] and is shown in a one-time popup.
    fn submit_add_user(&mut self) -> Outcome {
        let f = self.add_user_form.clone();
        let user = f.username.trim();
        let roles = f.roles.trim();
        if !valid_user(user) {
            self.report(&DomainError::InvalidValue { field: "user" });
            return Outcome::Continue;
        }
        if !valid_roles(roles) {
            self.report(&DomainError::InvalidValue { field: "roles" });
            return Outcome::Continue;
        }
        self.mode = Mode::Normal;
        self.status = Some(format!("creating user {user}…"));
        self.dispatch_aux(Job::AddUser {
            user: user.to_owned(),
            roles: roles.to_owned(),
        });
        Outcome::Continue
    }

    fn on_key_confirm_user_reset(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y' | 'Y') => self.confirm_user_reset(),
            _ => {
                self.mode = Mode::Normal;
            }
        }
        Outcome::Continue
    }

    fn confirm_user_reset(&mut self) {
        let Mode::ConfirmUserReset(user) = std::mem::replace(&mut self.mode, Mode::Normal) else {
            return;
        };
        if !valid_user(&user) {
            self.report(&DomainError::InvalidValue { field: "user" });
            return;
        }
        self.status = Some(format!("resetting {user}…"));
        self.dispatch_aux(Job::ResetUser(user));
    }

    /// MFA-devices popup: navigate, register a new device, or remove one.
    fn on_key_mfa(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.mfa_devices.clear();
                self.mode = Mode::Normal;
            }
            KeyCode::Down | KeyCode::Char('j') if !self.mfa_devices.is_empty() => {
                self.mfa_sel = clamp_step(self.mfa_sel, self.mfa_devices.len(), true);
            }
            KeyCode::Up | KeyCode::Char('k') if !self.mfa_devices.is_empty() => {
                self.mfa_sel = clamp_step(self.mfa_sel, self.mfa_devices.len(), false);
            }
            // Register a new device — interactive (tsh drives the authenticator).
            KeyCode::Char('a') => {
                self.mfa_devices.clear();
                self.mode = Mode::Normal;
                return Outcome::Run {
                    label: "Adding an MFA device (follow tsh's prompts)…".to_owned(),
                    args: cmd::mfa_add(),
                };
            }
            // Remove the selected device (confirm first).
            KeyCode::Char('d') => {
                if let Some(name) = self.mfa_devices.get(self.mfa_sel).map(|d| d.name.clone()) {
                    self.mode = Mode::ConfirmMfaRm(name);
                }
            }
            _ => {}
        }
        Outcome::Continue
    }

    fn on_key_confirm_mfa_rm(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y' | 'Y') => return self.confirm_mfa_rm(),
            // Cancel → back to the device list.
            _ => {
                self.mode = Mode::ShowMfa;
            }
        }
        Outcome::Continue
    }

    fn confirm_mfa_rm(&mut self) -> Outcome {
        self.mfa_devices.clear();
        let Mode::ConfirmMfaRm(name) = std::mem::replace(&mut self.mode, Mode::Normal) else {
            return Outcome::Continue;
        };
        if name.is_empty() || name.starts_with('-') {
            self.report(&DomainError::InvalidValue {
                field: "mfa_device",
            });
            return Outcome::Continue;
        }
        Outcome::Run {
            label: format!("Removing MFA device {name}…"),
            args: cmd::mfa_rm(&name),
        }
    }

    /// Active-sessions popup: navigate, or join the selected session.
    fn on_key_sessions(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.sessions.clear();
                self.mode = Mode::Normal;
            }
            KeyCode::Down | KeyCode::Char('j') if !self.sessions.is_empty() => {
                self.sessions_sel = clamp_step(self.sessions_sel, self.sessions.len(), true);
            }
            KeyCode::Up | KeyCode::Char('k') if !self.sessions.is_empty() => {
                self.sessions_sel = clamp_step(self.sessions_sel, self.sessions.len(), false);
            }
            KeyCode::Enter => {
                if let Some(id) = self
                    .sessions
                    .get(self.sessions_sel)
                    .map(|s| s.id.clone())
                    .filter(|s| !s.is_empty() && !s.starts_with('-'))
                {
                    self.sessions.clear();
                    self.mode = Mode::Normal;
                    return Outcome::Run {
                        label: format!("Joining session {id}…"),
                        args: cmd::join(&id),
                    };
                }
            }
            _ => {}
        }
        Outcome::Continue
    }
}
