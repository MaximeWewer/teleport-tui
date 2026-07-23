//! User actions: opening/submitting the modal forms, and turning a selection
//! into an interactive `tsh` command or a background proxy (`Outcome`). A child
//! `impl super::App`.
//!
//! Split out of `app`; model types and imports arrive via `super::*`.

#[allow(clippy::wildcard_imports)]
use super::*;

impl App {
    /// Open the login form, pre-filling proxy/user from the current profile (if
    /// any) or the configured defaults.
    fn open_login_form(&mut self) {
        let proxy = self
            .profile
            .as_ref()
            .map(|p| p.cluster.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| self.login_proxy.clone())
            .unwrap_or_default();
        self.open_login_form_proxy(proxy);
    }

    /// Open the login form seeded with a specific `proxy` (user/auth/mfa still
    /// come from the profile / persisted defaults).
    fn open_login_form_proxy(&mut self, proxy: String) {
        let user = self
            .profile
            .as_ref()
            .map(|p| p.username.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| self.login_user.clone())
            .unwrap_or_default();
        // Seed the dropdowns from the persisted defaults (blank → first slot).
        let auth = opt_index(AUTH_OPTIONS, self.login_auth.as_deref().unwrap_or(""));
        let mfa = opt_index(MFA_OPTIONS, self.login_mfa.as_deref().unwrap_or(""));
        self.login_form = LoginForm {
            proxy,
            user,
            auth,
            mfa,
            field: 0,
        };
        self.mode = Mode::LoginForm;
    }

    /// `L`: open the login **form**. In the all-clusters admin view, if the
    /// highlighted row is a cluster with no live session, the form is pre-filled
    /// with *that* cluster's proxy so submitting logs into it (and its admin
    /// objects join the aggregate). Otherwise it's the normal login form.
    pub(super) fn login_action(&mut self) -> Outcome {
        if let Some(proxy) = self.pending_login_cluster() {
            // Remember the root to restore after this leaf login (consumed in
            // submit_login); the aggregate re-fans once the leaf is reachable.
            self.relogin_root = self.topology.as_ref().map(|t| t.root().name.to_string());
            self.open_login_form_proxy(proxy);
        } else {
            self.relogin_root = None;
            self.open_login_form();
        }
        Outcome::Continue
    }

    /// The proxy of the highlighted serial-aggregate row, but only when that row
    /// is a `login_required` placeholder (so `L` knows to target it).
    fn pending_login_cluster(&self) -> Option<String> {
        if !(self.aggregate && self.tab.serial_aggregation()) {
            return None;
        }
        let idx = self.selected_index()?;
        let row = self.agg_rows.get(idx)?;
        row.login_required.then(|| row.cluster.clone())
    }

    /// Open the Settings screen, pre-filled from the live persisted defaults.
    pub(super) fn open_settings_form(&mut self) {
        self.settings_form = SettingsForm {
            ssh_login: self.default_login.clone().unwrap_or_default(),
            kube_user: self.default_kube_user.clone().unwrap_or_default(),
            db_user: self.default_db_user.clone().unwrap_or_default(),
            proxy: self.login_proxy.clone().unwrap_or_default(),
            user: self.login_user.clone().unwrap_or_default(),
            auth: opt_index(AUTH_OPTIONS, self.login_auth.as_deref().unwrap_or("")),
            mfa: opt_index(MFA_OPTIONS, self.login_mfa.as_deref().unwrap_or("")),
            refresh: self
                .refresh_seconds
                .map(|n| n.to_string())
                .unwrap_or_default(),
            kube_tools: self.kube_tools.join(", "),
            field: 0,
        };
        self.mode = Mode::Settings;
    }

    /// Validate, apply to the live state, and persist the Settings form to
    /// `config.toml`. Text fields reuse the strict login/path validators.
    pub(super) fn submit_settings(&mut self) -> Outcome {
        let f = self.settings_form.clone();
        for value in [&f.ssh_login, &f.kube_user, &f.db_user, &f.proxy, &f.user] {
            if !value.is_empty() && !valid_user(value) {
                self.report(&DomainError::InvalidValue { field: "settings" });
                return Outcome::Continue;
            }
        }
        // Helper: empty string → None (key omitted from the file).
        let opt = |s: &str| (!s.trim().is_empty()).then(|| s.trim().to_owned());
        self.default_login = opt(&f.ssh_login);
        self.default_kube_user = opt(&f.kube_user);
        self.default_db_user = opt(&f.db_user);
        self.login_proxy = opt(&f.proxy);
        self.login_user = opt(&f.user);
        self.login_auth = opt(f.auth_str());
        self.login_mfa = opt(f.mfa_str());
        self.refresh_seconds = f.refresh.trim().parse::<u64>().ok().filter(|n| *n > 0);
        let tools: Vec<String> = f
            .kube_tools
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        if !tools.is_empty() {
            self.kube_tools = tools;
        }
        self.mode = Mode::Normal;
        self.persist_settings();
        Outcome::Continue
    }

    /// Write the live defaults back to `config.toml`, preserving keys we don't
    /// edit (e.g. `tsh_path`) by re-reading the file first.
    fn persist_settings(&mut self) {
        let mut cfg = InfraConfig::load(&self.config_path);
        cfg.proxy.clone_from(&self.login_proxy);
        cfg.user.clone_from(&self.login_user);
        cfg.auth.clone_from(&self.login_auth);
        cfg.mfa.clone_from(&self.login_mfa);
        cfg.default_login.clone_from(&self.default_login);
        cfg.kube_user.clone_from(&self.default_kube_user);
        cfg.db_user.clone_from(&self.default_db_user);
        cfg.refresh_seconds = self.refresh_seconds;
        cfg.kube_tools.clone_from(&self.kube_tools);
        if let Err(e) = cfg.save(&self.config_path) {
            self.status = Some(format!("[CONFIG_SAVE_FAILED] {e}"));
        } else {
            self.status = Some(format!("settings saved → {}", self.config_path.display()));
        }
    }

    /// Build `tsh login` from the form and hand off to the terminal. `tsh`
    /// prompts for the password and MFA itself (browser/OTP) — never the TUI.
    pub(super) fn submit_login(&mut self) -> Outcome {
        let f = self.login_form.clone();
        // Only the free-text fields can carry bad input; auth/mfa come from
        // fixed dropdowns and are always valid.
        for value in [&f.proxy, &f.user] {
            if !value.is_empty() && !valid_user(value) {
                self.report(&DomainError::InvalidValue { field: "login" });
                return Outcome::Continue;
            }
        }
        self.mode = Mode::Normal;
        self.last_was_auth = true;
        // A leaf re-login (from `L` on a login-required row): restore root before
        // the post-login refetch, and drop the just-logged-in cluster's cached
        // slices (all tabs) so it re-fetches with real data instead of the stale
        // login-required placeholder. Other clusters keep their cache.
        if let Some(root) = self.relogin_root.take() {
            self.pending_root_restore = Some(root);
            let proxy = f.proxy.clone();
            self.agg_cache.retain(|(_, cluster), _| cluster != &proxy);
        }
        let auth = f.auth_str();
        let mfa = f.mfa_str();
        let args = cmd::login(&f.proxy, &f.user, auth, mfa);
        let target = if f.proxy.is_empty() {
            "Teleport".to_owned()
        } else {
            f.proxy.clone()
        };
        // `local` is the only flow where tsh prompts for a typed password; the
        // others (sso/passwordless) drive the browser, TPM, or a security key.
        let hint = if auth == "local" || auth.is_empty() {
            " (tsh will prompt for password/MFA in the terminal)"
        } else {
            ""
        };
        Outcome::Run {
            label: format!("Logging in to {target}…{hint}"),
            args,
        }
    }

    /// Open the `tsh scp` form for the selected SSH node, capturing its host and
    /// the active cluster. No-op if no node is selected. Login defaults to the
    /// first profile login (blank = the node's default SSH user).
    pub(super) fn open_scp_form(&mut self) {
        if self.tab != Tab::Ssh {
            return;
        }
        let Some(idx) = self.selected_index() else {
            return;
        };
        // Resolve (cluster, host) from the aggregate row or the scoped node list,
        // so scp targets the node's own cluster even in all-clusters mode.
        let resolved = if self.aggregate {
            self.agg_rows.get(idx).and_then(|r| {
                r.cells
                    .first()
                    .map(|host| (r.cluster.clone(), host.clone()))
            })
        } else {
            self.cluster_arg()
                .zip(self.nodes.get(idx).map(|n| n.hostname.to_string()))
        };
        let Some((cluster, host)) = resolved else {
            return;
        };
        let login = self.profile_logins().into_iter().next().unwrap_or_default();
        self.scp_form = ScpForm {
            host,
            cluster,
            download: true,
            login,
            ..ScpForm::default()
        };
        self.mode = Mode::Scp;
    }

    /// Open the `tsh ssh` options form for the highlighted SSH node, capturing its
    /// (cluster, host) and pre-filling the first known login. No-op off the SSH tab
    /// or with nothing selected.
    pub(super) fn open_ssh_options_form(&mut self) {
        if self.tab != Tab::Ssh {
            return;
        }
        let Some(idx) = self.selected_index() else {
            return;
        };
        // Resolve (cluster, host) from the aggregate row or the scoped node list,
        // so the connection targets the node's own cluster even in all-clusters mode.
        let resolved = if self.aggregate {
            self.agg_rows.get(idx).and_then(|r| {
                r.cells
                    .first()
                    .map(|host| (r.cluster.clone(), host.clone()))
            })
        } else {
            self.cluster_arg()
                .zip(self.nodes.get(idx).map(|n| n.hostname.to_string()))
        };
        let Some((cluster, host)) = resolved else {
            return;
        };
        let login = self.profile_logins().into_iter().next().unwrap_or_default();
        self.ssh_options_form = SshOptionsForm {
            host,
            cluster,
            login,
            ..SshOptionsForm::default()
        };
        self.mode = Mode::SshOptions;
    }

    /// Validate the SSH options form and hand off `tsh ssh` with the chosen extras
    /// (a `-L` forward, `-N` tunnel-only, and/or a one-off command). A blank form
    /// is just a normal connect.
    pub(super) fn submit_ssh_options(&mut self) -> Outcome {
        let f = self.ssh_options_form.clone();
        if !f.login.is_empty() && !valid_user(&f.login) {
            self.report(&DomainError::InvalidValue { field: "ssh_login" });
            return Outcome::Continue;
        }
        if !f.forward.is_empty() && !valid_forward(&f.forward) {
            self.report(&DomainError::InvalidValue {
                field: "ssh_forward",
            });
            return Outcome::Continue;
        }
        if !f.command.is_empty() && !valid_command(&f.command) {
            self.report(&DomainError::InvalidValue {
                field: "ssh_command",
            });
            return Outcome::Continue;
        }
        self.mode = Mode::Normal;
        // A pure tunnel (`-N`, no shell) runs in the BACKGROUND so the TUI stays up
        // and it joins the forwards list; everything else hands over the terminal.
        if f.tunnel_only && !f.forward.is_empty() && f.command.is_empty() {
            return Outcome::OpenForward {
                cluster: f.cluster.clone(),
                user: f.login.clone(),
                host: f.host.clone(),
                spec: f.forward.clone(),
                label: format!("Starting forward {} · {}…", f.forward, f.host),
            };
        }
        let args = cmd::ssh_full(&f.cluster, &f.login, &f.host, &f.forward, false, &f.command);
        // A one-off command finishes on its own → pause on its output (RunCommand);
        // a plain connect opens an interactive shell the user ends themselves (Run).
        if f.command.is_empty() {
            Outcome::Run {
                label: format!("Connecting to {}  ({})…", f.host, f.cluster),
                args,
            }
        } else {
            Outcome::RunCommand {
                label: format!("Running on {}  ({})…", f.host, f.cluster),
                args,
            }
        }
    }

    /// Build `tsh scp [-c cluster] [-r] <from> <to>` from the form and hand off
    /// to the terminal (tsh shows progress and may prompt for MFA there).
    pub(super) fn submit_scp(&mut self) -> Outcome {
        let f = self.scp_form.clone();
        if !f.login.is_empty() && !valid_user(&f.login) {
            self.report(&DomainError::InvalidValue { field: "scp_login" });
            return Outcome::Continue;
        }
        if !valid_path(&f.remote) || !valid_path(&f.local) {
            self.report(&DomainError::InvalidValue { field: "scp_path" });
            return Outcome::Continue;
        }
        self.mode = Mode::Normal;
        let args = cmd::scp(
            &f.cluster,
            &f.login,
            &f.host,
            &f.remote,
            &f.local,
            f.download,
            f.recursive,
        );
        let verb = if f.download {
            "Copying from"
        } else {
            "Sending to"
        };
        Outcome::Run {
            label: format!("{verb} {}  ({})…", f.host, f.cluster),
            args,
        }
    }

    /// Open the `tsh kube exec` form for the highlighted Kubernetes cluster,
    /// capturing its (teleport-cluster, kube-cluster) pair. No-op off the Kube
    /// tab or with nothing selected.
    pub(super) fn open_kube_exec_form(&mut self) {
        let Some((cluster, kube)) = self.resource_target() else {
            return;
        };
        self.kube_exec_form = KubeExecForm::default();
        self.mode = Mode::KubeExec { cluster, kube };
    }

    /// Validate the kube-exec form and emit the two-step exec. The command is
    /// split on whitespace into argv tokens (no shell, so no quoting/pipes); the
    /// pod/container/namespace reuse the strict identifier check.
    pub(super) fn submit_kube_exec(&mut self) -> Outcome {
        let Mode::KubeExec { cluster, kube } = self.mode.clone() else {
            self.mode = Mode::Normal;
            return Outcome::Continue;
        };
        let f = self.kube_exec_form.clone();
        let pod = f.pod.trim();
        if !valid_user(pod) {
            self.report(&DomainError::InvalidValue { field: "kube_pod" });
            return Outcome::Continue;
        }
        let command: Vec<String> = f.command.split_whitespace().map(str::to_owned).collect();
        if command.is_empty() {
            self.report(&DomainError::InvalidValue {
                field: "kube_command",
            });
            return Outcome::Continue;
        }
        let container = f.container.trim();
        let namespace = f.namespace.trim();
        if (!container.is_empty() && !valid_user(container))
            || (!namespace.is_empty() && !valid_user(namespace))
        {
            self.report(&DomainError::InvalidValue { field: "kube_exec" });
            return Outcome::Continue;
        }
        self.mode = Mode::Normal;
        let exec = cmd::kube_exec(pod, &command, container, namespace);
        Outcome::KubeExec {
            cluster,
            kube: kube.clone(),
            exec,
            label: format!("exec in {pod} on {kube}…"),
        }
    }

    pub(super) fn logout(&mut self) -> Outcome {
        self.last_was_auth = true;
        self.mode = Mode::Normal;
        Outcome::Run {
            args: cmd::logout(),
            label: "Logging out…".to_owned(),
        }
    }

    fn cluster_arg(&self) -> Option<String> {
        self.topology
            .as_ref()
            .map(|t| t.selected().name.to_string())
    }

    pub(super) fn activate(&mut self) -> Outcome {
        let Some(idx) = self.selected_index() else {
            return Outcome::Continue;
        };
        // Recordings: Enter replays the selected session (`tsh play <sid>`).
        // Recordings never aggregates (no cluster flag), so the scoped list is
        // always the source — even in all-clusters mode.
        if self.tab == Tab::Recordings {
            // The sid comes from the aggregate row in all-clusters mode (recorded
            // on the row, not a visible column) or the scoped list otherwise.
            let sid = if self.aggregate {
                self.agg_rows.get(idx).and_then(|r| r.sid.clone())
            } else {
                self.recordings.get(idx).map(|r| r.sid.clone())
            };
            let Some(sid) = sid.filter(|s| !s.is_empty() && !s.starts_with('-')) else {
                return Outcome::Continue;
            };
            return Outcome::PlayRecording {
                label: format!("Replaying session {sid}…"),
                args: cmd::play(&sid),
            };
        }
        // Admin (tctl) tabs are read-only — Enter opens a full-field detail popup
        // for the selected row instead of a connect action.
        if self.tab.is_admin() {
            return self.show_detail(idx);
        }
        // Source (cluster, name) from the aggregate row (connect directly even in
        // all-clusters mode) or from the scoped vec + selected cluster.
        let resolved = if self.aggregate && !self.tab.is_admin() {
            self.agg_target(idx)
        } else {
            let cluster = self.cluster_arg();
            let name = match self.tab {
                Tab::Ssh => self.nodes.get(idx).map(|n| n.hostname.to_string()),
                Tab::Kube => self.kube.get(idx).map(|k| k.name.to_string()),
                Tab::Db => self.dbs.get(idx).map(|d| d.name.to_string()),
                Tab::Apps => self.apps.get(idx).map(|a| a.name.to_string()),
                Tab::Requests => self.requests.get(idx).map(|r| r.id.to_string()),
                Tab::Users
                | Tab::Roles
                | Tab::Tokens
                | Tab::Bots
                | Tab::Inventory
                | Tab::Recordings => {
                    return Outcome::Continue; // read-only / handled above
                }
            };
            cluster.zip(name)
        };
        let Some((cluster, name)) = resolved else {
            return Outcome::Continue;
        };
        self.connect_resource(cluster, name)
    }

    /// Open the read-only detail popup for the selected admin row: every field,
    /// untruncated. In all-clusters mode only the display cells survive, so they
    /// are labelled by column header + cluster; otherwise the typed resource's
    /// [`Resource::details`] is used (surfaces fields the table omits).
    fn show_detail(&mut self, idx: usize) -> Outcome {
        let title = format!("{} detail", self.tab.title());
        let rows = if self.aggregating() {
            let Some(r) = self.agg_rows.get(idx) else {
                return Outcome::Continue;
            };
            let mut rows = vec![("CLUSTER".to_owned(), vec![r.cluster.clone()])];
            rows.extend(
                tab_columns(self.tab)
                    .iter()
                    .zip(&r.cells)
                    .map(|(c, v)| ((*c).to_owned(), vec![v.clone()])),
            );
            rows
        } else {
            let rows = match self.tab {
                Tab::Users => self.users.get(idx).map(Resource::details),
                Tab::Roles => self.roles.get(idx).map(Resource::details),
                Tab::Tokens => self.tokens.get(idx).map(Resource::details),
                Tab::Bots => self.bots.get(idx).map(Resource::details),
                Tab::Inventory => self.instances.get(idx).map(Resource::details),
                _ => None,
            };
            let Some(rows) = rows else {
                return Outcome::Continue;
            };
            rows
        };
        self.mode = Mode::ShowDetail {
            title,
            rows,
            scroll: 0,
        };
        Outcome::Continue
    }

    /// Start the tab's connect action for `name` on `cluster`. Works the same in
    /// scoped and all-clusters views.
    fn connect_resource(&mut self, cluster: String, name: String) -> Outcome {
        match self.tab {
            Tab::Ssh => {
                // A configured default login connects directly (no picker).
                if let Some(login) = self.default_login.clone().filter(|l| valid_user(l)) {
                    return self.connect_with_user(
                        PendingConnect::Ssh {
                            cluster,
                            host: name,
                        },
                        &login,
                    );
                }
                let users = self.profile_logins();
                self.offer_connect(
                    PendingConnect::Ssh {
                        cluster,
                        host: name,
                    },
                    users,
                )
            }
            Tab::Kube => {
                // A configured default kube user skips the picker (→ tool choice).
                if let Some(user) = self.default_kube_user.clone().filter(|u| valid_user(u)) {
                    return self.offer_kube_tool(cluster, name, Some(user));
                }
                let users = self.profile_kube_users();
                self.offer_connect(PendingConnect::Kube { cluster, name }, users)
            }
            Tab::Db => {
                // A configured default db user connects directly; else prompt.
                if let Some(user) = self.default_db_user.clone().filter(|u| valid_user(u)) {
                    return Outcome::Run {
                        label: format!("Connecting to database {name} as {user}…"),
                        args: cmd::db_connect(&cluster, &name, &user),
                    };
                }
                self.input.clear();
                self.mode = Mode::DbUser { cluster, name };
                Outcome::Continue
            }
            Tab::Apps => {
                // Prompt for a local proxy port (blank = random free port).
                self.input.clear();
                self.mode = Mode::AppPort { cluster, name };
                Outcome::Continue
            }
            Tab::Requests => Outcome::Run {
                label: format!("Showing access request {name}…"),
                args: cmd::request_show(&cluster, &name),
            },
            Tab::Users
            | Tab::Roles
            | Tab::Tokens
            | Tab::Bots
            | Tab::Inventory
            | Tab::Recordings => Outcome::Continue,
        }
    }

    fn profile_logins(&self) -> Vec<String> {
        self.profile
            .as_ref()
            .map(|p| p.logins.clone())
            .unwrap_or_default()
    }

    fn profile_kube_users(&self) -> Vec<String> {
        self.profile
            .as_ref()
            .map(|p| p.kubernetes_users.clone())
            .unwrap_or_default()
    }

    /// Decide how to obtain the user for a pending connection:
    /// one candidate → connect directly; several → dropdown; none → fall back
    /// (free-text login for SSH, no `--as` for kube).
    fn offer_connect(&mut self, pending: PendingConnect, users: Vec<String>) -> Outcome {
        let is_ssh = matches!(pending, PendingConnect::Ssh { .. });
        let users: Vec<String> = users.into_iter().filter(|u| valid_user(u)).collect();
        match users.len() {
            0 if is_ssh => {
                // No known logins: ask for one (the pending connection rides along).
                self.input.clear();
                self.mode = Mode::Login(pending);
                Outcome::Continue
            }
            0 => self.connect_no_user(pending),
            1 => users
                .first()
                .map_or(Outcome::Continue, |u| self.connect_with_user(pending, u)),
            _ => {
                self.user_choices = users;
                self.user_picker.select(Some(0));
                self.mode = Mode::UserPicker(pending);
                Outcome::Continue
            }
        }
    }

    pub(super) fn connect_with_user(&mut self, pending: PendingConnect, user: &str) -> Outcome {
        if !valid_user(user) {
            self.report(&DomainError::InvalidValue { field: "user" });
            return Outcome::Continue;
        }
        match pending {
            PendingConnect::Ssh { cluster, host } => {
                self.mode = Mode::Normal;
                Outcome::Run {
                    label: format!("Connecting to {user}@{host}  ({cluster})…"),
                    args: cmd::ssh(&cluster, user, &host),
                }
            }
            // Kubernetes: pick a launcher tool next (auto-proxy).
            PendingConnect::Kube { cluster, name } => {
                self.offer_kube_tool(cluster, name, Some(user.to_owned()))
            }
        }
    }

    fn connect_no_user(&mut self, pending: PendingConnect) -> Outcome {
        match pending {
            PendingConnect::Kube { cluster, name } => self.offer_kube_tool(cluster, name, None),
            PendingConnect::Ssh { .. } => {
                self.mode = Mode::Normal;
                Outcome::Continue
            }
        }
    }

    /// Offer the configured Kubernetes launchers: one tool → open directly;
    /// several → dropdown.
    fn offer_kube_tool(&mut self, cluster: String, name: String, user: Option<String>) -> Outcome {
        let tools = if self.kube_tools.is_empty() {
            vec!["shell".to_owned()]
        } else {
            self.kube_tools.clone()
        };
        if let [tool] = tools.as_slice() {
            self.mode = Mode::Normal;
            return Self::launch_kube(&cluster, &name, user.as_deref(), tool);
        }
        self.tool_choices = tools;
        self.tool_picker.select(Some(0));
        self.mode = Mode::ToolPicker {
            cluster,
            name,
            user,
        };
        Outcome::Continue
    }

    /// Hand off to the event loop to start a background `tsh proxy kube` and
    /// open the chosen tool with `$KUBECONFIG` set. Done outside `--exec` so the
    /// proxy stays silent and the handed-over shell terminal isn't corrupted.
    pub(super) fn launch_kube(
        cluster: &str,
        name: &str,
        user: Option<&str>,
        tool: &str,
    ) -> Outcome {
        Outcome::OpenKube {
            kube: name.to_owned(),
            cluster: cluster.to_owned(),
            user: user.map(ToOwned::to_owned),
            tool: tool.to_owned(),
        }
    }

    /// Build `tsh db connect <name> -c <cluster> [--db-user=<user>]` from the
    /// typed db user (blank = let tsh choose the default user).
    pub(super) fn connect_db(&mut self) -> Outcome {
        let Mode::DbUser { cluster, name } = std::mem::replace(&mut self.mode, Mode::Normal) else {
            return Outcome::Continue;
        };
        let user = self.input.trim().to_owned();
        self.input.clear();
        if user.is_empty() {
            return Outcome::Run {
                label: format!("Connecting to database {name}…"),
                args: cmd::db_connect(&cluster, &name, ""),
            };
        }
        if !valid_user(&user) {
            self.report(&DomainError::InvalidValue { field: "db_user" });
            return Outcome::Continue;
        }
        Outcome::Run {
            label: format!("Connecting to database {name} as {user}…"),
            args: cmd::db_connect(&cluster, &name, &user),
        }
    }

    /// Start a background `tsh proxy db` tunnel for the selected database, so a
    /// GUI client can connect to a local endpoint. Resolves (cluster, name) from
    /// the aggregate row or the scoped list, like the connect action.
    pub(super) fn db_proxy_selected(&mut self) -> Outcome {
        if self.tab != Tab::Db {
            return Outcome::Continue;
        }
        let Some(idx) = self.selected_index() else {
            return Outcome::Continue;
        };
        let resolved = if self.aggregate {
            self.agg_target(idx)
        } else {
            self.cluster_arg()
                .zip(self.dbs.get(idx).map(|d| d.name.to_string()))
        };
        let Some((cluster, name)) = resolved else {
            return Outcome::Continue;
        };
        self.status = Some(format!("starting db proxy for {name}…"));
        Outcome::OpenDbProxy { name, cluster }
    }

    /// `(cluster, name)` from an aggregate row's first cell, **validated as safe
    /// argv positionals**. In all-clusters mode these are reconstructed from
    /// display cells rather than the domain newtypes that produced them, so
    /// re-apply the empty / leading-`-` guard (argument-injection) the newtypes
    /// enforce before the values can reach a `tsh`/`tctl` argument slot.
    fn agg_target(&self, idx: usize) -> Option<(String, String)> {
        let r = self.agg_rows.get(idx)?;
        let name = r.cells.first()?;
        if r.cluster.is_empty()
            || name.is_empty()
            || r.cluster.starts_with('-')
            || name.starts_with('-')
        {
            return None;
        }
        Some((r.cluster.clone(), name.clone()))
    }

    /// (cluster, name) of the highlighted Db/Apps row — from the aggregate row in
    /// all-clusters mode, else the scoped vec + selected cluster. Used by the
    /// cert-lifecycle actions (`l`/`u`), which are gated to those tabs.
    fn resource_target(&self) -> Option<(String, String)> {
        let idx = self.selected_index()?;
        if self.aggregating() {
            return self.agg_target(idx);
        }
        let cluster = self.cluster_arg()?;
        let name = match self.tab {
            Tab::Db => self.dbs.get(idx).map(|d| d.name.to_string())?,
            Tab::Apps => self.apps.get(idx).map(|a| a.name.to_string())?,
            Tab::Kube => self.kube.get(idx).map(|k| k.name.to_string())?,
            _ => return None,
        };
        Some((cluster, name))
    }

    /// `l` on Db: `tsh db login` to retrieve the selected database's certificate
    /// (no shell; creds land in `~/.tsh`). A configured default db-user is passed.
    pub(super) fn db_login_selected(&mut self) -> Outcome {
        let Some((cluster, name)) = self.resource_target() else {
            return Outcome::Continue;
        };
        let db_user = self
            .default_db_user
            .clone()
            .filter(|u| valid_user(u))
            .unwrap_or_default();
        Outcome::Run {
            label: format!("Logging in to database {name}…"),
            args: cmd::db_login(&cluster, &name, &db_user),
        }
    }

    /// `u` on Db: `tsh db logout` to remove the selected database's credentials.
    pub(super) fn db_logout_selected(&mut self) -> Outcome {
        let Some((cluster, name)) = self.resource_target() else {
            return Outcome::Continue;
        };
        Outcome::Run {
            label: format!("Removing credentials for database {name}…"),
            args: cmd::db_logout(&cluster, &name),
        }
    }

    /// `l` on Apps: `tsh apps login` to retrieve the selected app's certificate.
    pub(super) fn app_login_selected(&mut self) -> Outcome {
        let Some((cluster, name)) = self.resource_target() else {
            return Outcome::Continue;
        };
        Outcome::Run {
            label: format!("Retrieving certificate for app {name}…"),
            args: cmd::app_login(&cluster, &name),
        }
    }

    /// `u` on Apps: `tsh apps logout` to remove the selected app's certificate.
    pub(super) fn app_logout_selected(&mut self) -> Outcome {
        let Some((cluster, name)) = self.resource_target() else {
            return Outcome::Continue;
        };
        Outcome::Run {
            label: format!("Removing certificate for app {name}…"),
            args: cmd::app_logout(&cluster, &name),
        }
    }

    /// Build an [`Outcome::OpenApp`] from the typed local port (blank = random
    /// free port). Rejects anything that isn't a valid 1–65535 port number.
    pub(super) fn connect_app(&mut self) -> Outcome {
        let Mode::AppPort { cluster, name } = std::mem::replace(&mut self.mode, Mode::Normal)
        else {
            return Outcome::Continue;
        };
        let raw = self.input.trim().to_owned();
        self.input.clear();
        let port = if raw.is_empty() {
            None
        } else {
            match raw.parse::<u16>() {
                Ok(p) if p != 0 => Some(p),
                _ => {
                    // Keep the prompt open so the user can correct the entry.
                    self.mode = Mode::AppPort { cluster, name };
                    self.report(&DomainError::InvalidValue { field: "port" });
                    return Outcome::Continue;
                }
            }
        };
        self.mode = Mode::Normal;
        Outcome::OpenApp {
            name,
            cluster,
            port,
        }
    }

    /// Generate a join token via `tctl tokens add --format=json`, run off-thread.
    /// The JSON result (including the secret token) is captured and shown in a
    /// popup — it is **never** logged. tctl availability is handled by the admin
    /// adapter (returns an error if absent).
    pub(super) fn generate_token(&mut self) {
        let token_type = self.input.trim().to_owned();
        if !valid_token_type(&token_type) {
            self.report(&DomainError::InvalidValue {
                field: "token_type",
            });
            return;
        }
        self.mode = Mode::Normal;
        self.input.clear();
        self.status = Some(format!("generating {token_type} token…"));
        self.dispatch_aux(Job::GenerateToken(token_type));
    }

    /// Approve/deny the selected request (interactive, audited by Teleport).
    pub(super) fn review_selected(&mut self, approve: bool) -> Outcome {
        let Some(idx) = self.selected_index() else {
            return Outcome::Continue;
        };
        let Some((id, pending)) = self
            .requests
            .get(idx)
            .map(|r| (r.id.to_string(), r.state.is_pending()))
        else {
            return Outcome::Continue;
        };
        if !pending {
            self.status = Some("only pending requests can be reviewed".to_owned());
            return Outcome::Continue;
        }
        let Some(cluster) = self.cluster_arg() else {
            return Outcome::Continue;
        };
        let action = if approve { "Approving" } else { "Denying" };
        Outcome::Run {
            label: format!("{action} access request {id}…"),
            args: cmd::request_review(&cluster, &id, approve),
        }
    }

    /// Drop the selected (previously assumed) access request, reverting its
    /// elevated access.
    pub(super) fn drop_selected(&mut self) -> Outcome {
        let Some(id) = self
            .selected_index()
            .and_then(|i| self.requests.get(i))
            .map(|r| r.id.to_string())
        else {
            return Outcome::Continue;
        };
        Outcome::Run {
            label: format!("Dropping access request {id}…"),
            args: cmd::request_drop(&id),
        }
    }

    /// Create an access request for the typed comma-separated roles.
    pub(super) fn create_request(&mut self) -> Outcome {
        let roles = self.input.trim().to_owned();
        if !valid_roles(&roles) {
            self.report(&DomainError::InvalidValue { field: "roles" });
            return Outcome::Continue;
        }
        let Some(cluster) = self.cluster_arg() else {
            return Outcome::Continue;
        };
        self.mode = Mode::Normal;
        self.input.clear();
        Outcome::Run {
            label: format!("Creating access request for roles {roles}…"),
            args: cmd::request_create(&cluster, &roles),
        }
    }

    /// Free-text login entry (used only when no known logins are available).
    /// Connects to the pending SSH target with the typed login.
    pub(super) fn start_ssh(&mut self) -> Outcome {
        let login = match Login::try_from(self.input.trim()) {
            Ok(l) => l,
            Err(e) => {
                self.report(&e);
                return Outcome::Continue;
            }
        };
        self.input.clear();
        let user = login.to_string();
        let Mode::Login(pending) = std::mem::replace(&mut self.mode, Mode::Normal) else {
            return Outcome::Continue;
        };
        self.connect_with_user(pending, &user)
    }
}
