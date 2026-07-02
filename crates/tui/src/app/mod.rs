//! Application state (the Elm-like "Model") and update logic. Holds injected
//! repository ports as trait objects (dependency injection from `main`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use application::command as cmd;
use application::error::AppError;
use application::use_case::{
    AddUser, GenerateToken, GetStatus, ListApps, ListBots, ListClusters, ListDatabases,
    ListInstances, ListKube, ListMfaDevices, ListNodes, ListRecordings, ListRequests, ListRoles,
    ListSessions, ListTokens, ListUsers, RemoveToken, ResetUser,
};
use domain::admin::{
    AdminRole, AdminUser, Bot, GeneratedToken, Instance, InviteLink, ProvisionToken,
};
use domain::capability::Capabilities;
use domain::cluster::{ClusterContext, ClusterTopology};
use domain::error::{DomainError, ReportableError};
use domain::mfa::MfaDevice;
use domain::node::SshNode;
use domain::port::{
    AdminRepository, AppRepository, AuthGateway, ClusterRepository, DatabaseRepository,
    KubeRepository, NodeRepository, RecordingRepository, RequestRepository, SessionRepository,
};
use domain::profile::Profile;
use domain::recording::SessionRecording;
use domain::request::AccessRequest;
use domain::resource::{App as AppResource, Database, KubeCluster, Resource};
use domain::session::ActiveSession;
use domain::value::Login;
use infrastructure::config::Config as InfraConfig;
use infrastructure::logging::NdjsonLogger;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::{ListState, TableState};
use zeroize::Zeroizing;

use crate::forms::{
    AUTH_OPTIONS, AddUserForm, KubeExecForm, LoginForm, MFA_OPTIONS, ScpForm, SettingsForm,
    SshOptionsForm, opt_index, valid_command, valid_forward, valid_path, valid_roles,
    valid_token_type, valid_user,
};

mod actions;
mod dispatch;
mod input;
mod model;
mod nav;
mod update;
use dispatch::{Dispatcher, Job, JobResult, agg_rows_of};
// Re-exported so the rest of the crate keeps using `crate::app::Tab` etc., and so
// the sibling child modules' `use super::*` still resolves the model types.
pub(crate) use model::*;

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // distinct UI flags, not a state enum
pub(crate) struct App {
    /// Concurrency seam: repos + background job/proxy channels (see [`Dispatcher`]).
    dispatcher: Dispatcher,
    /// Monotonic id of the latest tab-data request (for stale-result gating).
    tab_req: u64,
    pub(crate) loading: bool,
    pub(crate) spinner: usize,
    logger: NdjsonLogger,
    run_id: String,
    pub(crate) tsh: PathBuf,

    pub(crate) profile: Option<Profile>,
    pub(crate) last_was_auth: bool,
    pub(crate) topology: Option<ClusterTopology>,
    pub(crate) tab: Tab,
    pub(crate) nodes: Vec<SshNode>,
    pub(crate) kube: Vec<KubeCluster>,
    pub(crate) dbs: Vec<Database>,
    pub(crate) apps: Vec<AppResource>,
    pub(crate) requests: Vec<AccessRequest>,
    pub(crate) recordings: Vec<SessionRecording>,
    pub(crate) users: Vec<AdminUser>,
    pub(crate) roles: Vec<AdminRole>,
    /// Provision tokens (Tokens tab) — a plain admin listing (name/type/labels/
    /// expiry), exactly what `tctl tokens ls` prints. No secret in the listing.
    pub(crate) tokens: Vec<ProvisionToken>,
    /// Machine ID bots (Bots tab) and connected agent instances (Inventory tab).
    pub(crate) bots: Vec<Bot>,
    pub(crate) instances: Vec<Instance>,
    pub(crate) visible: Vec<usize>,
    pub(crate) table: TableState,

    pub(crate) mode: Mode,
    pub(crate) input: String,
    pub(crate) picker: ListState,
    pub(crate) status: Option<String>,
    /// Held only while the generated-token popup is open; scrubbed on dismiss.
    pub(crate) token_view: Option<TokenView>,
    /// Held while the one-time invite/reset URL popup is open; scrubbed on dismiss.
    pub(crate) invite_view: Option<InviteView>,
    /// Held while the MFA-devices popup is open (`tsh mfa ls`). Public-key
    /// metadata only — not secret.
    pub(crate) mfa_devices: Vec<MfaDevice>,
    /// Selected row in the MFA popup; device awaiting `tsh mfa rm` confirmation.
    pub(crate) mfa_sel: usize,
    /// Held while the active-sessions popup is open (`tsh sessions ls`).
    pub(crate) sessions: Vec<ActiveSession>,
    pub(crate) sessions_sel: usize,
    /// In-progress `tctl users add` form.
    pub(crate) add_user_form: AddUserForm,
    /// In-progress `tsh kube exec` form (Kube tab).
    pub(crate) kube_exec_form: KubeExecForm,
    pub(crate) user_choices: Vec<String>,
    pub(crate) user_picker: ListState,
    /// Configured Kubernetes launchers (e.g. shell, k9s).
    kube_tools: Vec<String>,
    pub(crate) tool_choices: Vec<String>,
    pub(crate) tool_picker: ListState,
    /// The currently running background app proxy (stopped on drop / Esc).
    pub(crate) proxy: Option<AppProxy>,
    /// Active background SSH port-forwards (`tsh ssh -L … -N`), each stopped on
    /// drop. Listed/stopped from the forwards popup.
    pub(crate) forwards: Vec<Forward>,
    /// Selected row in the forwards popup.
    pub(crate) forwards_sel: usize,
    /// Per-tab cache marker: the context (cluster name, or `@admin`) the tab's
    /// data was last loaded for. A matching key means "show cache, don't refetch".
    cache_key: HashMap<Tab, String>,
    pub(crate) login_form: LoginForm,
    login_proxy: Option<String>,
    login_user: Option<String>,
    /// Persisted login-form defaults (auth connector / MFA mode).
    login_auth: Option<String>,
    login_mfa: Option<String>,
    /// Persisted default users that skip the per-resource pickers/prompts.
    default_login: Option<String>,
    default_kube_user: Option<String>,
    default_db_user: Option<String>,
    /// Auto-refresh interval (persisted; applied on next launch).
    refresh_seconds: Option<u64>,
    /// Resolved `config.toml` path that the Settings screen writes back to.
    config_path: PathBuf,
    /// In-progress Settings (persisted defaults) editor.
    pub(crate) settings_form: SettingsForm,
    /// All-clusters aggregate view: when on, the active tab lists every cluster.
    pub(crate) aggregate: bool,
    pub(crate) agg_rows: Vec<AggRow>,
    agg_seq: u64,
    agg_pending: usize,
    /// Per-`(tab, cluster)` cache of an all-clusters fan-out: each cluster's rows
    /// are cached independently as they arrive, so **partial** progress survives
    /// navigating away — on return, cached clusters render instantly and only the
    /// missing ones are re-fetched (no restart from zero). Cleared per-cluster on
    /// login, per-tab on `r`, and wholesale on topology change / logout.
    agg_cache: HashMap<(Tab, String), Vec<AggRow>>,
    /// Set when an all-clusters admin login (`L` on a login-required row) just
    /// switched the active profile to a leaf. The next [`Self::after_action`]
    /// re-selects this (root) proxy *before* refetching clusters/status, so the
    /// topology isn't re-read from the leaf's narrower viewpoint.
    pending_root_restore: Option<String>,
    /// Root proxy to restore after the login form (opened via `L` on a
    /// login-required leaf row) is submitted; carries the intent from opening the
    /// form to [`Self::submit_login`]. `None` for a normal login.
    relogin_root: Option<String>,
    /// Whether the current identity has admin rights (probed via `tctl`). When
    /// false, the whole Admin menu group (Users/Roles/Requests) is hidden.
    pub(crate) admin_allowed: bool,
    /// Whether the admin-rights probe has returned. Until it has, the admin tabs
    /// are prefetched *optimistically* (in parallel with the slow `tctl status`
    /// probe) rather than waiting for it — their `tctl` listings are ~3s each, so
    /// gating them behind the probe left the tabs cold for several seconds.
    admin_probed: bool,
    /// In-progress `tsh scp` transfer form (SSH nodes only).
    pub(crate) scp_form: ScpForm,
    /// In-progress `tsh ssh` options form (SSH nodes only).
    pub(crate) ssh_options_form: SshOptionsForm,
    /// Runtime CLI capabilities of the installed `tsh` (gates tabs/actions).
    pub(crate) caps: Capabilities,
    /// Generation token for background prefetch results (bumped when the target
    /// cluster changes, so stale-cluster prefetches are dropped on apply).
    prefetch_seq: u64,
    /// Cluster the current prefetch batch targets (`None` until first prefetch).
    prefetch_cluster: Option<String>,
}

/// Background-prefetch sequence numbers start here, disjoint from `tab_req`
/// (which counts active-tab loads), so `apply_tab` can tell them apart.
const PREFETCH_BASE: u64 = 1 << 40;

impl App {
    pub(crate) fn new(
        repos: Repositories,
        logger: NdjsonLogger,
        run_id: String,
        tsh: PathBuf,
        settings: Settings,
        synchronous: bool,
    ) -> Self {
        let dispatcher = Dispatcher::new(repos, synchronous);
        let Settings {
            kube_tools,
            login_proxy,
            login_user,
            login_auth,
            login_mfa,
            default_login,
            default_kube_user,
            default_db_user,
            refresh_seconds,
            config_path,
            capabilities,
        } = settings;
        Self {
            dispatcher,
            tab_req: 0,
            loading: false,
            spinner: 0,
            logger,
            run_id,
            tsh,
            profile: None,
            last_was_auth: false,
            topology: None,
            tab: Tab::Ssh,
            nodes: Vec::new(),
            kube: Vec::new(),
            dbs: Vec::new(),
            apps: Vec::new(),
            requests: Vec::new(),
            recordings: Vec::new(),
            users: Vec::new(),
            roles: Vec::new(),
            tokens: Vec::new(),
            bots: Vec::new(),
            instances: Vec::new(),
            visible: Vec::new(),
            table: TableState::default(),
            mode: Mode::Normal,
            input: String::new(),
            picker: ListState::default(),
            status: None,
            token_view: None,
            invite_view: None,
            mfa_devices: Vec::new(),
            mfa_sel: 0,
            sessions: Vec::new(),
            sessions_sel: 0,
            add_user_form: AddUserForm::default(),
            kube_exec_form: KubeExecForm::default(),
            user_choices: Vec::new(),
            user_picker: ListState::default(),
            kube_tools,
            tool_choices: Vec::new(),
            tool_picker: ListState::default(),
            proxy: None,
            forwards: Vec::new(),
            forwards_sel: 0,
            cache_key: HashMap::new(),
            login_form: LoginForm::default(),
            login_proxy,
            login_user,
            login_auth,
            login_mfa,
            default_login,
            default_kube_user,
            default_db_user,
            refresh_seconds,
            config_path,
            settings_form: SettingsForm::default(),
            aggregate: false,
            pending_root_restore: None,
            relogin_root: None,
            agg_rows: Vec::new(),
            agg_seq: 0,
            agg_pending: 0,
            agg_cache: HashMap::new(),
            admin_allowed: false,
            admin_probed: false,
            scp_form: ScpForm::default(),
            ssh_options_form: SshOptionsForm::default(),
            caps: capabilities,
            prefetch_seq: PREFETCH_BASE,
            prefetch_cluster: None,
        }
    }

    pub(crate) fn bootstrap(&mut self) {
        self.dispatch_aux(Job::Status);
        self.dispatch_aux(Job::Clusters);
        self.dispatch_aux(Job::AdminProbe);
    }

    /// Drain finished jobs and advance the spinner. Called once per UI tick by
    /// the event loop, so background results are applied without blocking input.
    /// Returns `true` if anything changed (a result landed or the spinner
    /// advanced), letting the loop skip the redraw when nothing did.
    pub(crate) fn tick(&mut self) -> bool {
        let mut changed = false;
        for (seq, result) in self.dispatcher.drain_jobs() {
            self.apply(seq, result);
            changed = true;
        }
        if self.loading {
            self.spinner = self.spinner.wrapping_add(1);
            changed = true;
        }
        changed
    }

    #[must_use]
    pub(crate) fn spinner_frame(&self) -> char {
        SPINNER
            .get(self.spinner % SPINNER.len())
            .copied()
            .unwrap_or('⠋')
    }

    fn report(&mut self, err: &impl ReportableError) {
        let _ = self.logger.report("application", err, None, &self.run_id);
        self.status = Some(format!("[{}] {}", err.code(), err.message()));
    }

    /// Attach a started background app proxy and switch to its overlay mode.
    /// Called by the event loop after spawning the proxy + opening the browser.
    pub(crate) fn attach_proxy(&mut self, proxy: AppProxy) {
        self.status = Some(format!("app proxy: {} → {}", proxy.name, proxy.url));
        self.proxy = Some(proxy);
        self.mode = Mode::AppProxy;
    }

    /// Report a failure to open an app (proxy did not start).
    pub(crate) fn report_app_error(&mut self, detail: &str) {
        self.status = Some(format!("[APP_PROXY_FAILED] {detail}"));
    }

    /// Register a started background SSH forward. Called by the event loop once the
    /// tunnel is confirmed up.
    pub(crate) fn attach_forward(&mut self, forward: Forward) {
        self.status = Some(format!(
            "forward up: {} · {} ({})",
            forward.spec, forward.target, forward.cluster
        ));
        self.forwards.push(forward);
    }

    /// Report a failed SSH forward launch.
    pub(crate) fn report_forward_error(&mut self, detail: &str) {
        self.status = Some(format!("[FORWARD_FAILED] {detail}"));
    }

    /// Open the forwards popup (even when empty, so the user can confirm none run).
    pub(super) fn open_forwards(&mut self) {
        self.forwards_sel = self.forwards_sel.min(self.forwards.len().saturating_sub(1));
        self.mode = Mode::Forwards;
    }

    /// Stop (kill) the selected forward; dropping it terminates the tunnel.
    pub(super) fn stop_selected_forward(&mut self) {
        if self.forwards_sel < self.forwards.len() {
            let f = self.forwards.remove(self.forwards_sel);
            self.status = Some(format!("forward stopped: {}", f.spec));
        }
        self.forwards_sel = self.forwards_sel.min(self.forwards.len().saturating_sub(1));
    }

    /// Move the forwards-popup selection by ±1 (clamped).
    pub(super) fn move_forward_sel(&mut self, forward: bool) {
        if self.forwards.is_empty() {
            return;
        }
        self.forwards_sel = clamp_step(self.forwards_sel, self.forwards.len(), forward);
    }

    /// Note that a handed-off session (e.g. kube shell) has ended.
    pub(crate) fn note_session_ended(&mut self) {
        self.status = Some("session ended".to_owned());
    }

    /// A clone of the proxy-event sender, handed to a worker thread so it can
    /// report a finished background proxy launch back to the event loop.
    pub(crate) fn proxy_sender(&self) -> Sender<ProxyEvent> {
        self.dispatcher.proxy_sender()
    }

    /// Drain any completed background proxy launches (non-blocking). The event
    /// loop handles each (attach app proxy / hand off kube shell / report error).
    pub(crate) fn drain_proxy_events(&self) -> Vec<ProxyEvent> {
        self.dispatcher.drain_proxy()
    }

    /// Show a transient "connecting…" status while a background proxy starts.
    pub(crate) fn note_connecting(&mut self, label: &str) {
        self.status = Some(label.to_owned());
    }

    /// Surface a non-zero exit from a handed-off command (e.g. a failed
    /// `tsh ssh`/login) rather than treating it as success.
    pub(crate) fn note_command_exit(&mut self, code: Option<i32>) {
        let detail = code.map_or_else(|| "terminated".to_owned(), |c| format!("exit code {c}"));
        self.status = Some(format!("command failed ({detail})"));
    }
}

/// What a key did to a single-line text prompt: edited the buffer, submitted
/// (Enter), or cancelled (Esc). Lets the per-prompt handlers share the common
/// edit logic while keeping their distinct submit/cancel side effects explicit.
enum TextEvent {
    Edited,
    Submit,
    Cancel,
}

/// Indices of `items` kept by the search predicate, preserving order.
fn indices<T: Resource>(items: &[T], needle: &str, keep: impl Fn(bool) -> bool) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter(|(_, it)| keep(it.matches(needle)))
        .map(|(i, _)| i)
        .collect()
}

/// Replace a vec's contents and return the new length.
fn set_vec<T>(dst: &mut Vec<T>, value: Vec<T>) -> usize {
    *dst = value;
    dst.len()
}

/// Clamped index step: stops at the first/last item (no wrap-around). An empty
/// list clamps to 0 (callers already guard emptiness; this keeps it total and
/// avoids the `len - 1` underflow if one ever doesn't).
fn clamp_step(cur: usize, len: usize, forward: bool) -> usize {
    if len == 0 {
        return 0;
    }
    if forward {
        (cur + 1).min(len - 1)
    } else {
        cur.saturating_sub(1)
    }
}

#[cfg(test)]
mod tests;
