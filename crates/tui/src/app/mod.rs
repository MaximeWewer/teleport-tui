//! Application state (the Elm-like "Model") and update logic. Holds injected
//! repository ports as trait objects (dependency injection from `main`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::Sender;

use domain::capability::Capabilities;
use domain::cluster::ClusterTopology;
use domain::error::ReportableError;
use domain::mfa::MfaDevice;
use domain::port::{ErrorLog, LogLevel, PreferencesStore};
use domain::preferences::Preferences;
use domain::profile::{Profile, ProfileSummary};
use domain::session::ActiveSession;
use domain::value::{ClusterName, ProxyAddr};
use ratatui::widgets::{ListState, TableState};

use crate::forms::{
    AddUserForm, KubeExecForm, LoginForm, ScpForm, SettingsForm, SshOptionsForm,
    forward_binds_all_interfaces,
};

mod actions;
mod dispatch;
mod input;
mod listings;
mod model;
mod nav;
mod update;
use dispatch::{Dispatcher, Job};
use listings::{AggView, Listings, PickList};
// Re-exported so the rest of the crate keeps using `crate::app::Tab` etc., and so
// the sibling child modules import the model types from `super`.
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
    /// Structured error export (injected port; an NDJSON file in production).
    logger: Box<dyn ErrorLog>,
    run_id: String,
    pub(crate) tsh: PathBuf,

    pub(crate) profile: Option<Profile>,
    /// Every `tsh` profile (one per proxy logged in to), the active one
    /// included, from the same `tsh status` read as [`Self::profile`].
    pub(crate) profiles: Vec<ProfileSummary>,
    /// Generation of the active `tsh` profile, bumped on every switch to
    /// another proxy. Profile-dependent results (status, topology, admin probe,
    /// MFA, sessions) carry the generation they were read for and are dropped
    /// when it is not this one, so the old profile can't leak into the new.
    profile_gen: u64,
    /// Lowest aggregate fan-out seq still current: slices of a fan-out started
    /// before the last profile switch are dropped (not even cached).
    agg_floor: u64,
    /// The proxy a background profile switch is running for (one at a time).
    pub(crate) profile_switching: Option<ProxyAddr>,
    /// An outcome produced by a background result rather than a key press (an
    /// expired profile's interactive login), for the event loop to run next.
    deferred: Option<Outcome>,
    pub(crate) last_was_auth: bool,
    pub(crate) topology: Option<ClusterTopology>,
    pub(crate) tab: Tab,
    /// The scoped view's per-tab listings.
    pub(crate) lists: Listings,
    pub(crate) visible: Vec<usize>,
    pub(crate) table: TableState,

    pub(crate) mode: Mode,
    pub(crate) input: String,
    pub(crate) picker: ListState,
    pub(crate) status: Option<String>,
    /// A start-up warning (bad config value, unusable `tctl_path`, …). Shown in
    /// place of the status line until the next key press, so the first
    /// background results can't overwrite it before the user has seen it.
    pub(crate) notice: Option<String>,
    /// Held only while the generated-token popup is open; scrubbed on dismiss.
    pub(crate) token_view: Option<TokenView>,
    /// Held while the one-time invite/reset URL popup is open; scrubbed on dismiss.
    pub(crate) invite_view: Option<InviteView>,
    /// Held while the MFA-devices popup is open (`tsh mfa ls`). Public-key
    /// metadata only - not secret.
    pub(crate) mfa_devices: PickList<MfaDevice>,
    /// Held while the active-sessions popup is open (`tsh sessions ls`).
    pub(crate) sessions: PickList<ActiveSession>,
    /// In-progress `tctl users add` form.
    pub(crate) add_user_form: AddUserForm,
    /// In-progress `tsh kube exec` form (Kube tab).
    pub(crate) kube_exec_form: KubeExecForm,
    pub(crate) user_choices: PickList<String>,
    pub(crate) tool_choices: PickList<String>,
    /// The currently running background app proxy (stopped on drop / Esc).
    pub(crate) proxy: Option<AppProxy>,
    /// Active background SSH port-forwards (`tsh ssh -L … -N`), each stopped on
    /// drop. Listed/stopped from the forwards popup.
    pub(crate) forwards: PickList<Forward>,
    /// Per-tab cache marker: the context (cluster name, or `@admin`) the tab's
    /// data was last loaded for. A matching key means "show cache, don't refetch".
    cache_key: HashMap<Tab, String>,
    pub(crate) login_form: LoginForm,
    /// The live user defaults (login form, users that skip the pickers,
    /// Kubernetes launchers, refresh interval), edited by the Settings screen.
    pub(crate) prefs: Preferences,
    /// Where the Settings screen persists its edits (injected port; the
    /// `config.toml` file in production).
    prefs_store: Box<dyn PreferencesStore>,
    /// In-progress Settings (persisted defaults) editor.
    pub(crate) settings_form: SettingsForm,
    /// All-clusters aggregate view state.
    pub(crate) agg: AggView,
    /// Set when an all-clusters admin login (`L` on a login-required row) just
    /// switched the active profile to a leaf. The next [`Self::after_action`]
    /// re-selects this (root) proxy *before* refetching clusters/status, so the
    /// topology isn't re-read from the leaf's narrower viewpoint.
    pending_root_restore: Option<ClusterName>,
    /// Root proxy to restore after the login form (opened via `L` on a
    /// login-required leaf row) is submitted; carries the intent from opening the
    /// form to [`Self::submit_login`]. `None` for a normal login.
    relogin_root: Option<ClusterName>,
    /// Whether the current identity has admin rights (probed via `tctl`). When
    /// false, the whole Admin menu group (Users/Roles/Requests) is hidden.
    pub(crate) admin_allowed: bool,
    /// Whether the admin-rights probe has returned. Until it has, the admin tabs
    /// are prefetched *optimistically* (in parallel with the slow `tctl status`
    /// probe) rather than waiting for it - their `tctl` listings are ~3s each, so
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

/// A non-fatal start-up problem, as a loggable error record.
struct StartupWarning<'a>(&'a str);

impl ReportableError for StartupWarning<'_> {
    fn code(&self) -> &'static str {
        "STARTUP_WARNING"
    }
    fn category(&self) -> domain::error::Category {
        domain::error::Category::Input
    }
    fn message(&self) -> String {
        self.0.to_owned()
    }
}

/// Background-prefetch sequence numbers start here, disjoint from `tab_req`
/// (which counts active-tab loads), so `apply_tab` can tell them apart.
const PREFETCH_BASE: u64 = 1 << 40;

impl App {
    pub(crate) fn new(
        repos: Repositories,
        logger: Box<dyn ErrorLog>,
        prefs_store: Box<dyn PreferencesStore>,
        run_id: String,
        tsh: PathBuf,
        settings: Settings,
        synchronous: bool,
    ) -> Self {
        let dispatcher = Dispatcher::new(repos, synchronous);
        let Settings {
            prefs,
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
            profiles: Vec::new(),
            profile_gen: 0,
            agg_floor: 0,
            profile_switching: None,
            deferred: None,
            last_was_auth: false,
            topology: None,
            tab: Tab::Ssh,
            lists: Listings::default(),
            visible: Vec::new(),
            table: TableState::default(),
            mode: Mode::Normal,
            input: String::new(),
            picker: ListState::default(),
            status: None,
            notice: None,
            token_view: None,
            invite_view: None,
            mfa_devices: PickList::default(),
            sessions: PickList::default(),
            add_user_form: AddUserForm::default(),
            kube_exec_form: KubeExecForm::default(),
            user_choices: PickList::default(),
            tool_choices: PickList::default(),
            proxy: None,
            forwards: PickList::default(),
            cache_key: HashMap::new(),
            login_form: LoginForm::default(),
            prefs,
            prefs_store,
            settings_form: SettingsForm::default(),
            agg: AggView::default(),
            pending_root_restore: None,
            relogin_root: None,
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

    /// An outcome a background result asked for (see [`Self::deferred`]),
    /// handed to the event loop once.
    pub(crate) const fn take_deferred(&mut self) -> Option<Outcome> {
        self.deferred.take()
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

    /// Surface start-up warnings: each is logged, and all are shown as the
    /// [`App::notice`] until the next key press.
    pub(crate) fn warn_startup(&mut self, warnings: &[String]) {
        for w in warnings {
            self.logger
                .record("tui", LogLevel::Warn, &StartupWarning(w), &self.run_id);
        }
        if !warnings.is_empty() {
            // Callers pass display-safe text: the adapters that produce the
            // warnings (config parsing, binary lookup) redact them at the source.
            self.notice = Some(format!("⚠ {}", warnings.join(" · ")));
        }
    }

    fn report(&mut self, err: &impl ReportableError) {
        self.logger
            .record("application", LogLevel::Error, err, &self.run_id);
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
    /// A forward bound on every interface gets a warning: anyone on the network
    /// can reach the tunnel.
    pub(crate) fn attach_forward(&mut self, forward: Forward) {
        let exposed = if forward_binds_all_interfaces(&forward.spec) {
            " - WARNING: bound on all interfaces, reachable from the network"
        } else {
            ""
        };
        self.status = Some(format!(
            "forward up: {} · {} ({}){exposed}",
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
        self.forwards.clamp();
        self.mode = Mode::Forwards;
    }

    /// Stop (kill) the selected forward; dropping it terminates the tunnel.
    pub(super) fn stop_selected_forward(&mut self) {
        if let Some(f) = self.forwards.remove_selected() {
            self.status = Some(format!("forward stopped: {}", f.spec));
        }
    }

    /// Move the forwards-popup selection by ±1 (clamped).
    pub(super) fn move_forward_sel(&mut self, forward: bool) {
        self.forwards.step(forward);
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

/// Seconds since the Unix epoch, now (0 if the clock is before it).
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
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
