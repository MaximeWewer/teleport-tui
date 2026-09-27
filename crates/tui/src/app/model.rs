//! The data model: the tab/mode enums, the `Outcome` the event loop acts on,
//! the injected `Repositories` bundle, the background-proxy handle + events, the
//! one-time secret views (`TokenView`/`InviteView`), and the aggregate row type.
//! Pure type definitions - the update/dispatch logic lives in [`super`].
//!
//! A child module of `app`: model types are re-exported from `super` so the rest
//! of the crate keeps referring to them as `crate::app::Tab` etc.

use domain::admin::{
    AdminRole, AdminUser, Bot, GeneratedToken, Instance, InviteLink, ProvisionToken,
};
use domain::capability::Capabilities;
use domain::node::SshNode;
use domain::port::{
    AdminRepository, AppRepository, AuthGateway, ClusterRepository, DatabaseRepository,
    KubeRepository, NodeRepository, RecordingRepository, RequestRepository, SessionRepository,
};
use domain::preferences::Preferences;
use domain::recording::SessionRecording;
use domain::request::AccessRequest;
use domain::resource::{App as AppResource, Database, KubeCluster, Resource};
use domain::value::{ClusterName, DeviceName, Hostname, Identifier, Login, ResourceName};
use zeroize::Zeroizing;

/// Resource tab. Each maps to a `tsh <verb> ls` listing and an Enter action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Tab {
    Ssh,
    Kube,
    Db,
    Apps,
    Requests,
    Users,
    Roles,
    Tokens,
    Bots,
    Inventory,
    Recordings,
}

impl Tab {
    /// Tab order, grouped: Access (SSH/Kube/Db/Apps) then Admin, then audit.
    pub(crate) const ALL: [Self; 11] = [
        Self::Ssh,
        Self::Kube,
        Self::Db,
        Self::Apps,
        Self::Users,
        Self::Roles,
        Self::Requests,
        Self::Tokens,
        Self::Bots,
        Self::Inventory,
        Self::Recordings,
    ];

    /// Resource-access tabs (cluster-scoped listings of infrastructure).
    pub(crate) const ACCESS: [Self; 4] = [Self::Ssh, Self::Kube, Self::Db, Self::Apps];
    /// Administrative / security tabs.
    pub(crate) const ADMIN: [Self; 6] = [
        Self::Users,
        Self::Roles,
        Self::Requests,
        Self::Tokens,
        Self::Bots,
        Self::Inventory,
    ];
    /// Audit / session-history tabs (cluster-scoped, not admin).
    pub(crate) const AUDIT: [Self; 1] = [Self::Recordings];

    #[must_use]
    pub(crate) const fn title(self) -> &'static str {
        match self {
            Self::Ssh => "SSH",
            Self::Kube => "Kubernetes",
            Self::Db => "Databases",
            Self::Apps => "Apps",
            Self::Requests => "Requests",
            Self::Users => "Users",
            Self::Roles => "Roles",
            Self::Tokens => "Tokens",
            Self::Bots => "Bots",
            Self::Inventory => "Inventory",
            Self::Recordings => "Recordings",
        }
    }

    /// Whether the all-clusters aggregate must reach this tab's data by
    /// re-selecting each cluster's profile (serial), rather than the concurrent
    /// per-cluster `-c` fan-out. True for the admin tabs (root-scoped via `tctl`)
    /// **and Recordings** - `tsh recordings ls` has no cluster flag either, so a
    /// leaf's recordings need a profile switch, exactly like the admin tabs.
    #[must_use]
    pub(crate) const fn serial_aggregation(self) -> bool {
        self.is_admin() || matches!(self, Self::Recordings)
    }

    /// Admin tabs are root-scoped via `tctl`, not tied to the selected cluster.
    #[must_use]
    pub(crate) const fn is_admin(self) -> bool {
        matches!(
            self,
            Self::Users | Self::Roles | Self::Tokens | Self::Bots | Self::Inventory
        )
    }

    /// Membership in the Admin menu group (Users/Roles/Requests). Used to hide
    /// the whole group when the user lacks admin rights.
    #[must_use]
    pub(crate) fn admin_only(self) -> bool {
        Self::ADMIN.contains(&self)
    }

    /// Tabs that require elevated rights and are hidden without them: the Admin
    /// group plus **Recordings** - reading the session audit log is a privileged
    /// operation not every user can perform, so it's gated like the admin tabs.
    #[must_use]
    pub(crate) fn admin_gated(self) -> bool {
        self.admin_only() || matches!(self, Self::Recordings)
    }

    pub(crate) fn next(self) -> Self {
        let i = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Self::ALL
            .get((i + 1) % Self::ALL.len())
            .copied()
            .unwrap_or(self)
    }

    pub(crate) fn prev(self) -> Self {
        let n = Self::ALL.len();
        let i = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Self::ALL.get((i + n - 1) % n).copied().unwrap_or(self)
    }
}

/// The active screen/modal **and the data that screen is operating on**. Modes
/// that capture a target (a confirmation, a picker, a prompt) carry it inline, so
/// a mode can't exist without its datum - e.g. you can't be in `ConfirmMfaRm`
/// without the device name. This replaces the former fieldless `Mode` + a
/// separate `pending` slot, making those illegal (mode, no-data) states
/// unrepresentable. Not `Copy` (some variants own `String`s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mode {
    Normal,
    Search,
    Picker,
    /// Typing a login for an SSH/kube connection that had no known user; carries
    /// the pending connection to launch once the login is entered.
    Login(PendingConnect),
    CreateRequest,
    ConfirmLogout,
    CreateToken,
    ShowToken,
    /// Confirming removal of the selected provision token (`tctl tokens rm`).
    ConfirmTokenRm,
    /// Editing the `tctl users add` form (username + roles).
    AddUser,
    /// Confirming a `tctl users reset` for the carried user.
    ConfirmUserReset(ResourceName),
    /// Showing the one-time account-setup URL (`tctl users add`/`reset`).
    ShowInvite,
    /// Showing the current user's MFA devices (`tsh mfa ls`); add/remove/navigate.
    ShowMfa,
    /// Confirming removal of the carried MFA device (`tsh mfa rm`).
    ConfirmMfaRm(DeviceName),
    /// Showing active sessions to join (`tsh sessions ls`); navigate + Enter join.
    ShowSessions,
    /// Read-only full-field detail popup for the selected admin row. Carries a
    /// title + `(label, values)` pairs - each field is a list so multi-valued
    /// fields (roles, labels) render one item per line - plus a vertical scroll
    /// offset (↑/↓ scroll when the fields overflow the popup; Esc/q/Enter close).
    ShowDetail {
        title: String,
        rows: Vec<(String, Vec<String>)>,
        scroll: u16,
    },
    /// Choosing which user/login to connect as; carries the pending connection.
    UserPicker(PendingConnect),
    /// Choosing a Kubernetes launcher tool for the carried (cluster, name, user).
    ToolPicker {
        cluster: ClusterName,
        name: ResourceName,
        user: Option<Identifier>,
    },
    /// Entering the database user for the carried (cluster, name).
    DbUser {
        cluster: ClusterName,
        name: ResourceName,
    },
    /// Entering the local proxy port for the carried app (cluster, name).
    AppPort {
        cluster: ClusterName,
        name: ResourceName,
    },
    /// An app proxy is running in the background (browser open); Esc stops it.
    AppProxy,
    /// Editing the `tsh scp` file-transfer form for the selected SSH node.
    Scp,
    /// Editing the `tsh ssh` options form (forward / tunnel / command) for the
    /// selected SSH node.
    SshOptions,
    /// Listing the active background SSH forwards (stop one, or Esc to close).
    Forwards,
    /// Editing the `tsh kube exec` form for the carried (cluster, kube).
    KubeExec {
        cluster: ClusterName,
        kube: ResourceName,
    },
    /// Editing the persisted defaults (Settings screen).
    Settings,
    /// Editing the `tsh login` form (proxy / user / auth / mfa).
    LoginForm,
    Help,
}

/// A connection awaiting a user/login choice. Built from validated parts; the
/// chosen user is substituted at launch time. SSH connects directly; Kubernetes
/// first picks a launcher tool (auto-proxy via `tsh proxy kube --exec`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingConnect {
    Ssh {
        cluster: ClusterName,
        host: Hostname,
    },
    Kube {
        cluster: ClusterName,
        name: ResourceName,
    },
}

/// UI configuration injected at startup: the editable defaults from
/// `config.toml` (the Settings screen writes them back through the injected
/// [`PreferencesStore`](domain::port::PreferencesStore)) plus the probed `tsh` capabilities.
#[derive(Debug, Clone, Default)]
pub(crate) struct Settings {
    pub(crate) prefs: Preferences,
    /// What the installed `tsh` supports (gates tabs/actions at runtime).
    pub(crate) capabilities: Capabilities,
}

/// What the event loop must do after a key press. Terminal-suspending actions
/// (interactive `tsh` subcommands) are returned, not run here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Continue,
    Quit,
    /// Run an interactive `tsh` subcommand (terminal handed over). `label` is a
    /// human-friendly description shown while the command connects, so the
    /// screen is never blank during the (tsh-inherent) connection delay.
    Run {
        args: Vec<String>,
        label: String,
    },
    /// Open an application: start a background local proxy and a browser, then
    /// keep the TUI up (handled by the event loop, which owns process spawning).
    OpenApp {
        name: ResourceName,
        cluster: ClusterName,
        /// Requested local proxy port; `None` = pick a random free port.
        port: Option<u16>,
    },
    /// Open a Kubernetes cluster: start a background `tsh proxy kube`, then hand
    /// off a clean shell/tool with `$KUBECONFIG` set (event loop owns this).
    OpenKube {
        kube: ResourceName,
        cluster: ClusterName,
        user: Option<Identifier>,
        tool: String,
    },
    /// Open a background `tsh proxy db` tunnel for a GUI client; the TUI shows the
    /// local endpoint and keeps the proxy up until dismissed (event loop owns it).
    OpenDbProxy {
        name: ResourceName,
        cluster: ClusterName,
    },
    /// Open a background SSH local port-forward (`tsh ssh -L <spec> -N`, no shell).
    /// Runs off the UI thread and stays up in the TUI's forwards list until stopped
    /// (event loop owns process spawning).
    OpenForward {
        cluster: ClusterName,
        user: Option<Login>,
        host: Hostname,
        spec: String,
        label: String,
    },
    /// Run `tsh kube exec` in a pod. `tsh kube exec` has no cluster flag, so the
    /// event loop first runs `tsh kube login --cluster=<cluster> <kube>` to set the
    /// active context, then hands off the interactive exec.
    KubeExec {
        cluster: ClusterName,
        kube: ResourceName,
        exec: Vec<String>,
        label: String,
    },
    /// Replay a recorded session (`tsh play`) interruptibly - the event loop keeps
    /// the keyboard so Esc/q returns to the TUI (see [`crate::ssh::play_recording`]).
    PlayRecording {
        args: Vec<String>,
        label: String,
    },
    /// Run a one-off, non-interactive command over `tsh ssh` (terminal handed
    /// over). Unlike [`Outcome::Run`], the event loop **pauses on the output** until
    /// a keypress before resuming the TUI, so a fast command's result isn't wiped.
    RunCommand {
        args: Vec<String>,
        label: String,
    },
}

/// Which kind of background proxy is running - drives the overlay wording (an
/// app proxy opens a browser; a db proxy exposes a local endpoint for a client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyKind {
    App,
    Db,
}

/// A running background proxy. Dropping it stops the proxy (kills the child), so
/// quitting the TUI or pressing Esc cleans up automatically.
#[derive(Debug)]
pub(crate) struct AppProxy {
    child: std::process::Child,
    pub(crate) name: String,
    pub(crate) url: String,
    pub(crate) kind: ProxyKind,
}

impl AppProxy {
    pub(crate) const fn new(
        child: std::process::Child,
        name: String,
        url: String,
        kind: ProxyKind,
    ) -> Self {
        Self {
            child,
            name,
            url,
            kind,
        }
    }
}

impl Drop for AppProxy {
    fn drop(&mut self) {
        crate::proxy::stop_child(&mut self.child);
    }
}

/// A running background SSH local port-forward (`tsh ssh -L … -N`). Dropping it
/// stops the tunnel (kills the child), so stopping it from the list - or quitting
/// the TUI - cleans up automatically.
#[derive(Debug)]
pub(crate) struct Forward {
    child: std::process::Child,
    /// `-L` spec (`[bind:]port:host:hostport`), shown as the primary column.
    pub(crate) spec: String,
    /// `[user@]host` the tunnel runs over.
    pub(crate) target: String,
    pub(crate) cluster: String,
}

impl Forward {
    pub(crate) const fn new(
        child: std::process::Child,
        spec: String,
        target: String,
        cluster: String,
    ) -> Self {
        Self {
            child,
            spec,
            target,
            cluster,
        }
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        crate::proxy::stop_child(&mut self.child);
    }
}

/// Outcome of a background proxy launch, delivered to the event loop so the
/// blocking `tsh proxy …` start-up (port wait / kubeconfig handshake, up to a
/// few seconds) runs off the UI thread instead of freezing the TUI. The event
/// loop owns the terminal, so the kube handoff (`run_interactive`) must happen
/// there - hence the result is routed back rather than handled in the worker.
// The `*Ready` postfix reads as "launch finished" and is the clearest name for
// each variant; keep it despite the shared suffix.
#[allow(clippy::enum_variant_names)]
pub(crate) enum ProxyEvent {
    /// A background app/db proxy finished starting (or failed). On success,
    /// attach it; for an app proxy the browser was already opened by the worker.
    AppReady {
        name: String,
        kind: ProxyKind,
        result: std::io::Result<(std::process::Child, String)>,
    },
    /// A background kube proxy is ready (or failed). On success, the event loop
    /// hands off a `tool` shell with the printed `$KUBECONFIG`.
    KubeReady {
        kube: String,
        tool: String,
        result: std::io::Result<(std::process::Child, String)>,
    },
    /// A background SSH forward finished starting (or failed). On success, the
    /// child is added to the forwards list; on failure the error is surfaced.
    ForwardReady {
        spec: String,
        target: String,
        cluster: String,
        result: std::io::Result<std::process::Child>,
    },
}

/// A generated join token held for one-time display. The token value is wrapped
/// in [`Zeroizing`] so it is scrubbed from memory when the popup is dismissed.
/// Its `Debug` impl masks the secret.
pub(crate) struct TokenView {
    pub(crate) token: Zeroizing<String>,
    pub(crate) roles: Vec<String>,
    pub(crate) expires: String,
    pub(crate) ca_pins: Vec<String>,
}

impl From<GeneratedToken> for TokenView {
    fn from(g: GeneratedToken) -> Self {
        Self {
            // Moves the allocation (no copy) from one wiping holder to another.
            token: Zeroizing::new(g.token.into_inner()),
            roles: g.roles,
            expires: g.expires,
            ca_pins: g.ca_pins,
        }
    }
}

// The token field is intentionally masked (it is a secret).
impl std::fmt::Debug for TokenView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenView")
            .field("token", &"<redacted>")
            .field("roles", &self.roles)
            .field("expires", &self.expires)
            .field("ca_pins", &self.ca_pins)
            .finish()
    }
}

/// A one-time account-setup URL (`tctl users add`/`reset`) held for display. The
/// URL embeds a secret invite token → it lives in [`Zeroizing`] (scrubbed when
/// the popup is dismissed) and its `Debug` masks it.
pub(crate) struct InviteView {
    pub(crate) user: String,
    pub(crate) url: Zeroizing<String>,
}

impl From<InviteLink> for InviteView {
    fn from(l: InviteLink) -> Self {
        Self {
            user: l.user,
            url: Zeroizing::new(l.url.into_inner()),
        }
    }
}

impl std::fmt::Debug for InviteView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteView")
            .field("user", &self.user)
            .field("url", &"<redacted>")
            .finish()
    }
}

/// All injected repository ports, bundled for clean dependency injection.
#[derive(Debug)]
pub(crate) struct Repositories {
    pub(crate) clusters: Box<dyn ClusterRepository>,
    pub(crate) nodes: Box<dyn NodeRepository>,
    pub(crate) kube: Box<dyn KubeRepository>,
    pub(crate) databases: Box<dyn DatabaseRepository>,
    pub(crate) apps: Box<dyn AppRepository>,
    pub(crate) requests: Box<dyn RequestRepository>,
    pub(crate) recordings: Box<dyn RecordingRepository>,
    pub(crate) sessions: Box<dyn SessionRepository>,
    pub(crate) auth: Box<dyn AuthGateway>,
    pub(crate) admin: Box<dyn AdminRepository>,
}

/// One row in the all-clusters aggregate view: the cluster it came from plus the
/// resource's display cells.
#[derive(Debug, Clone)]
pub(crate) struct AggRow {
    pub(crate) cluster: ClusterName,
    pub(crate) cells: Vec<String>,
    /// True for a placeholder row standing in for a cluster the all-clusters
    /// admin fan-out could not reach because it has no active session. Pressing
    /// `L` on it logs into that cluster's proxy; it is not a real resource row.
    pub(crate) login_required: bool,
    /// True for a placeholder row carrying a cluster's listing error: not a
    /// resource, so row actions (connect, login, review, ...) must not target it.
    pub(crate) error: bool,
    /// For an aggregated Recordings row, the session id to `tsh play` (the sid is
    /// not a displayed column). `None` for every other tab.
    pub(crate) sid: Option<String>,
}

impl AggRow {
    /// A stand-in for a cluster (error / not logged in), not a real resource.
    pub(crate) const fn is_placeholder(&self) -> bool {
        self.login_required || self.error
    }

    /// Search matches the primary identifier (first column: hostname/name) only.
    pub(crate) fn matches(&self, needle: &str) -> bool {
        self.cells
            .first()
            .is_some_and(|c| c.to_lowercase().contains(needle))
    }
}

/// Column headers for a tab's resource (used by the aggregate view).
pub(crate) fn tab_columns(tab: Tab) -> &'static [&'static str] {
    match tab {
        Tab::Ssh => SshNode::columns(),
        Tab::Kube => KubeCluster::columns(),
        Tab::Db => Database::columns(),
        Tab::Apps => AppResource::columns(),
        Tab::Requests => AccessRequest::columns(),
        Tab::Users => AdminUser::columns(),
        Tab::Roles => AdminRole::columns(),
        Tab::Tokens => ProvisionToken::columns(),
        Tab::Bots => Bot::columns(),
        Tab::Inventory => Instance::columns(),
        Tab::Recordings => SessionRecording::columns(),
    }
}

/// Spinner animation frames.
pub(crate) const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
