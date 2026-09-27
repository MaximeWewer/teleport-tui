//! Ports - traits the application depends on, implemented by infrastructure
//! adapters. The dependency rule points inward: domain declares, infra fulfils.

use crate::admin::{
    AdminRole, AdminUser, Bot, GeneratedToken, Instance, InviteLink, ProvisionToken,
};
use crate::capability::Capabilities;
use crate::cluster::{ClusterContext, ClusterTopology};
use crate::error::{DomainError, ReportableError};
use crate::mfa::MfaDevice;
use crate::node::SshNode;
use crate::preferences::Preferences;
use crate::profile::Profile;
use crate::recording::SessionRecording;
use crate::request::AccessRequest;
use crate::resource::{App, Database, KubeCluster};
use crate::session::ActiveSession;
use crate::value::{ClusterName, ResourceName, RoleList, TokenTypes};

/// Severity of an exported error record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
}

impl LogLevel {
    /// The record's `level` field value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
        }
    }
}

/// Structured error export (an NDJSON file in production). Best-effort by
/// contract: a sink that fails to write must not surface that failure, so
/// callers never branch on logging.
pub trait ErrorLog: std::fmt::Debug + Send + Sync {
    /// Record `err`, raised in `layer`, for the run `run_id`.
    fn record(&self, layer: &str, level: LogLevel, err: &dyn ReportableError, run_id: &str);
}

/// Persists the user's [`Preferences`] (the config file in production).
pub trait PreferencesStore: std::fmt::Debug + Send + Sync {
    /// Save `prefs`, keeping whatever else the store holds that is not a
    /// preference (e.g. binary path overrides).
    ///
    /// # Errors
    /// Returns the I/O error when the store could not be written.
    fn save(&self, prefs: &Preferences) -> std::io::Result<()>;

    /// Where the preferences live, for the "saved" confirmation.
    fn location(&self) -> String;
}

/// Probes which top-level commands the installed `tsh` supports, so the UI can
/// adapt to the actual binary (runtime detection, not compile-time `cfg`).
pub trait CapabilityProbe: std::fmt::Debug + Send + Sync {
    /// Best-effort: returns [`Capabilities::unknown`] (permissive) on any
    /// failure, never an error - a probe miss must not hide working features.
    fn probe(&self) -> Capabilities;
}

/// Reads the root/leaf topology (`tsh clusters`).
pub trait ClusterRepository: std::fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns [`DomainError`] on auth failure, offline cluster, or parse error.
    fn list_clusters(&self) -> Result<ClusterTopology, DomainError>;
}

/// Lists SSH nodes, scoped to one cluster context (`tsh ls -c <cluster>`).
pub trait NodeRepository: std::fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns [`DomainError`] on auth failure, offline cluster, or parse error.
    fn list_nodes(&self, ctx: &ClusterContext) -> Result<Vec<SshNode>, DomainError>;
}

/// Lists Kubernetes clusters (`tsh kube ls -c <cluster>`).
pub trait KubeRepository: std::fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn list_kube(&self, ctx: &ClusterContext) -> Result<Vec<KubeCluster>, DomainError>;
}

/// Lists databases (`tsh db ls -c <cluster>`).
pub trait DatabaseRepository: std::fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn list_databases(&self, ctx: &ClusterContext) -> Result<Vec<Database>, DomainError>;
}

/// Lists applications (`tsh apps ls -c <cluster>`).
pub trait AppRepository: std::fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn list_apps(&self, ctx: &ClusterContext) -> Result<Vec<App>, DomainError>;
}

/// Lists recorded sessions (`tsh recordings ls -c <cluster>`).
pub trait RecordingRepository: std::fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn list_recordings(&self, ctx: &ClusterContext) -> Result<Vec<SessionRecording>, DomainError>;
}

/// Lists active sessions one can join (`tsh sessions ls -c <cluster>`).
pub trait SessionRepository: std::fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn list_sessions(&self, ctx: &ClusterContext) -> Result<Vec<ActiveSession>, DomainError>;
}

/// Lists access requests (`tsh request ls -c <cluster>`).
pub trait RequestRepository: std::fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn list_requests(&self, ctx: &ClusterContext) -> Result<Vec<AccessRequest>, DomainError>;
}

/// Read-only administrative listings via `tctl get` (root cluster). Token
/// generation is interactive and handled outside this port.
pub trait AdminRepository: std::fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns [`DomainError`] (e.g. `TSH_NOT_FOUND`, insufficient privileges).
    fn list_users(&self) -> Result<Vec<AdminUser>, DomainError>;
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn list_roles(&self) -> Result<Vec<AdminRole>, DomainError>;
    /// Generate a join token of the given type(s). The returned
    /// token is a secret - display once, never log.
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn generate_token(&self, token_type: &TokenTypes) -> Result<GeneratedToken, DomainError>;

    /// List active provision (join) tokens (`tctl tokens ls`). For the `token`
    /// join method a token's name IS its secret, hence
    /// [`ProvisionToken::name`] is a [`crate::secret::SecretString`]: never log it.
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure. Defaults to "unsupported" so adapters
    /// without token management need not implement it.
    fn list_tokens(&self) -> Result<Vec<ProvisionToken>, DomainError> {
        Err(DomainError::BinaryNotFound)
    }

    /// Remove a provision token by its name (`tctl tokens rm <name>`); for the
    /// `token` join method the name is the join secret.
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn remove_token(&self, _token: &str) -> Result<(), DomainError> {
        Err(DomainError::BinaryNotFound)
    }

    /// Create a user with the given roles (`tctl users add`),
    /// returning the one-time setup [`InviteLink`] (a secret - show once).
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn add_user(&self, _user: &ResourceName, _roles: &RoleList) -> Result<InviteLink, DomainError> {
        Err(DomainError::BinaryNotFound)
    }

    /// Reset a user's password and second factors (`tctl users reset`),
    /// returning the one-time reset [`InviteLink`] (a secret - show once).
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn reset_user(&self, _user: &ResourceName) -> Result<InviteLink, DomainError> {
        Err(DomainError::BinaryNotFound)
    }

    /// List Machine ID bots (`tctl bots ls`). Read-only.
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn list_bots(&self) -> Result<Vec<Bot>, DomainError> {
        Err(DomainError::BinaryNotFound)
    }

    /// List connected agent instances (`tctl inventory ls`). Read-only.
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn list_instances(&self) -> Result<Vec<Instance>, DomainError> {
        Err(DomainError::BinaryNotFound)
    }

    /// Cheap capability probe: does the current identity have the rights to read
    /// `tctl`-scoped admin resources? The UI hides the whole Admin menu group
    /// when this is `false`. Defaults to probing via [`AdminRepository::list_roles`];
    /// adapters may override with a lighter-weight check.
    ///
    /// # Errors
    /// Returns [`DomainError`] when the probe itself could not run (e.g. the
    /// binary failed to spawn or timed out), as opposed to `Ok(false)` for an
    /// identity that simply lacks admin rights.
    fn can_admin(&self) -> Result<bool, DomainError> {
        Ok(self.list_roles().is_ok())
    }
}

/// Reads and re-selects the active session profile (`tsh status`, `tsh login
/// <cluster>` with a cached session). Interactive login/logout are handled
/// outside this gateway (terminal handed to `tsh`).
pub trait AuthGateway: std::fmt::Debug + Send + Sync {
    /// `Ok(None)` means no active session (logged out).
    ///
    /// # Errors
    /// Returns [`DomainError`] on parse failure or unexpected CLI error.
    fn status(&self) -> Result<Option<Profile>, DomainError>;

    /// List the current user's registered MFA devices (`tsh mfa ls`).
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn list_mfa_devices(&self) -> Result<Vec<MfaDevice>, DomainError> {
        Err(DomainError::BinaryNotFound)
    }

    /// Select the Teleport `cluster` (root or a trusted leaf under the current
    /// proxy) as the active profile (`tsh login <cluster>`, positional), so
    /// subsequent `tctl` calls - and `tsh` commands without a cluster flag -
    /// target it. `tctl` has no per-command cluster flag - it always talks to
    /// the *currently selected* cluster - so all-clusters admin (and scoped admin
    /// off the root) must re-select each cluster in turn.
    ///
    /// Non-interactive: succeeds only when a valid cached session for `cluster`
    /// already exists. An `Err(NotAuthenticated)` means a fresh interactive
    /// login is required (the UI hands the terminal to `tsh` for that).
    ///
    /// # Errors
    /// Returns [`DomainError::NotAuthenticated`] when no valid session exists for
    /// `cluster`, or another [`DomainError`] on spawn failure. Defaults to
    /// "unsupported" so gateways without profile control need not implement it.
    fn select_cluster(&self, _cluster: &ClusterName) -> Result<(), DomainError> {
        Err(DomainError::BinaryNotFound)
    }
}
