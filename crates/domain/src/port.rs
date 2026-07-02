//! Ports — traits the application depends on, implemented by infrastructure
//! adapters. The dependency rule points inward: domain declares, infra fulfils.

use crate::admin::{
    AdminRole, AdminUser, Bot, GeneratedToken, Instance, InviteLink, ProvisionToken,
};
use crate::capability::Capabilities;
use crate::cluster::{ClusterContext, ClusterTopology};
use crate::error::DomainError;
use crate::mfa::MfaDevice;
use crate::node::SshNode;
use crate::profile::Profile;
use crate::recording::SessionRecording;
use crate::request::AccessRequest;
use crate::resource::{App, Database, KubeCluster};
use crate::session::ActiveSession;

/// Probes which top-level commands the installed `tsh` supports, so the UI can
/// adapt to the actual binary (runtime detection, not compile-time `cfg`).
pub trait CapabilityProbe: std::fmt::Debug + Send + Sync {
    /// Best-effort: returns [`Capabilities::unknown`] (permissive) on any
    /// failure, never an error — a probe miss must not hide working features.
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
    /// Generate a join token of the given comma-separated type(s). The returned
    /// token is a secret — display once, never log.
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn generate_token(&self, token_type: &str) -> Result<GeneratedToken, DomainError>;

    /// List active provision (join) tokens (`tctl tokens ls`). Each carries its
    /// secret value — treat the result like a secret (zeroize, never log).
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure. Defaults to "unsupported" so adapters
    /// without token management need not implement it.
    fn list_tokens(&self) -> Result<Vec<ProvisionToken>, DomainError> {
        Err(DomainError::BinaryNotFound)
    }

    /// Remove a provision token by its (secret) value (`tctl tokens rm <token>`).
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn remove_token(&self, _token: &str) -> Result<(), DomainError> {
        Err(DomainError::BinaryNotFound)
    }

    /// Create a user with the given comma-separated roles (`tctl users add`),
    /// returning the one-time setup [`InviteLink`] (a secret — show once).
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn add_user(&self, _user: &str, _roles: &str) -> Result<InviteLink, DomainError> {
        Err(DomainError::BinaryNotFound)
    }

    /// Reset a user's password and second factors (`tctl users reset`),
    /// returning the one-time reset [`InviteLink`] (a secret — show once).
    ///
    /// # Errors
    /// Returns [`DomainError`] on failure.
    fn reset_user(&self, _user: &str) -> Result<InviteLink, DomainError> {
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
    #[must_use]
    fn can_admin(&self) -> bool {
        self.list_roles().is_ok()
    }

    /// Switch the active Teleport profile to `proxy` so subsequent `tctl` calls
    /// target that cluster's auth (`tsh login --proxy=<proxy>`). `tctl` has no
    /// per-command cluster flag — it always talks to the *currently logged-in*
    /// proxy — so all-clusters admin must re-select each cluster in turn.
    ///
    /// Non-interactive: succeeds only when a valid cached session for `proxy`
    /// already exists. An `Err(NotAuthenticated)` means a fresh interactive
    /// login is required (the UI hands the terminal to `tsh` for that).
    ///
    /// # Errors
    /// Returns [`DomainError::NotAuthenticated`] when no valid session exists for
    /// `proxy`, or another [`DomainError`] on spawn failure. Defaults to
    /// "unsupported" so adapters without profile control need not implement it.
    fn select_cluster(&self, _proxy: &str) -> Result<(), DomainError> {
        Err(DomainError::BinaryNotFound)
    }
}

/// Reads the active session profile (`tsh status`). Login/logout are
/// interactive and handled outside this gateway (terminal handed to `tsh`).
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
}
