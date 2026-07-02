//! Use cases — one type per business intention. Each holds a port (injected as
//! a trait object) and orchestrates the domain. No business rules, no I/O here.

use domain::admin::{
    AdminRole, AdminUser, Bot, GeneratedToken, Instance, InviteLink, ProvisionToken,
};
use domain::cluster::{ClusterContext, ClusterTopology};
use domain::mfa::MfaDevice;
use domain::node::SshNode;
use domain::port::{
    AdminRepository, AppRepository, AuthGateway, ClusterRepository, DatabaseRepository,
    KubeRepository, NodeRepository, RecordingRepository, RequestRepository, SessionRepository,
};
use domain::profile::Profile;
use domain::recording::SessionRecording;
use domain::request::AccessRequest;
use domain::resource::{App, Database, KubeCluster};
use domain::session::ActiveSession;

use crate::error::AppError;

/// List the root/leaf topology.
#[derive(Debug)]
pub struct ListClusters<'a> {
    repo: &'a dyn ClusterRepository,
}

impl<'a> ListClusters<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn ClusterRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self) -> Result<ClusterTopology, AppError> {
        Ok(self.repo.list_clusters()?)
    }
}

/// List SSH nodes for a given cluster context. (Search/filtering is applied by
/// the presentation layer over the visible rows, not here.)
#[derive(Debug)]
pub struct ListNodes<'a> {
    repo: &'a dyn NodeRepository,
}

impl<'a> ListNodes<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn NodeRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<SshNode>, AppError> {
        Ok(self.repo.list_nodes(ctx)?)
    }
}

/// List Kubernetes clusters for a cluster context.
#[derive(Debug)]
pub struct ListKube<'a> {
    repo: &'a dyn KubeRepository,
}

impl<'a> ListKube<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn KubeRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<KubeCluster>, AppError> {
        Ok(self.repo.list_kube(ctx)?)
    }
}

/// List databases for a cluster context.
#[derive(Debug)]
pub struct ListDatabases<'a> {
    repo: &'a dyn DatabaseRepository,
}

impl<'a> ListDatabases<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn DatabaseRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<Database>, AppError> {
        Ok(self.repo.list_databases(ctx)?)
    }
}

/// List applications for a cluster context.
#[derive(Debug)]
pub struct ListApps<'a> {
    repo: &'a dyn AppRepository,
}

impl<'a> ListApps<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn AppRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<App>, AppError> {
        Ok(self.repo.list_apps(ctx)?)
    }
}

/// List Teleport users (read-only admin).
#[derive(Debug)]
pub struct ListUsers<'a> {
    repo: &'a dyn AdminRepository,
}

impl<'a> ListUsers<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn AdminRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self) -> Result<Vec<AdminUser>, AppError> {
        Ok(self.repo.list_users()?)
    }
}

/// Generate a join token (admin). The returned token is a secret — display
/// once, never log.
#[derive(Debug)]
pub struct GenerateToken<'a> {
    repo: &'a dyn AdminRepository,
}

impl<'a> GenerateToken<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn AdminRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self, token_type: &str) -> Result<GeneratedToken, AppError> {
        Ok(self.repo.generate_token(token_type)?)
    }
}

/// List active provision (join) tokens (admin). Each result carries a secret
/// value — the caller must move it into zeroizing storage and never log it.
#[derive(Debug)]
pub struct ListTokens<'a> {
    repo: &'a dyn AdminRepository,
}

impl<'a> ListTokens<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn AdminRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self) -> Result<Vec<ProvisionToken>, AppError> {
        Ok(self.repo.list_tokens()?)
    }
}

/// Remove a provision token by its (secret) value (admin).
#[derive(Debug)]
pub struct RemoveToken<'a> {
    repo: &'a dyn AdminRepository,
}

impl<'a> RemoveToken<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn AdminRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self, token: &str) -> Result<(), AppError> {
        Ok(self.repo.remove_token(token)?)
    }
}

/// Create a user with roles (admin). The returned invite URL is a secret —
/// display once, never log.
#[derive(Debug)]
pub struct AddUser<'a> {
    repo: &'a dyn AdminRepository,
}

impl<'a> AddUser<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn AdminRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self, user: &str, roles: &str) -> Result<InviteLink, AppError> {
        Ok(self.repo.add_user(user, roles)?)
    }
}

/// Reset a user's password and second factors (admin). The returned reset URL
/// is a secret — display once, never log.
#[derive(Debug)]
pub struct ResetUser<'a> {
    repo: &'a dyn AdminRepository,
}

impl<'a> ResetUser<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn AdminRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self, user: &str) -> Result<InviteLink, AppError> {
        Ok(self.repo.reset_user(user)?)
    }
}

/// List Machine ID bots (read-only admin).
#[derive(Debug)]
pub struct ListBots<'a> {
    repo: &'a dyn AdminRepository,
}

impl<'a> ListBots<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn AdminRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self) -> Result<Vec<Bot>, AppError> {
        Ok(self.repo.list_bots()?)
    }
}

/// List connected agent instances (read-only admin).
#[derive(Debug)]
pub struct ListInstances<'a> {
    repo: &'a dyn AdminRepository,
}

impl<'a> ListInstances<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn AdminRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self) -> Result<Vec<Instance>, AppError> {
        Ok(self.repo.list_instances()?)
    }
}

/// List Teleport roles (read-only admin).
#[derive(Debug)]
pub struct ListRoles<'a> {
    repo: &'a dyn AdminRepository,
}

impl<'a> ListRoles<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn AdminRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self) -> Result<Vec<AdminRole>, AppError> {
        Ok(self.repo.list_roles()?)
    }
}

/// Read the active session profile (`None` = logged out).
#[derive(Debug)]
pub struct GetStatus<'a> {
    gateway: &'a dyn AuthGateway,
}

impl<'a> GetStatus<'a> {
    #[must_use]
    pub fn new(gateway: &'a dyn AuthGateway) -> Self {
        Self { gateway }
    }

    /// # Errors
    /// Propagates gateway failures as [`AppError`].
    pub fn execute(&self) -> Result<Option<Profile>, AppError> {
        Ok(self.gateway.status()?)
    }
}

/// List recorded sessions for a cluster context.
#[derive(Debug)]
pub struct ListRecordings<'a> {
    repo: &'a dyn RecordingRepository,
}

impl<'a> ListRecordings<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn RecordingRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<SessionRecording>, AppError> {
        Ok(self.repo.list_recordings(ctx)?)
    }
}

/// List active sessions one can join, for a cluster context.
#[derive(Debug)]
pub struct ListSessions<'a> {
    repo: &'a dyn SessionRepository,
}

impl<'a> ListSessions<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn SessionRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<ActiveSession>, AppError> {
        Ok(self.repo.list_sessions(ctx)?)
    }
}

/// List the current user's registered MFA devices.
#[derive(Debug)]
pub struct ListMfaDevices<'a> {
    gateway: &'a dyn AuthGateway,
}

impl<'a> ListMfaDevices<'a> {
    #[must_use]
    pub fn new(gateway: &'a dyn AuthGateway) -> Self {
        Self { gateway }
    }

    /// # Errors
    /// Propagates gateway failures as [`AppError`].
    pub fn execute(&self) -> Result<Vec<MfaDevice>, AppError> {
        Ok(self.gateway.list_mfa_devices()?)
    }
}

/// List access requests for a cluster context.
#[derive(Debug)]
pub struct ListRequests<'a> {
    repo: &'a dyn RequestRepository,
}

impl<'a> ListRequests<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn RequestRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates repository failures as [`AppError`].
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<AccessRequest>, AppError> {
        Ok(self.repo.list_requests(ctx)?)
    }
}
