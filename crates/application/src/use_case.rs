//! Use cases - one type per business intention.
//!
//! Each holds a port (injected as a trait object) and orchestrates the domain.
//! No business rules, no I/O here. Failures are the domain's own
//! [`DomainError`] vocabulary: this layer adds no error cases of its own, so it
//! does not wrap them.

use domain::admin::{
    AdminRole, AdminUser, Bot, GeneratedToken, Instance, InviteLink, ProvisionToken,
};
use domain::cluster::{ClusterContext, ClusterTopology};
use domain::error::DomainError;
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
use domain::value::{ClusterName, ResourceName, RoleList, TokenTypes};

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
    /// Propagates repository failures.
    pub fn execute(&self) -> Result<ClusterTopology, DomainError> {
        self.repo.list_clusters()
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
    /// Propagates repository failures.
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<SshNode>, DomainError> {
        self.repo.list_nodes(ctx)
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
    /// Propagates repository failures.
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<KubeCluster>, DomainError> {
        self.repo.list_kube(ctx)
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
    /// Propagates repository failures.
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<Database>, DomainError> {
        self.repo.list_databases(ctx)
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
    /// Propagates repository failures.
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<App>, DomainError> {
        self.repo.list_apps(ctx)
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
    /// Propagates repository failures.
    pub fn execute(&self) -> Result<Vec<AdminUser>, DomainError> {
        self.repo.list_users()
    }
}

/// Generate a join token (admin). The returned token is a secret - display
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
    /// Propagates repository failures.
    pub fn execute(&self, token_type: &TokenTypes) -> Result<GeneratedToken, DomainError> {
        self.repo.generate_token(token_type)
    }
}

/// List active provision (join) tokens (admin). A `token`-method token's name is
/// its join secret: it arrives as a `SecretString` (masked, wiped on drop) and
/// must never be logged.
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
    /// Propagates repository failures.
    pub fn execute(&self) -> Result<Vec<ProvisionToken>, DomainError> {
        self.repo.list_tokens()
    }
}

/// Remove a provision token by its name (admin); for the `token` join method the
/// name is the join secret.
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
    /// Propagates repository failures.
    pub fn execute(&self, token: &str) -> Result<(), DomainError> {
        self.repo.remove_token(token)
    }
}

/// Create a user with roles (admin). The returned invite URL is a secret -
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
    /// Propagates repository failures.
    pub fn execute(
        &self,
        user: &ResourceName,
        roles: &RoleList,
    ) -> Result<InviteLink, DomainError> {
        self.repo.add_user(user, roles)
    }
}

/// Reset a user's password and second factors (admin). The returned reset URL
/// is a secret - display once, never log.
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
    /// Propagates repository failures.
    pub fn execute(&self, user: &ResourceName) -> Result<InviteLink, DomainError> {
        self.repo.reset_user(user)
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
    /// Propagates repository failures.
    pub fn execute(&self) -> Result<Vec<Bot>, DomainError> {
        self.repo.list_bots()
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
    /// Propagates repository failures.
    pub fn execute(&self) -> Result<Vec<Instance>, DomainError> {
        self.repo.list_instances()
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
    /// Propagates repository failures.
    pub fn execute(&self) -> Result<Vec<AdminRole>, DomainError> {
        self.repo.list_roles()
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
    /// Propagates gateway failures.
    pub fn execute(&self) -> Result<Option<Profile>, DomainError> {
        self.gateway.status()
    }
}

/// Re-select `cluster` as the active profile (non-interactive, needs a cached
/// session), so a following `tctl` / flagless `tsh` call targets it.
#[derive(Debug)]
pub struct SelectCluster<'a> {
    gateway: &'a dyn AuthGateway,
}

impl<'a> SelectCluster<'a> {
    #[must_use]
    pub fn new(gateway: &'a dyn AuthGateway) -> Self {
        Self { gateway }
    }

    /// # Errors
    /// Propagates gateway failures (`NotAuthenticated` = a fresh interactive
    /// login is needed) as [`DomainError`].
    pub fn execute(&self, cluster: &ClusterName) -> Result<(), DomainError> {
        self.gateway.select_cluster(cluster)
    }
}

/// Probe whether the current identity has `tctl` admin rights: `Ok(false)` for
/// no rights, `Err` when the probe itself could not run.
#[derive(Debug)]
pub struct ProbeAdminRights<'a> {
    repo: &'a dyn AdminRepository,
}

impl<'a> ProbeAdminRights<'a> {
    #[must_use]
    pub fn new(repo: &'a dyn AdminRepository) -> Self {
        Self { repo }
    }

    /// # Errors
    /// Propagates a probe that could not run as [`DomainError`].
    pub fn execute(&self) -> Result<bool, DomainError> {
        self.repo.can_admin()
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
    /// Propagates repository failures.
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<SessionRecording>, DomainError> {
        self.repo.list_recordings(ctx)
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
    /// Propagates repository failures.
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<ActiveSession>, DomainError> {
        self.repo.list_sessions(ctx)
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
    /// Propagates gateway failures.
    pub fn execute(&self) -> Result<Vec<MfaDevice>, DomainError> {
        self.gateway.list_mfa_devices()
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
    /// Propagates repository failures.
    pub fn execute(&self, ctx: &ClusterContext) -> Result<Vec<AccessRequest>, DomainError> {
        self.repo.list_requests(ctx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use domain::cluster::{ClusterKind, ClusterStatus};
    use domain::secret::SecretString;
    use domain::value::Hostname;

    use super::*;

    fn ctx(name: &str) -> ClusterContext {
        ClusterContext {
            name: ClusterName::try_from(name).unwrap(),
            kind: ClusterKind::Leaf,
            status: ClusterStatus::Online,
        }
    }

    fn offline(ctx: &ClusterContext) -> DomainError {
        DomainError::ClusterOffline {
            cluster: ctx.name.to_string(),
        }
    }

    /// One fake for every cluster-scoped listing port: records the context each
    /// call was scoped to and fails with `ClusterOffline` when `fail` is set.
    #[derive(Debug, Default)]
    struct Scoped {
        seen: Mutex<Vec<String>>,
        fail: bool,
    }

    impl Scoped {
        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::default()
            }
        }
        fn list<T>(&self, ctx: &ClusterContext, rows: Vec<T>) -> Result<Vec<T>, DomainError> {
            self.seen.lock().unwrap().push(ctx.name.to_string());
            if self.fail {
                Err(offline(ctx))
            } else {
                Ok(rows)
            }
        }
        fn seen(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl NodeRepository for Scoped {
        fn list_nodes(&self, ctx: &ClusterContext) -> Result<Vec<SshNode>, DomainError> {
            let node = SshNode {
                id: "uuid-1".to_owned(),
                hostname: Hostname::try_from("web-1").unwrap(),
                address: String::new(),
                labels: Vec::new(),
            };
            self.list(ctx, vec![node])
        }
    }
    impl KubeRepository for Scoped {
        fn list_kube(&self, ctx: &ClusterContext) -> Result<Vec<KubeCluster>, DomainError> {
            self.list(ctx, Vec::new())
        }
    }
    impl DatabaseRepository for Scoped {
        fn list_databases(&self, ctx: &ClusterContext) -> Result<Vec<Database>, DomainError> {
            self.list(ctx, Vec::new())
        }
    }
    impl AppRepository for Scoped {
        fn list_apps(&self, ctx: &ClusterContext) -> Result<Vec<App>, DomainError> {
            self.list(ctx, Vec::new())
        }
    }
    impl RecordingRepository for Scoped {
        fn list_recordings(
            &self,
            ctx: &ClusterContext,
        ) -> Result<Vec<SessionRecording>, DomainError> {
            self.list(ctx, Vec::new())
        }
    }
    impl SessionRepository for Scoped {
        fn list_sessions(&self, ctx: &ClusterContext) -> Result<Vec<ActiveSession>, DomainError> {
            self.list(ctx, Vec::new())
        }
    }
    impl RequestRepository for Scoped {
        fn list_requests(&self, ctx: &ClusterContext) -> Result<Vec<AccessRequest>, DomainError> {
            self.list(ctx, Vec::new())
        }
    }

    #[test]
    fn scoped_listings_pass_the_context_through() {
        let repo = Scoped::default();
        let c = ctx("leaf.example.com");
        let nodes = ListNodes::new(&repo).execute(&c).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].hostname.as_str(), "web-1");
        ListKube::new(&repo).execute(&c).unwrap();
        ListDatabases::new(&repo).execute(&c).unwrap();
        ListApps::new(&repo).execute(&c).unwrap();
        ListRecordings::new(&repo).execute(&c).unwrap();
        ListSessions::new(&repo).execute(&c).unwrap();
        ListRequests::new(&repo).execute(&c).unwrap();
        assert_eq!(repo.seen(), vec!["leaf.example.com"; 7]);
    }

    #[test]
    fn scoped_listings_propagate_the_domain_error_unchanged() {
        let repo = Scoped::failing();
        let c = ctx("down");
        let is_offline = |e: DomainError| matches!(e, DomainError::ClusterOffline { cluster } if cluster == "down");
        assert!(is_offline(ListNodes::new(&repo).execute(&c).unwrap_err()));
        assert!(is_offline(ListKube::new(&repo).execute(&c).unwrap_err()));
        assert!(is_offline(
            ListDatabases::new(&repo).execute(&c).unwrap_err()
        ));
        assert!(is_offline(ListApps::new(&repo).execute(&c).unwrap_err()));
        assert!(is_offline(
            ListRecordings::new(&repo).execute(&c).unwrap_err()
        ));
        assert!(is_offline(
            ListSessions::new(&repo).execute(&c).unwrap_err()
        ));
        assert!(is_offline(
            ListRequests::new(&repo).execute(&c).unwrap_err()
        ));
    }

    #[derive(Debug)]
    struct Clusters(Result<(), ()>);

    impl ClusterRepository for Clusters {
        fn list_clusters(&self) -> Result<ClusterTopology, DomainError> {
            self.0.map_err(|()| DomainError::NotAuthenticated)?;
            let mut root = ctx("root");
            root.kind = ClusterKind::Root;
            ClusterTopology::new(vec![root, ctx("leaf")], None)
        }
    }

    #[test]
    fn list_clusters_returns_the_repository_topology() {
        let topo = ListClusters::new(&Clusters(Ok(()))).execute().unwrap();
        assert_eq!(topo.root().name.as_str(), "root");
        assert_eq!(topo.all().len(), 2);
        let err = ListClusters::new(&Clusters(Err(()))).execute().unwrap_err();
        assert!(matches!(err, DomainError::NotAuthenticated));
    }

    /// Full admin fake: records every write with its arguments.
    #[derive(Debug, Default)]
    struct Admin {
        calls: Mutex<Vec<String>>,
        admin: bool,
    }

    impl Admin {
        fn log(&self, call: String) {
            self.calls.lock().unwrap().push(call);
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl AdminRepository for Admin {
        fn list_users(&self) -> Result<Vec<AdminUser>, DomainError> {
            Ok(vec![AdminUser {
                name: ResourceName::try_from("alice").unwrap(),
                roles: vec!["access".to_owned()],
                labels: Vec::new(),
            }])
        }
        fn list_roles(&self) -> Result<Vec<AdminRole>, DomainError> {
            Ok(Vec::new())
        }
        fn generate_token(&self, token_type: &TokenTypes) -> Result<GeneratedToken, DomainError> {
            self.log(format!("generate {token_type}"));
            Ok(GeneratedToken {
                token: SecretString::new("s3cr3t".to_owned()),
                roles: token_type.as_str().split(',').map(str::to_owned).collect(),
                expires: String::new(),
                ca_pins: Vec::new(),
            })
        }
        fn list_tokens(&self) -> Result<Vec<ProvisionToken>, DomainError> {
            Ok(Vec::new())
        }
        fn remove_token(&self, token: &str) -> Result<(), DomainError> {
            self.log(format!("rm {token}"));
            Ok(())
        }
        fn add_user(
            &self,
            user: &ResourceName,
            roles: &RoleList,
        ) -> Result<InviteLink, DomainError> {
            self.log(format!("add {user} {roles}"));
            Ok(InviteLink {
                user: user.to_string(),
                url: SecretString::new("https://proxy/web/invite/x".to_owned()),
            })
        }
        fn reset_user(&self, user: &ResourceName) -> Result<InviteLink, DomainError> {
            self.log(format!("reset {user}"));
            Ok(InviteLink {
                user: user.to_string(),
                url: SecretString::new("https://proxy/web/reset/x".to_owned()),
            })
        }
        fn list_bots(&self) -> Result<Vec<Bot>, DomainError> {
            Ok(Vec::new())
        }
        fn list_instances(&self) -> Result<Vec<Instance>, DomainError> {
            Ok(Vec::new())
        }
        fn can_admin(&self) -> Result<bool, DomainError> {
            Ok(self.admin)
        }
    }

    #[test]
    fn admin_writes_forward_their_arguments() {
        let repo = Admin::default();
        let user = ResourceName::try_from("bob@example.com").unwrap();
        let roles = RoleList::try_from("access,editor").unwrap();

        let token = GenerateToken::new(&repo)
            .execute(&TokenTypes::try_from("node,app").unwrap())
            .unwrap();
        assert_eq!(token.token.expose(), "s3cr3t");
        assert_eq!(token.roles, ["node", "app"]);

        let invite = AddUser::new(&repo).execute(&user, &roles).unwrap();
        assert_eq!(invite.user, "bob@example.com");
        let reset = ResetUser::new(&repo).execute(&user).unwrap();
        assert_eq!(reset.url.expose(), "https://proxy/web/reset/x");
        RemoveToken::new(&repo).execute("tok-1").unwrap();

        assert_eq!(
            repo.calls(),
            [
                "generate node,app",
                "add bob@example.com access,editor",
                "reset bob@example.com",
                "rm tok-1",
            ]
        );
    }

    #[test]
    fn admin_listings_and_probe_delegate_to_the_repository() {
        let repo = Admin {
            admin: true,
            ..Admin::default()
        };
        let users = ListUsers::new(&repo).execute().unwrap();
        assert_eq!(users[0].name.as_str(), "alice");
        assert!(ListRoles::new(&repo).execute().unwrap().is_empty());
        assert!(ListTokens::new(&repo).execute().unwrap().is_empty());
        assert!(ListBots::new(&repo).execute().unwrap().is_empty());
        assert!(ListInstances::new(&repo).execute().unwrap().is_empty());
        assert!(ProbeAdminRights::new(&repo).execute().unwrap());
        assert!(!ProbeAdminRights::new(&Admin::default()).execute().unwrap());
        // Listings are reads: nothing was recorded as a write.
        assert!(repo.calls().is_empty());
    }

    /// Minimal admin adapter that only implements the required methods, so the
    /// port's defaults are exercised through the use cases.
    #[derive(Debug)]
    struct MinimalAdmin {
        roles_ok: bool,
    }

    impl AdminRepository for MinimalAdmin {
        fn list_users(&self) -> Result<Vec<AdminUser>, DomainError> {
            Ok(Vec::new())
        }
        fn list_roles(&self) -> Result<Vec<AdminRole>, DomainError> {
            if self.roles_ok {
                Ok(Vec::new())
            } else {
                Err(DomainError::NotAuthenticated)
            }
        }
        fn generate_token(&self, _: &TokenTypes) -> Result<GeneratedToken, DomainError> {
            Err(DomainError::BinaryNotFound)
        }
    }

    #[test]
    fn optional_admin_operations_default_to_unsupported() {
        let repo = MinimalAdmin { roles_ok: true };
        let user = ResourceName::try_from("bob").unwrap();
        let roles = RoleList::try_from("access").unwrap();
        let unsupported = |e: DomainError| matches!(e, DomainError::BinaryNotFound);
        assert!(unsupported(ListTokens::new(&repo).execute().unwrap_err()));
        assert!(unsupported(
            RemoveToken::new(&repo).execute("t").unwrap_err()
        ));
        assert!(unsupported(
            AddUser::new(&repo).execute(&user, &roles).unwrap_err()
        ));
        assert!(unsupported(
            ResetUser::new(&repo).execute(&user).unwrap_err()
        ));
        assert!(unsupported(ListBots::new(&repo).execute().unwrap_err()));
        assert!(unsupported(
            ListInstances::new(&repo).execute().unwrap_err()
        ));
    }

    #[test]
    fn default_admin_probe_falls_back_to_listing_roles() {
        assert!(
            ProbeAdminRights::new(&MinimalAdmin { roles_ok: true })
                .execute()
                .unwrap()
        );
        // A failed role listing reads as "no admin", not as a probe error.
        assert!(
            !ProbeAdminRights::new(&MinimalAdmin { roles_ok: false })
                .execute()
                .unwrap()
        );
    }

    #[derive(Debug, Default)]
    struct Gateway {
        logged_in: bool,
        selected: Mutex<Vec<String>>,
    }

    impl AuthGateway for Gateway {
        fn status(&self) -> Result<Option<Profile>, DomainError> {
            Ok(self.logged_in.then(|| Profile {
                username: "alice".to_owned(),
                cluster: "root".to_owned(),
                roles: Vec::new(),
                logins: vec!["root".to_owned()],
                kubernetes_enabled: false,
                kubernetes_users: Vec::new(),
                valid_until: String::new(),
            }))
        }
        fn list_mfa_devices(&self) -> Result<Vec<MfaDevice>, DomainError> {
            Ok(vec![MfaDevice {
                name: "yubi".to_owned(),
                kind: "webauthn".to_owned(),
                added: String::new(),
                last_used: String::new(),
            }])
        }
        fn select_cluster(&self, cluster: &ClusterName) -> Result<(), DomainError> {
            if cluster.as_str() == "expired" {
                return Err(DomainError::NotAuthenticated);
            }
            self.selected.lock().unwrap().push(cluster.to_string());
            Ok(())
        }
    }

    #[test]
    fn get_status_maps_logged_out_to_none() {
        let gw = Gateway {
            logged_in: true,
            ..Gateway::default()
        };
        let profile = GetStatus::new(&gw).execute().unwrap().unwrap();
        assert_eq!(profile.username, "alice");
        assert!(
            GetStatus::new(&Gateway::default())
                .execute()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn select_cluster_forwards_the_name_and_its_auth_error() {
        let gw = Gateway::default();
        SelectCluster::new(&gw)
            .execute(&ClusterName::try_from("leaf").unwrap())
            .unwrap();
        assert_eq!(*gw.selected.lock().unwrap(), ["leaf"]);
        let err = SelectCluster::new(&gw)
            .execute(&ClusterName::try_from("expired").unwrap())
            .unwrap_err();
        assert!(matches!(err, DomainError::NotAuthenticated));
        assert_eq!(gw.selected.lock().unwrap().len(), 1);
    }

    #[test]
    fn list_mfa_devices_delegates_to_the_gateway() {
        let devices = ListMfaDevices::new(&Gateway::default()).execute().unwrap();
        assert_eq!(devices[0].name, "yubi");
    }

    #[derive(Debug)]
    struct StatusOnly;

    impl AuthGateway for StatusOnly {
        fn status(&self) -> Result<Option<Profile>, DomainError> {
            Ok(None)
        }
    }

    #[test]
    fn optional_gateway_operations_default_to_unsupported() {
        assert!(matches!(
            ListMfaDevices::new(&StatusOnly).execute().unwrap_err(),
            DomainError::BinaryNotFound
        ));
        assert!(matches!(
            SelectCluster::new(&StatusOnly)
                .execute(&ClusterName::try_from("root").unwrap())
                .unwrap_err(),
            DomainError::BinaryNotFound
        ));
    }
}
