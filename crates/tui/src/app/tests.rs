use super::*;
use domain::cluster::{ClusterContext, ClusterKind, ClusterStatus, ClusterTopology};
use domain::error::DomainError;
use domain::value::{ClusterName, Hostname};
use ratatui::crossterm::event::KeyEvent;

#[derive(Debug)]
struct FakeClusters;
impl ClusterRepository for FakeClusters {
    fn list_clusters(&self) -> Result<ClusterTopology, DomainError> {
        let ctx = |n: &str, k| ClusterContext {
            name: ClusterName::try_from(n).unwrap(),
            kind: k,
            status: ClusterStatus::Online,
        };
        ClusterTopology::new(
            vec![
                ctx("root.example", ClusterKind::Root),
                ctx("leaf.example", ClusterKind::Leaf),
            ],
            None,
        )
    }
}

#[derive(Debug)]
struct FakeNodes;
impl NodeRepository for FakeNodes {
    fn list_nodes(&self, _ctx: &ClusterContext) -> Result<Vec<SshNode>, DomainError> {
        let node = |h: &str, label: &str| SshNode {
            id: h.to_owned(),
            hostname: Hostname::try_from(h).unwrap(),
            address: String::new(),
            labels: vec![("env".to_owned(), label.to_owned())],
        };
        Ok(vec![
            node("web-01", "prod"),
            node("web-02", "staging"),
            node("db-01", "prod"),
        ])
    }
}

#[derive(Debug)]
struct FakeKube;
impl KubeRepository for FakeKube {
    fn list_kube(&self, _ctx: &ClusterContext) -> Result<Vec<KubeCluster>, DomainError> {
        Ok(vec![KubeCluster {
            name: domain::value::ResourceName::try_from("k8s-prod").unwrap(),
            labels: vec![],
        }])
    }
}

#[derive(Debug)]
struct FakeDb;
impl DatabaseRepository for FakeDb {
    fn list_databases(&self, _ctx: &ClusterContext) -> Result<Vec<Database>, DomainError> {
        Ok(vec![Database {
            name: domain::value::ResourceName::try_from("pg-main").unwrap(),
            protocol: "postgres".to_owned(),
            uri: "pg.internal:5432".to_owned(),
            labels: vec![],
        }])
    }
}

#[derive(Debug)]
struct FakeApps;
impl AppRepository for FakeApps {
    fn list_apps(&self, _ctx: &ClusterContext) -> Result<Vec<AppResource>, DomainError> {
        Ok(vec![AppResource {
            name: domain::value::ResourceName::try_from("argocd").unwrap(),
            uri: "https://argo.example".to_owned(),
            public_addr: "argocd.example".to_owned(),
            labels: vec![],
        }])
    }
}

#[derive(Debug)]
struct FakeRequests;
impl RequestRepository for FakeRequests {
    fn list_requests(&self, _ctx: &ClusterContext) -> Result<Vec<AccessRequest>, DomainError> {
        use domain::request::RequestState;
        use domain::value::RequestId;
        Ok(vec![AccessRequest {
            id: RequestId::try_from("req-0001").unwrap(),
            user: "maxime".to_owned(),
            roles: vec!["admin".to_owned()],
            state: RequestState::Pending,
            reason: "test".to_owned(),
            created: String::new(),
        }])
    }
}

#[derive(Debug)]
struct FakeRecordings;
impl RecordingRepository for FakeRecordings {
    fn list_recordings(&self, _ctx: &ClusterContext) -> Result<Vec<SessionRecording>, DomainError> {
        Ok(vec![SessionRecording {
            sid: "sess-0001".to_owned(),
            started: "2026-06-29T16:24:57Z".to_owned(),
            duration: "5m29s".to_owned(),
            user: "alice".to_owned(),
            server: "node-01".to_owned(),
            proto: "ssh".to_owned(),
        }])
    }
}

#[derive(Debug)]
struct FakeSessions;
impl SessionRepository for FakeSessions {
    fn list_sessions(&self, _ctx: &ClusterContext) -> Result<Vec<ActiveSession>, DomainError> {
        Ok(vec![ActiveSession {
            id: "live-0001".to_owned(),
            kind: "ssh".to_owned(),
            host: "node-01".to_owned(),
            login: "admin".to_owned(),
            started_by: "alice".to_owned(),
            created: "2026-06-30T05:50:30Z".to_owned(),
        }])
    }
}

#[derive(Debug)]
struct FakeAdmin;
impl AdminRepository for FakeAdmin {
    fn list_users(&self) -> Result<Vec<AdminUser>, DomainError> {
        use domain::value::ResourceName;
        Ok(vec![AdminUser {
            name: ResourceName::try_from("alice").unwrap(),
            roles: vec!["access".to_owned()],
            labels: vec![],
        }])
    }
    fn list_roles(&self) -> Result<Vec<AdminRole>, DomainError> {
        Ok(vec![])
    }
    fn generate_token(&self, token_type: &str) -> Result<GeneratedToken, DomainError> {
        Ok(GeneratedToken {
            token: "secret-token-value".to_owned(),
            roles: vec![token_type.to_owned()],
            expires: "2026-06-29T00:00:00Z".to_owned(),
            ca_pins: vec!["sha256:abc".to_owned()],
        })
    }
    fn list_tokens(&self) -> Result<Vec<ProvisionToken>, DomainError> {
        Ok(vec![
            ProvisionToken {
                name: "tbot-ci".to_owned(),
                types: vec!["Bot".to_owned()],
                labels: vec![("team".to_owned(), "ci".to_owned())],
                expires: String::new(),
            },
            ProvisionToken {
                name: "node-join".to_owned(),
                types: vec!["Node".to_owned()],
                labels: vec![],
                expires: "2026-07-02".to_owned(),
            },
        ])
    }
    fn remove_token(&self, _token: &str) -> Result<(), DomainError> {
        Ok(())
    }
    fn add_user(&self, user: &str, _roles: &str) -> Result<InviteLink, DomainError> {
        Ok(InviteLink {
            user: user.to_owned(),
            url: "https://proxy.example/web/invite/secret123".to_owned(),
        })
    }
    fn reset_user(&self, user: &str) -> Result<InviteLink, DomainError> {
        Ok(InviteLink {
            user: user.to_owned(),
            url: "https://proxy.example/web/reset/secret456".to_owned(),
        })
    }
    fn list_bots(&self) -> Result<Vec<Bot>, DomainError> {
        Ok(vec![Bot {
            name: domain::value::ResourceName::try_from("ci").unwrap(),
            roles: vec!["lab".to_owned()],
            user: "bot-ci".to_owned(),
            max_ttl_secs: 43200,
            labels: vec![],
        }])
    }
    fn list_instances(&self) -> Result<Vec<Instance>, DomainError> {
        Ok(vec![Instance {
            server_id: "uuid-1".to_owned(),
            hostname: "agent-01".to_owned(),
            version: "v18.7.3".to_owned(),
            services: vec!["Node".to_owned()],
            last_seen: "2026-06-29T16:28:30Z".to_owned(),
        }])
    }
}

#[derive(Debug)]
struct FakeAuth;
impl AuthGateway for FakeAuth {
    fn list_mfa_devices(&self) -> Result<Vec<MfaDevice>, DomainError> {
        Ok(vec![MfaDevice {
            name: "yubikey".to_owned(),
            kind: "webauthn".to_owned(),
            added: "2025-10-01".to_owned(),
            last_used: "2026-06-29".to_owned(),
        }])
    }
    fn status(&self) -> Result<Option<Profile>, DomainError> {
        Ok(Some(Profile {
            username: "maxime".to_owned(),
            cluster: "root.example".to_owned(),
            roles: vec!["admin".to_owned()],
            logins: vec!["root".to_owned(), "admin".to_owned()],
            kubernetes_enabled: true,
            kubernetes_users: vec!["kube-admin".to_owned()],
            valid_until: "2026-06-29T10:00:00Z".to_owned(),
        }))
    }
}

/// Admin repo that denies every call — models a user without admin rights
/// (default `can_admin` probes `list_roles`, which errors here).
#[derive(Debug)]
struct NonAdmin;
impl AdminRepository for NonAdmin {
    fn list_users(&self) -> Result<Vec<AdminUser>, DomainError> {
        Err(DomainError::InvalidValue { field: "denied" })
    }
    fn list_roles(&self) -> Result<Vec<AdminRole>, DomainError> {
        Err(DomainError::InvalidValue { field: "denied" })
    }
    fn generate_token(&self, _token_type: &str) -> Result<GeneratedToken, DomainError> {
        Err(DomainError::InvalidValue { field: "denied" })
    }
}

fn test_app() -> App {
    test_app_with_admin(Box::new(FakeAdmin))
}

fn test_app_with_admin(admin: Box<dyn AdminRepository>) -> App {
    let logger = NdjsonLogger::new(PathBuf::from("/dev/null"));
    let repos = Repositories {
        clusters: Box::new(FakeClusters),
        nodes: Box::new(FakeNodes),
        kube: Box::new(FakeKube),
        databases: Box::new(FakeDb),
        apps: Box::new(FakeApps),
        requests: Box::new(FakeRequests),
        recordings: Box::new(FakeRecordings),
        sessions: Box::new(FakeSessions),
        auth: Box::new(FakeAuth),
        admin,
    };
    // `synchronous = true`: jobs run inline so tests are deterministic.
    let settings = Settings {
        kube_tools: vec!["shell".to_owned(), "k9s".to_owned()],
        login_proxy: None,
        login_user: None,
        ..Settings::default()
    };
    let mut app = App::new(
        repos,
        logger,
        "test".to_owned(),
        PathBuf::from("tsh"),
        settings,
        true,
    );
    app.bootstrap();
    app
}

fn press(c: char) -> KeyEvent {
    KeyEvent::from(KeyCode::Char(c))
}

#[test]
fn bootstrap_loads_topology_and_nodes() {
    let app = test_app();
    assert_eq!(app.topology.as_ref().unwrap().leaves().count(), 1);
    assert_eq!(app.nodes.len(), 3);
    assert_eq!(app.visible.len(), 3);
}

#[test]
fn search_filters_visible_nodes() {
    let mut app = test_app(); // hosts: web-01, web-02, db-01
    app.on_key(press('/'));
    // Search is hostname-only: "web" matches web-01/web-02, not labels.
    for c in "web".chars() {
        app.on_key(press(c));
    }
    assert_eq!(app.visible.len(), 2);
    // "prod" is a label value -> no hostname match.
    app.on_key(KeyEvent::from(KeyCode::Esc));
    app.on_key(press('/'));
    for c in "prod".chars() {
        app.on_key(press(c));
    }
    assert_eq!(app.visible.len(), 0);
    app.on_key(KeyEvent::from(KeyCode::Esc));
    assert_eq!(app.visible.len(), 3);
}

#[test]
fn paste_inserts_text_and_drops_control_chars() {
    let mut app = test_app(); // hosts: web-01, web-02, db-01
    // A paste outside a text field is ignored (forwarding chars could run 'q'/'r').
    app.on_paste("web");
    assert!(matches!(app.mode, Mode::Normal));
    assert_eq!(app.visible.len(), 3);
    // In search, a multi-line paste lands in the query with the newline dropped —
    // staying in Search (not submitted) proves the '\n' didn't act as Enter.
    app.on_key(press('/'));
    app.on_paste("we\nb");
    assert!(matches!(app.mode, Mode::Search));
    assert_eq!(app.visible.len(), 2); // "web" matches web-01/web-02, not db-01
}

#[test]
fn ssh_with_multiple_logins_opens_user_picker() {
    let mut app = test_app();
    // Two logins available -> dropdown, not direct connect.
    app.on_key(KeyEvent::from(KeyCode::Enter));
    assert!(matches!(app.mode, Mode::UserPicker(_)));
    assert_eq!(app.user_choices, vec!["root", "admin"]);
    // pick the second login then connect
    app.on_key(press('j'));
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::Run { args, .. } => {
            assert_eq!(args, vec!["ssh", "-c", "root.example", "admin@web-01"]);
        }
        other => panic!("expected Run, got {other:?}"),
    }
    assert_eq!(app.mode, Mode::Normal);
}

#[test]
fn apps_enter_requests_open_app() {
    let mut app = test_app();
    app.on_key(press('4')); // -> Apps
    assert_eq!(app.tab, Tab::Apps);
    assert_eq!(app.apps.len(), 1);
    // Enter opens the port prompt; a typed port is carried through.
    app.on_key(KeyEvent::from(KeyCode::Enter));
    assert!(matches!(app.mode, Mode::AppPort { .. }));
    for c in "8080".chars() {
        app.on_key(press(c));
    }
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::OpenApp {
            name,
            cluster,
            port,
        } => {
            assert_eq!(name, "argocd");
            assert_eq!(cluster, "root.example");
            assert_eq!(port, Some(8080));
        }
        other => panic!("expected OpenApp, got {other:?}"),
    }
}

#[test]
fn app_port_blank_means_random() {
    let mut app = test_app();
    app.on_key(press('4')); // -> Apps
    app.on_key(KeyEvent::from(KeyCode::Enter)); // -> port prompt
    assert!(matches!(app.mode, Mode::AppPort { .. }));
    // Blank entry => random free port (None), proxy still opens.
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::OpenApp { port, .. } => assert_eq!(port, None),
        other => panic!("expected OpenApp, got {other:?}"),
    }
    assert_eq!(app.mode, Mode::Normal);
}

#[test]
fn db_prompts_user_then_connects() {
    let mut app = test_app();
    app.on_key(press('3')); // -> Databases
    assert_eq!(app.tab, Tab::Db);
    assert_eq!(app.dbs.len(), 1);
    app.on_key(KeyEvent::from(KeyCode::Enter)); // -> db user prompt
    assert!(matches!(app.mode, Mode::DbUser { .. }));
    for c in "readonly".chars() {
        app.on_key(press(c));
    }
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::Run { args, .. } => assert_eq!(
            args,
            vec![
                "db",
                "connect",
                "-c",
                "root.example",
                "pg-main",
                "--db-user=readonly"
            ]
        ),
        other => panic!("expected Run, got {other:?}"),
    }
    assert_eq!(app.mode, Mode::Normal);
}

#[test]
fn db_blank_user_connects_with_default() {
    let mut app = test_app();
    app.on_key(press('3'));
    app.on_key(KeyEvent::from(KeyCode::Enter)); // db user prompt
    // blank user -> no --db-user flag
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::Run { args, .. } => {
            assert_eq!(args, vec!["db", "connect", "-c", "root.example", "pg-main"]);
        }
        other => panic!("expected Run, got {other:?}"),
    }
}

#[test]
fn kube_picks_user_then_tool_then_opens_auto_proxy() {
    let mut app = test_app(); // 1 kube user, tools = [shell, k9s]
    app.on_key(KeyEvent::from(KeyCode::Tab)); // Ssh -> Kube
    assert_eq!(app.tab, Tab::Kube);
    // One kube user -> skip user picker; two tools -> tool picker opens.
    app.on_key(KeyEvent::from(KeyCode::Enter));
    assert!(matches!(app.mode, Mode::ToolPicker { .. }));
    assert_eq!(app.tool_choices, vec!["shell", "k9s"]);
    // pick k9s (second) -> background proxy + clean handoff (OpenKube)
    app.on_key(press('j'));
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::OpenKube {
            kube,
            cluster,
            user,
            tool,
        } => {
            assert_eq!(kube, "k8s-prod");
            assert_eq!(cluster, "root.example");
            assert_eq!(user.as_deref(), Some("kube-admin"));
            assert_eq!(tool, "k9s");
        }
        other => panic!("expected OpenKube, got {other:?}"),
    }
    assert_eq!(app.mode, Mode::Normal);
}

fn async_app() -> App {
    let logger = NdjsonLogger::new(PathBuf::from("/dev/null"));
    let repos = Repositories {
        clusters: Box::new(FakeClusters),
        nodes: Box::new(FakeNodes),
        kube: Box::new(FakeKube),
        databases: Box::new(FakeDb),
        apps: Box::new(FakeApps),
        requests: Box::new(FakeRequests),
        recordings: Box::new(FakeRecordings),
        sessions: Box::new(FakeSessions),
        auth: Box::new(FakeAuth),
        admin: Box::new(FakeAdmin),
    };
    App::new(
        repos,
        logger,
        "t".to_owned(),
        PathBuf::from("tsh"),
        Settings {
            kube_tools: vec!["shell".to_owned()],
            login_proxy: None,
            login_user: None,
            ..Settings::default()
        },
        false,
    )
}

use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct CountingNodes(std::sync::Arc<AtomicUsize>);
impl NodeRepository for CountingNodes {
    fn list_nodes(&self, _ctx: &ClusterContext) -> Result<Vec<SshNode>, DomainError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![SshNode {
            id: "n".to_owned(),
            hostname: Hostname::try_from("web-01").unwrap(),
            address: String::new(),
            labels: vec![],
        }])
    }
}

#[derive(Debug)]
struct CountingAdmin(std::sync::Arc<AtomicUsize>);
impl AdminRepository for CountingAdmin {
    fn list_users(&self) -> Result<Vec<AdminUser>, DomainError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![AdminUser {
            name: domain::value::ResourceName::try_from("alice").unwrap(),
            roles: vec![],
            labels: vec![],
        }])
    }
    fn list_roles(&self) -> Result<Vec<AdminRole>, DomainError> {
        Ok(vec![]) // also the default `can_admin` probe → admin allowed
    }
    fn generate_token(&self, _t: &str) -> Result<GeneratedToken, DomainError> {
        Err(DomainError::BinaryNotFound)
    }
    // A working profile switch lets the all-clusters admin fan-out reach
    // every cluster (otherwise each would read as login-required).
    fn select_cluster(&self, _proxy: &str) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Admin that only has a live session for the root cluster; every leaf
/// requires an interactive login (exercises the login-required placeholder).
#[derive(Debug)]
struct RootOnlyAdmin;
impl AdminRepository for RootOnlyAdmin {
    fn list_users(&self) -> Result<Vec<AdminUser>, DomainError> {
        Ok(vec![AdminUser {
            name: domain::value::ResourceName::try_from("alice").unwrap(),
            roles: vec![],
            labels: vec![],
        }])
    }
    fn list_roles(&self) -> Result<Vec<AdminRole>, DomainError> {
        Ok(vec![])
    }
    fn generate_token(&self, _t: &str) -> Result<GeneratedToken, DomainError> {
        Err(DomainError::BinaryNotFound)
    }
    fn select_cluster(&self, proxy: &str) -> Result<(), DomainError> {
        if proxy == "root.example" {
            Ok(())
        } else {
            Err(DomainError::NotAuthenticated)
        }
    }
}

#[test]
fn admin_tab_aggregates_across_clusters() {
    let counter = std::sync::Arc::new(AtomicUsize::new(0));
    let mut app = test_app_with_admin(Box::new(CountingAdmin(counter.clone())));
    assert!(app.admin_allowed);
    // Ignore the bootstrap prefetch warm-up; count only what follows.
    counter.store(0, Ordering::SeqCst);
    // Enter all-clusters mode (c, ↑ to "All clusters", Enter).
    app.on_key(press('c'));
    app.on_key(KeyEvent::from(KeyCode::Up));
    app.on_key(KeyEvent::from(KeyCode::Enter));
    assert!(app.aggregate);
    // Users fans out across both online clusters (root + leaf), each row tagged
    // with its cluster, none login-required (the fake profile switch succeeds).
    // Root's rows were already loaded scoped (`tctl` targets the root proxy), so
    // they're reused from memory — only the *leaf* triggers a `list_users`.
    app.on_key(press('5'));
    assert_eq!(app.tab, Tab::Users);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(app.agg_rows.len(), 2);
    assert!(app.agg_rows.iter().all(|r| !r.login_required));
    assert!(app.agg_rows.iter().any(|r| r.cluster == "root.example"));
    assert!(app.agg_rows.iter().any(|r| r.cluster == "leaf.example"));
    // Leave and return — the fan-out is cached per tab (no refetch).
    app.on_key(press('1')); // SSH (aggregated)
    app.on_key(press('5')); // Users again
    assert!(app.aggregate, "still in all-clusters view");
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    // `r` drops both the scoped and aggregate caches, so it re-fans every
    // cluster (root can no longer be reused): one call per cluster.
    app.on_key(press('r'));
    assert_eq!(counter.load(Ordering::SeqCst), 3);
}

#[test]
fn admin_aggregate_marks_unauthenticated_clusters_login_required() {
    let mut app = test_app_with_admin(Box::new(RootOnlyAdmin));
    app.on_key(press('c'));
    app.on_key(KeyEvent::from(KeyCode::Up));
    app.on_key(KeyEvent::from(KeyCode::Enter));
    assert!(app.aggregate);
    app.on_key(press('5')); // Users
    assert_eq!(app.tab, Tab::Users);
    // root.example → one real row; leaf.example → a login-required placeholder.
    assert_eq!(app.agg_rows.len(), 2);
    let root = app
        .agg_rows
        .iter()
        .find(|r| r.cluster == "root.example")
        .unwrap();
    assert!(!root.login_required);
    let leaf = app
        .agg_rows
        .iter()
        .find(|r| r.cluster == "leaf.example")
        .unwrap();
    assert!(leaf.login_required);
    // Selecting the placeholder and pressing `L` opens the login FORM
    // pre-filled with that leaf's proxy (not a raw terminal handoff).
    let idx = app.agg_rows.iter().position(|r| r.login_required).unwrap();
    app.table.select(Some(idx));
    assert!(matches!(app.on_key(press('L')), Outcome::Continue));
    assert_eq!(app.mode, Mode::LoginForm);
    assert_eq!(app.login_form.proxy, "leaf.example");
    // Submitting runs `tsh login --proxy=leaf.example` and schedules a root
    // restore before the post-login refetch (so the topology isn't re-read
    // from the leaf's narrower view).
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::Run { args, .. } => {
            assert_eq!(args[0..2], ["login", "--proxy=leaf.example"]);
        }
        _ => panic!("expected a login Run on submit"),
    }
    assert_eq!(app.pending_root_restore.as_deref(), Some("root.example"));
}

#[test]
fn c_without_topology_shows_hint_not_empty_picker() {
    let mut app = test_app();
    app.topology = None; // simulate `tsh clusters` having failed
    app.on_key(press('c'));
    assert_eq!(
        app.mode,
        Mode::Normal,
        "must not enter an empty, invisible Picker mode"
    );
    assert!(
        app.status
            .as_deref()
            .unwrap_or("")
            .contains("clusters not loaded"),
        "gives feedback instead"
    );
    // `r` retries loading clusters when there's no topology.
    app.on_key(press('r'));
    assert!(
        app.topology.is_some(),
        "r re-ran tsh clusters (FakeClusters)"
    );
}

#[test]
fn aggregate_reuses_cached_clusters_and_fetches_only_missing() {
    let counter = std::sync::Arc::new(AtomicUsize::new(0));
    let mut app = test_app_with_admin(Box::new(CountingAdmin(counter.clone())));
    // Pretend one cluster's Users slice was cached by an earlier partial fan-out.
    app.agg_cache.insert(
        (Tab::Users, "root.example".to_owned()),
        vec![AggRow {
            cluster: "root.example".to_owned(),
            cells: vec!["alice".to_owned()],
            login_required: false,
            sid: None,
        }],
    );
    counter.store(0, Ordering::SeqCst); // ignore the bootstrap prefetch
    app.on_key(press('c'));
    app.on_key(KeyEvent::from(KeyCode::Up));
    app.on_key(KeyEvent::from(KeyCode::Enter));
    app.on_key(press('5')); // Users, all-clusters
    // root.example was cached → not re-fetched; only leaf.example is fetched.
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "only the missing cluster fetched"
    );
    assert!(app.agg_rows.iter().any(|r| r.cluster == "root.example")); // from cache
    assert!(app.agg_rows.iter().any(|r| r.cluster == "leaf.example")); // freshly fetched
}

#[test]
fn agg_slice_caches_per_cluster_even_when_off_tab() {
    // A cluster's slice arriving while the user is on another tab must still be
    // cached per (tab, cluster), so partial progress survives navigation.
    let mut app = test_app();
    assert_eq!(app.tab, Tab::Ssh); // not on Roles
    let rows = vec![AggRow {
        cluster: "leaf.example".to_owned(),
        cells: vec!["admin".to_owned()],
        login_required: false,
        sid: None,
    }];
    app.apply(
        app.agg_seq,
        JobResult::AggregateAdmin {
            tab: Tab::Roles,
            cluster: "leaf.example".to_owned(),
            rows,
        },
    );
    assert!(
        app.agg_cache
            .contains_key(&(Tab::Roles, "leaf.example".to_owned())),
        "the slice is cached per (tab, cluster) regardless of the current view"
    );
}

#[test]
fn recordings_aggregate_across_clusters_and_play() {
    // CountingAdmin.select_cluster returns Ok, so the serial recordings
    // fan-out reaches every cluster (Recordings has no cluster flag, so it
    // uses the same profile-switch path as the admin tabs).
    let counter = std::sync::Arc::new(AtomicUsize::new(0));
    let mut app = test_app_with_admin(Box::new(CountingAdmin(counter)));
    app.on_key(press('c'));
    app.on_key(KeyEvent::from(KeyCode::Up));
    app.on_key(KeyEvent::from(KeyCode::Enter));
    assert!(app.aggregate);
    app.switch_tab(Tab::Recordings);
    assert_eq!(app.tab, Tab::Recordings);
    // FakeRecordings yields 1 recording per cluster × 2 online clusters, each
    // carrying its sid (not a visible column) and tagged with its cluster.
    assert_eq!(app.agg_rows.len(), 2);
    assert!(app.agg_rows.iter().all(|r| !r.login_required));
    assert!(
        app.agg_rows
            .iter()
            .all(|r| r.sid.as_deref() == Some("sess-0001"))
    );
    assert!(app.agg_rows.iter().any(|r| r.cluster == "leaf.example"));
    // Enter plays the highlighted recording via its aggregate-row sid.
    app.table.select(Some(0));
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::PlayRecording { args, .. } => assert_eq!(args, vec!["play", "sess-0001"]),
        other => panic!("expected PlayRecording, got {other:?}"),
    }
}

#[test]
fn all_clusters_aggregate_merges_and_connects_directly() {
    let mut app = test_app(); // SSH tab; FakeNodes returns 3 nodes per cluster
    // open cluster picker, move up to "All clusters" (index 0), confirm.
    app.on_key(press('c'));
    app.on_key(KeyEvent::from(KeyCode::Up));
    app.on_key(KeyEvent::from(KeyCode::Enter));
    assert!(app.aggregate);
    // 3 nodes × 2 online clusters (root + leaf) = 6 aggregate rows.
    assert_eq!(app.agg_rows.len(), 6);
    assert!(app.agg_rows.iter().any(|r| r.cluster == "root.example"));
    assert!(app.agg_rows.iter().any(|r| r.cluster == "leaf.example"));
    // Enter connects DIRECTLY (no drill-down): row 0 is root.example/web-01.
    app.table.select(Some(0));
    app.on_key(KeyEvent::from(KeyCode::Enter));
    assert!(app.aggregate, "stays in all-clusters view");
    assert!(matches!(app.mode, Mode::UserPicker(_))); // 2 logins -> pick user
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::Run { args, .. } => {
            // connects on the row's own cluster, not the selected one.
            assert_eq!(args, vec!["ssh", "-c", "root.example", "root@web-01"]);
        }
        other => panic!("expected Run, got {other:?}"),
    }
}

#[test]
fn switching_cluster_invalidates_cache_and_refetches() {
    let counter = std::sync::Arc::new(AtomicUsize::new(0));
    let repos = Repositories {
        clusters: Box::new(FakeClusters),
        nodes: Box::new(CountingNodes(counter.clone())),
        kube: Box::new(FakeKube),
        databases: Box::new(FakeDb),
        apps: Box::new(FakeApps),
        requests: Box::new(FakeRequests),
        recordings: Box::new(FakeRecordings),
        sessions: Box::new(FakeSessions),
        auth: Box::new(FakeAuth),
        admin: Box::new(FakeAdmin),
    };
    let logger = NdjsonLogger::new(PathBuf::from("/dev/null"));
    let mut app = App::new(
        repos,
        logger,
        "t".to_owned(),
        PathBuf::from("tsh"),
        Settings {
            kube_tools: vec!["shell".to_owned()],
            login_proxy: None,
            login_user: None,
            ..Settings::default()
        },
        true,
    );
    app.bootstrap(); // SSH loaded for root.example
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    // Switch cluster (root -> leaf): c, ↓, Enter.
    app.on_key(press('c'));
    app.on_key(KeyEvent::from(KeyCode::Down));
    app.on_key(KeyEvent::from(KeyCode::Enter));
    assert_eq!(
        app.topology.as_ref().unwrap().selected().name.as_str(),
        "leaf.example"
    );
    // The cluster change forced a refetch for the new cluster.
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    // Within the new cluster, switching tabs still uses the cache.
    app.on_key(press('2')); // Kube
    app.on_key(press('1')); // back to SSH -> cached for leaf.example
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

#[test]
fn entering_all_clusters_reuses_active_cluster_data() {
    // Regression: switching from a scoped cluster to all-clusters used to
    // refetch the cluster we were just viewing (its scoped rows were ignored).
    // Now the active cluster's rows seed the aggregate, so only the *other*
    // clusters are fetched.
    let counter = std::sync::Arc::new(AtomicUsize::new(0));
    let repos = Repositories {
        clusters: Box::new(FakeClusters),
        nodes: Box::new(CountingNodes(counter.clone())),
        kube: Box::new(FakeKube),
        databases: Box::new(FakeDb),
        apps: Box::new(FakeApps),
        requests: Box::new(FakeRequests),
        recordings: Box::new(FakeRecordings),
        sessions: Box::new(FakeSessions),
        auth: Box::new(FakeAuth),
        admin: Box::new(FakeAdmin),
    };
    let logger = NdjsonLogger::new(PathBuf::from("/dev/null"));
    let mut app = App::new(
        repos,
        logger,
        "t".to_owned(),
        PathBuf::from("tsh"),
        Settings {
            kube_tools: vec!["shell".to_owned()],
            ..Settings::default()
        },
        true,
    );
    app.bootstrap(); // SSH loaded for root.example (1 fetch)
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    counter.store(0, Ordering::SeqCst);

    // Enter all-clusters (c, ↑ "All clusters", Enter) on the SSH tab.
    app.on_key(press('c'));
    app.on_key(KeyEvent::from(KeyCode::Up));
    app.on_key(KeyEvent::from(KeyCode::Enter));
    assert!(app.aggregate);
    // Both clusters render (root reused from scoped cache + leaf fetched)...
    assert_eq!(app.agg_rows.len(), 2);
    assert!(app.agg_rows.iter().any(|r| r.cluster == "root.example"));
    assert!(app.agg_rows.iter().any(|r| r.cluster == "leaf.example"));
    // ...but only leaf triggered a fetch — root's rows came from memory.
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[test]
fn switching_tabs_uses_cache_and_r_forces_refetch() {
    let counter = std::sync::Arc::new(AtomicUsize::new(0));
    let repos = Repositories {
        clusters: Box::new(FakeClusters),
        nodes: Box::new(CountingNodes(counter.clone())),
        kube: Box::new(FakeKube),
        databases: Box::new(FakeDb),
        apps: Box::new(FakeApps),
        requests: Box::new(FakeRequests),
        recordings: Box::new(FakeRecordings),
        sessions: Box::new(FakeSessions),
        auth: Box::new(FakeAuth),
        admin: Box::new(FakeAdmin),
    };
    let logger = NdjsonLogger::new(PathBuf::from("/dev/null"));
    let mut app = App::new(
        repos,
        logger,
        "t".to_owned(),
        PathBuf::from("tsh"),
        Settings {
            kube_tools: vec!["shell".to_owned()],
            login_proxy: None,
            login_user: None,
            ..Settings::default()
        },
        true,
    );
    app.bootstrap(); // loads SSH once
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    app.on_key(press('2')); // -> Kube (loads kube, not nodes)
    app.on_key(press('1')); // -> back to SSH: cache hit, no refetch
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    app.on_key(press('r')); // explicit refresh -> refetch
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

#[test]
fn async_path_loads_off_thread_via_tick() {
    let mut app = async_app();
    app.bootstrap(); // spawns background jobs (status + clusters -> nodes)
    // Pump ticks until the nodes land (fakes are instant; bound the loop).
    let mut spins = 0;
    while app.nodes.is_empty() && spins < 1000 {
        app.tick();
        // Yield so the worker threads get scheduled (chained: clusters -> nodes).
        std::thread::sleep(std::time::Duration::from_millis(2));
        spins += 1;
    }
    assert_eq!(app.nodes.len(), 3, "background load did not complete");
    assert!(!app.loading, "loading flag should clear after results land");
    assert_eq!(app.profile.as_ref().unwrap().username, "maxime");
}

#[test]
fn selection_is_clamped_not_wrapped() {
    let mut app = test_app(); // 3 nodes, selection at 0
    assert_eq!(app.table.selected(), Some(0));
    // up at the top stays at 0 (no wrap to bottom)
    app.on_key(press('k'));
    assert_eq!(app.table.selected(), Some(0));
    // down to the last row, then down again stays at the last (no wrap to 0)
    app.on_key(press('j'));
    app.on_key(press('j'));
    app.on_key(press('j'));
    assert_eq!(app.table.selected(), Some(2));
}

#[test]
fn mouse_wheel_moves_selection_like_arrows() {
    let mut app = test_app(); // 3 nodes, selection at 0
    assert_eq!(app.table.selected(), Some(0));
    app.on_scroll(true); // wheel down
    assert_eq!(app.table.selected(), Some(1));
    app.on_scroll(true);
    assert_eq!(app.table.selected(), Some(2));
    app.on_scroll(false); // wheel up
    assert_eq!(app.table.selected(), Some(1));
}

#[test]
fn help_toggles_open_and_closed() {
    let mut app = test_app();
    app.on_key(press('?'));
    assert_eq!(app.mode, Mode::Help);
    app.on_key(KeyEvent::from(KeyCode::Char(' ')));
    assert_eq!(app.mode, Mode::Normal);
}

#[test]
fn bootstrap_reads_profile() {
    let app = test_app();
    assert_eq!(app.profile.as_ref().unwrap().username, "maxime");
}

#[test]
fn admin_users_tab_and_token_generation() {
    let mut app = test_app();
    app.on_key(press('5')); // -> Users
    assert_eq!(app.tab, Tab::Users);
    assert_eq!(app.users.len(), 1);
    // Token generation lives on the Tokens tab only.
    app.on_key(press('8')); // -> Tokens
    assert_eq!(app.tab, Tab::Tokens);
    // generate a token: g -> type -> Enter (runs inline in sync mode)
    app.on_key(press('g'));
    assert_eq!(app.mode, Mode::CreateToken);
    for c in "node".chars() {
        app.on_key(press(c));
    }
    app.on_key(KeyEvent::from(KeyCode::Enter));
    // The captured token is shown in a popup, not handed to the shell.
    assert_eq!(app.mode, Mode::ShowToken);
    let tv = app.token_view.as_ref().expect("token captured");
    assert_eq!(tv.token.as_str(), "secret-token-value");
    assert_eq!(tv.roles, vec!["node"]);
    // dismissing scrubs it.
    app.on_key(KeyEvent::from(KeyCode::Esc));
    assert_eq!(app.mode, Mode::Normal);
    assert!(app.token_view.is_none());
}

#[test]
fn login_form_builds_command_and_logout_emits() {
    let mut app = test_app();
    // L opens the login form, pre-filled from the active profile.
    app.on_key(press('L'));
    assert_eq!(app.mode, Mode::LoginForm);
    assert_eq!(app.login_form.proxy, "root.example"); // from FakeAuth profile
    // Auth dropdown: Tab x2 to Auth, → once selects "local" (index 1).
    app.on_key(KeyEvent::from(KeyCode::Tab)); // user
    app.on_key(KeyEvent::from(KeyCode::Tab)); // auth
    app.on_key(KeyEvent::from(KeyCode::Right)); // "" -> local
    assert_eq!(app.login_form.auth_str(), "local");
    // MFA dropdown: Tab to MFA, → once selects "otp" (index 1).
    app.on_key(KeyEvent::from(KeyCode::Tab)); // mfa
    app.on_key(KeyEvent::from(KeyCode::Right)); // "" -> otp
    assert_eq!(app.login_form.mfa_str(), "otp");
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::Run { args, .. } => assert_eq!(
            args,
            vec![
                "login",
                "--proxy=root.example",
                "--user=maxime",
                "--auth=local",
                "--mfa-mode=otp"
            ]
        ),
        other => panic!("expected Run, got {other:?}"),
    }
    assert!(app.last_was_auth);

    // logout still needs confirmation.
    app.on_key(press('O'));
    assert_eq!(app.mode, Mode::ConfirmLogout);
    match app.on_key(press('y')) {
        Outcome::Run { args, .. } => assert_eq!(args, vec!["logout"]),
        other => panic!("expected Run, got {other:?}"),
    }
    assert_eq!(app.mode, Mode::Normal);
}

#[test]
fn non_admin_hides_admin_group() {
    let mut app = test_app_with_admin(Box::new(NonAdmin));
    // bootstrap()'s synchronous AdminProbe resolved to "no admin".
    assert!(!app.admin_allowed);
    // Number keys for admin tabs are ignored.
    app.on_key(press('5'));
    assert_eq!(app.tab, Tab::Ssh);
    app.on_key(press('7'));
    assert_eq!(app.tab, Tab::Ssh);
    // Tab cycling stays within the Access group (never lands on admin).
    for _ in 0..6 {
        app.on_key(KeyEvent::from(KeyCode::Tab));
        assert!(!app.tab.admin_only(), "landed on hidden tab {:?}", app.tab);
    }
}

#[test]
fn admin_rights_show_admin_group() {
    let app = test_app(); // FakeAdmin: list_roles Ok => can_admin true
    assert!(app.admin_allowed);
}

#[test]
fn scp_download_builds_remote_to_local() {
    let mut app = test_app(); // SSH tab, row 0 = web-01 selected
    assert_eq!(app.tab, Tab::Ssh);
    app.on_key(press('s'));
    assert_eq!(app.mode, Mode::Scp);
    assert_eq!(app.scp_form.host, "web-01");
    assert_eq!(app.scp_form.cluster, "root.example");
    assert_eq!(app.scp_form.login, "root"); // first profile login
    assert!(app.scp_form.download);
    // Tab to Remote (field 2), type the node path.
    app.on_key(KeyEvent::from(KeyCode::Tab)); // login
    app.on_key(KeyEvent::from(KeyCode::Tab)); // remote
    for c in "/etc/hosts".chars() {
        app.on_key(press(c));
    }
    app.on_key(KeyEvent::from(KeyCode::Tab)); // local
    for c in "./hosts".chars() {
        app.on_key(press(c));
    }
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::Run { args, .. } => assert_eq!(
            args,
            vec![
                "scp",
                "-c",
                "root.example",
                "root@web-01:/etc/hosts",
                "./hosts"
            ]
        ),
        other => panic!("expected Run, got {other:?}"),
    }
    assert_eq!(app.mode, Mode::Normal);
}

#[test]
fn ssh_options_tunnel_goes_to_background_forward() {
    let mut app = test_app(); // SSH tab, row 0 = web-01, login "root"
    app.on_key(press('o'));
    assert_eq!(app.mode, Mode::SshOptions);
    assert_eq!(app.ssh_options_form.host, "web-01");
    assert_eq!(app.ssh_options_form.cluster, "root.example");
    assert_eq!(app.ssh_options_form.login, "root");
    app.on_key(KeyEvent::from(KeyCode::Tab)); // login → forward
    for c in "8080:localhost:80".chars() {
        app.on_key(press(c));
    }
    app.on_key(KeyEvent::from(KeyCode::Tab)); // forward → tunnel toggle
    app.on_key(KeyEvent::from(KeyCode::Right)); // tunnel_only = yes
    assert!(app.ssh_options_form.tunnel_only);
    // A pure tunnel runs in the background (not a terminal handoff) so the TUI stays.
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::OpenForward {
            cluster,
            user,
            host,
            spec,
            ..
        } => {
            assert_eq!(cluster, "root.example");
            assert_eq!(user, "root");
            assert_eq!(host, "web-01");
            assert_eq!(spec, "8080:localhost:80");
        }
        other => panic!("expected OpenForward, got {other:?}"),
    }
    assert_eq!(app.mode, Mode::Normal);
}

#[test]
fn forwards_popup_lists_and_stops() {
    use std::process::Command;
    let mut app = test_app();
    // Attach two fake forwards (a trivial child we can kill), then list + stop.
    let spawn = || Command::new("sleep").arg("30").spawn().unwrap();
    app.attach_forward(Forward::new(
        spawn(),
        "8080:localhost:80".to_owned(),
        "root@web-01".to_owned(),
        "root.example".to_owned(),
    ));
    app.attach_forward(Forward::new(
        spawn(),
        "9090:localhost:90".to_owned(),
        "root@web-02".to_owned(),
        "root.example".to_owned(),
    ));
    assert_eq!(app.forwards.len(), 2);
    app.on_key(press('F'));
    assert_eq!(app.mode, Mode::Forwards);
    app.on_key(KeyEvent::from(KeyCode::Down)); // select second
    assert_eq!(app.forwards_sel, 1);
    app.on_key(press('d')); // stop it (kills the child)
    assert_eq!(app.forwards.len(), 1);
    assert_eq!(app.forwards_sel, 0); // clamped
    app.on_key(KeyEvent::from(KeyCode::Esc));
    assert_eq!(app.mode, Mode::Normal);
}

#[test]
fn ssh_options_one_off_command_suppresses_tunnel_flag() {
    let mut app = test_app();
    app.on_key(press('o'));
    // Skip to the command field (login → forward → tunnel → command).
    for _ in 0..3 {
        app.on_key(KeyEvent::from(KeyCode::Tab));
    }
    for c in "uptime".chars() {
        app.on_key(press(c));
    }
    // A one-off command is a RunCommand (the event loop pauses on its output).
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::RunCommand { args, .. } => {
            assert_eq!(
                args,
                vec!["ssh", "-c", "root.example", "root@web-01", "uptime"]
            );
        }
        other => panic!("expected RunCommand, got {other:?}"),
    }
}

#[test]
fn scp_upload_recursive_swaps_direction() {
    let mut app = test_app();
    app.on_key(press('s'));
    // Direction toggle (field 0) → upload.
    app.on_key(KeyEvent::from(KeyCode::Right));
    assert!(!app.scp_form.download);
    app.on_key(KeyEvent::from(KeyCode::Tab)); // login
    app.on_key(KeyEvent::from(KeyCode::Tab)); // remote
    for c in "/opt/app".chars() {
        app.on_key(press(c));
    }
    app.on_key(KeyEvent::from(KeyCode::Tab)); // local
    for c in "./dist".chars() {
        app.on_key(press(c));
    }
    app.on_key(KeyEvent::from(KeyCode::Tab)); // recursive
    app.on_key(KeyEvent::from(KeyCode::Right)); // recursive = yes
    assert!(app.scp_form.recursive);
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        // Upload: local first, remote second; -r before the endpoints.
        Outcome::Run { args, .. } => assert_eq!(
            args,
            vec![
                "scp",
                "-c",
                "root.example",
                "-r",
                "./dist",
                "root@web-01:/opt/app"
            ]
        ),
        other => panic!("expected Run, got {other:?}"),
    }
}

#[test]
fn scp_shortcut_ignored_off_ssh_tab() {
    let mut app = test_app();
    app.on_key(press('2')); // -> Kubernetes
    assert_eq!(app.tab, Tab::Kube);
    app.on_key(press('s'));
    assert_eq!(app.mode, Mode::Normal); // no scp form on non-SSH tabs
}

#[test]
fn missing_cli_capability_hides_tab() {
    // A tsh that only supports `ls`/`ssh`: Kube/Db/Apps/Requests are hidden.
    let mut app = test_app();
    app.caps = domain::capability::Capabilities::probed(["ssh", "ls"]);
    assert!(app.tab_visible(Tab::Ssh));
    assert!(!app.tab_visible(Tab::Kube));
    assert!(!app.tab_visible(Tab::Db));
    assert!(!app.tab_visible(Tab::Apps));
    assert!(!app.tab_visible(Tab::Requests));
    // The number key for a hidden tab is a no-op.
    app.on_key(press('2'));
    assert_eq!(app.tab, Tab::Ssh);
    // Tab cycling skips hidden tabs (Kube/Db/Apps hidden, Users/Roles via tctl).
    app.on_key(KeyEvent::from(KeyCode::Tab));
    assert!(
        app.tab_visible(app.tab),
        "cycled onto a hidden tab: {:?}",
        app.tab
    );
}

#[test]
fn unknown_capabilities_are_permissive() {
    // Default (unprobed) capabilities keep every tab available.
    let app = test_app();
    assert!(app.tab_visible(Tab::Kube));
    assert!(app.tab_visible(Tab::Db));
    assert!(app.tab_visible(Tab::Apps));
}

#[test]
fn prefetch_warms_all_tabs_on_start() {
    // Synchronous bootstrap runs the prefetch inline: every visible tab is
    // loaded and cached, so later switches are instant (no per-tab wait).
    let app = test_app();
    assert!(!app.nodes.is_empty()); // active tab
    assert!(!app.kube.is_empty()); // prefetched
    for tab in [
        Tab::Kube,
        Tab::Db,
        Tab::Apps,
        Tab::Requests,
        Tab::Recordings,
        Tab::Users,
        Tab::Roles,
    ] {
        assert!(
            app.cache_key.contains_key(&tab),
            "tab not prefetched/cached: {tab:?}"
        );
    }
}

#[test]
fn admin_prefetch_survives_probe_before_topology() {
    // Race: the admin-rights probe (`tctl status`) can land BEFORE
    // `tsh clusters`. Replay that order and assert the admin tabs still end
    // up cached — rather than dispatched under a prefetch generation the
    // cluster load then bumps, which discarded them as stale.
    let mut app = test_app();
    // Reset to a pre-topology state, as if a fresh session just began.
    app.topology = None;
    app.admin_allowed = false;
    app.cache_key.clear();
    app.prefetch_cluster = None;

    // 1) Probe returns first, before the topology is known → prefetch deferred.
    app.apply(0, JobResult::AdminAllowed(true));
    assert!(
        !app.cache_key.contains_key(&Tab::Users),
        "admin prefetch must wait for topology, not warm under a stale generation"
    );

    // 2) Topology arrives → prefetch_all runs with admin rights known.
    let topo = FakeClusters.list_clusters().unwrap();
    app.apply(0, JobResult::Clusters(Ok(topo)));
    assert!(
        app.cache_key.contains_key(&Tab::Users),
        "admin Users tab should be prefetched once topology lands"
    );
    assert!(app.cache_key.contains_key(&Tab::Roles));
}

#[test]
fn search_arrows_navigate_filtered_results() {
    // Regression: in search mode the arrows used to be ignored, so a filtered
    // list couldn't be navigated. They now move the highlight while the filter
    // stays live.
    let mut app = test_app(); // SSH tab: web-01, web-02, db-01
    app.on_key(press('/'));
    assert_eq!(app.mode, Mode::Search);
    for c in "web".chars() {
        app.on_key(press(c));
    }
    assert_eq!(app.visible.len(), 2); // only the two web-* nodes
    assert_eq!(app.table.selected(), Some(0));

    app.on_key(KeyEvent::from(KeyCode::Down));
    assert_eq!(app.table.selected(), Some(1));
    assert_eq!(
        app.visible.len(),
        2,
        "filter still applied while navigating"
    );

    app.on_key(KeyEvent::from(KeyCode::Up));
    assert_eq!(app.table.selected(), Some(0));
    assert_eq!(app.mode, Mode::Search, "navigation stays in search mode");
}

#[test]
fn mfa_key_shows_devices_popup() {
    let mut app = test_app();
    app.on_key(press('M'));
    assert_eq!(app.mode, Mode::ShowMfa);
    assert_eq!(app.mfa_devices.len(), 1);
    assert_eq!(app.mfa_devices[0].kind, "webauthn");
    // Any key dismisses and clears the list.
    app.on_key(press('q'));
    assert_eq!(app.mode, Mode::Normal);
    assert!(app.mfa_devices.is_empty());
}

#[test]
fn sessions_key_lists_and_joins() {
    let mut app = test_app();
    app.on_key(press('S'));
    assert_eq!(app.mode, Mode::ShowSessions);
    assert_eq!(app.sessions.len(), 1);
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::Run { args, .. } => assert_eq!(args, vec!["join", "live-0001"]),
        other => panic!("expected Run(join), got {other:?}"),
    }
    assert_eq!(app.mode, Mode::Normal);
    assert!(app.sessions.is_empty());
}

#[test]
fn g_generates_token_only_on_tokens_tab() {
    let mut app = test_app();
    app.switch_tab(Tab::Users);
    app.on_key(press('g'));
    assert_ne!(app.mode, Mode::CreateToken); // not on Users/Roles
    app.switch_tab(Tab::Tokens);
    app.on_key(press('g'));
    assert_eq!(app.mode, Mode::CreateToken); // only on Tokens
}

#[test]
fn recordings_enter_replays_session() {
    use domain::resource::Resource;
    let mut app = test_app();
    app.switch_tab(Tab::Recordings);
    assert_eq!(app.recordings.len(), 1);
    assert_eq!(app.recordings[0].row()[1], "5m29s"); // DURATION column
    assert_eq!(app.recordings[0].row()[3], "node-01"); // SERVER column
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::PlayRecording { args, .. } => assert_eq!(args, vec!["play", "sess-0001"]),
        other => panic!("expected PlayRecording, got {other:?}"),
    }
}

#[test]
fn mfa_add_and_remove_actions() {
    let mut app = test_app();
    app.on_key(press('M')); // popup, 1 device ("yubikey")
    match app.on_key(press('a')) {
        Outcome::Run { args, .. } => assert_eq!(args, vec!["mfa", "add"]),
        other => panic!("expected Run, got {other:?}"),
    }
    app.on_key(press('M')); // reopen
    app.on_key(press('d')); // confirm dialog for selected device
    assert!(matches!(app.mode, Mode::ConfirmMfaRm(_)));
    match app.on_key(press('y')) {
        Outcome::Run { args, .. } => assert_eq!(args, vec!["mfa", "rm", "yubikey"]),
        other => panic!("expected Run, got {other:?}"),
    }
}

#[test]
fn db_proxy_key_returns_open_db_proxy() {
    let mut app = test_app();
    app.on_key(press('3')); // Db tab (pg-main selected)
    match app.on_key(press('P')) {
        Outcome::OpenDbProxy { name, cluster } => {
            assert_eq!(name, "pg-main");
            assert_eq!(cluster, "root.example");
        }
        other => panic!("expected OpenDbProxy, got {other:?}"),
    }
}

#[test]
fn db_and_app_cert_lifecycle_keys() {
    let mut app = test_app();
    // Db tab (pg-main selected): `l` logs in, `u` logs out.
    app.on_key(press('3'));
    assert_eq!(app.tab, Tab::Db);
    match app.on_key(press('l')) {
        Outcome::Run { args, .. } => {
            assert_eq!(args, vec!["db", "login", "-c", "root.example", "pg-main"]);
        }
        other => panic!("expected db login Run, got {other:?}"),
    }
    match app.on_key(press('u')) {
        Outcome::Run { args, .. } => {
            assert_eq!(args, vec!["db", "logout", "-c", "root.example", "pg-main"]);
        }
        other => panic!("expected db logout Run, got {other:?}"),
    }
    // Apps tab: `l`/`u` map to `tsh apps login`/`logout`.
    app.on_key(press('4'));
    assert_eq!(app.tab, Tab::Apps);
    match app.on_key(press('l')) {
        Outcome::Run { args, .. } => {
            assert_eq!(args[0..2], ["apps", "login"]);
            assert_eq!(args[2..4], ["-c", "root.example"]);
        }
        other => panic!("expected apps login Run, got {other:?}"),
    }
}

#[test]
fn kube_exec_form_emits_two_step_exec() {
    let mut app = test_app();
    app.on_key(press('2')); // Kube tab (k8s-prod selected)
    assert_eq!(app.tab, Tab::Kube);
    app.on_key(press('e'));
    assert!(matches!(app.mode, Mode::KubeExec { .. }));
    // Field 0 = pod, field 1 = command.
    for c in "api-0".chars() {
        app.on_key(press(c));
    }
    app.on_key(KeyEvent::from(KeyCode::Tab));
    for c in "sh".chars() {
        app.on_key(press(c));
    }
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::KubeExec {
            cluster,
            kube,
            exec,
            ..
        } => {
            assert_eq!(cluster, "root.example");
            assert_eq!(kube, "k8s-prod");
            assert_eq!(exec, vec!["kube", "exec", "--", "api-0", "sh"]);
        }
        other => panic!("expected KubeExec, got {other:?}"),
    }
    assert_eq!(app.mode, Mode::Normal);
    // An empty command is rejected (form stays open).
    app.on_key(press('e'));
    for c in "api-0".chars() {
        app.on_key(press(c));
    }
    assert!(matches!(
        app.on_key(KeyEvent::from(KeyCode::Enter)),
        Outcome::Continue
    ));
    assert!(matches!(app.mode, Mode::KubeExec { .. }));
}

#[test]
fn bots_and_inventory_tabs_load() {
    use domain::resource::Resource;
    let mut app = test_app();
    app.on_key(press('9')); // Bots tab
    assert_eq!(app.tab, Tab::Bots);
    assert_eq!(app.bots.len(), 1);
    assert_eq!(app.bots[0].row()[0], "ci");
    assert_eq!(app.bots[0].row()[3], "12h"); // 43200s formatted
    app.on_key(press('0')); // Inventory tab
    assert_eq!(app.tab, Tab::Inventory);
    assert_eq!(app.instances.len(), 1);
    assert_eq!(app.instances[0].row()[0], "agent-01");
}

#[test]
fn tokens_render_like_tctl_plain() {
    use domain::resource::Resource;
    let mut app = test_app();
    app.on_key(press('8'));
    assert_eq!(app.tab, Tab::Tokens);
    assert_eq!(app.tokens.len(), 2);
    // Plain, non-secret columns: TOKEN(name)/TYPE/LABELS/EXPIRES, like
    // `tctl tokens ls` — no masking, no reveal.
    let row = app.tokens[0].row();
    assert_eq!(row[0], "tbot-ci"); // TOKEN = name
    assert_eq!(row[1], "Bot"); // TYPE
    assert_eq!(row[2], "team=ci"); // LABELS
    assert_eq!(row[3], "never"); // empty expiry → never
}

#[test]
fn tokens_prefetched_at_startup_and_kept_on_leave() {
    let mut app = test_app();
    // Tokens are a plain admin listing now: warmed by the startup prefetch
    // like the other admin tabs, and not scrubbed when leaving the tab.
    assert!(app.cache_key.contains_key(&Tab::Tokens));
    app.on_key(press('8'));
    assert!(!app.tokens.is_empty());
    app.on_key(press('1')); // leave to SSH
    assert!(
        !app.tokens.is_empty(),
        "listing is not secret; stays cached"
    );
    assert!(app.cache_key.contains_key(&Tab::Tokens));
}

#[test]
fn add_user_shows_one_time_invite_url() {
    let mut app = test_app();
    app.on_key(press('5')); // Users tab
    app.on_key(press('n'));
    assert_eq!(app.mode, Mode::AddUser);
    for c in "bob".chars() {
        app.on_key(press(c));
    }
    app.on_key(KeyEvent::from(KeyCode::Tab));
    for c in "access".chars() {
        app.on_key(press(c));
    }
    app.on_key(KeyEvent::from(KeyCode::Enter));
    // Synchronous: AddUser → Invite applied inline → one-time URL popup.
    assert_eq!(app.mode, Mode::ShowInvite);
    let iv = app.invite_view.as_ref().unwrap();
    assert_eq!(iv.user, "bob");
    assert!(iv.url.as_str().contains("/web/invite/"));
    // Any key dismisses and scrubs the URL.
    app.on_key(press('q'));
    assert!(app.invite_view.is_none());
    assert_eq!(app.mode, Mode::Normal);
}

#[test]
fn add_user_rejects_empty_username() {
    let mut app = test_app();
    app.on_key(press('5'));
    app.on_key(press('n'));
    app.on_key(KeyEvent::from(KeyCode::Enter)); // empty → invalid
    assert_eq!(app.mode, Mode::AddUser); // form stays open
    assert!(app.invite_view.is_none());
}

#[test]
fn reset_user_confirm_shows_reset_url() {
    let mut app = test_app();
    app.on_key(press('5')); // Users tab (alice selected)
    app.on_key(press('R'));
    assert!(matches!(app.mode, Mode::ConfirmUserReset(ref u) if u == "alice"));
    app.on_key(press('y'));
    assert_eq!(app.mode, Mode::ShowInvite);
    assert!(
        app.invite_view
            .as_ref()
            .unwrap()
            .url
            .as_str()
            .contains("/web/reset/")
    );
}

#[test]
fn token_rm_opens_confirm_then_cancels() {
    let mut app = test_app();
    app.on_key(press('8'));
    app.on_key(press('d')); // selected row 0 → confirm dialog
    assert_eq!(app.mode, Mode::ConfirmTokenRm);
    app.on_key(KeyEvent::from(KeyCode::Esc));
    assert_eq!(app.mode, Mode::Normal);
}

#[test]
fn logout_clears_all_resources() {
    let mut app = test_app(); // logged in; nodes + topology loaded at bootstrap
    assert!(!app.nodes.is_empty());
    assert!(app.topology.is_some());
    // Post-logout status refresh reports no active session → wipe everything.
    app.apply(0, JobResult::Status(Ok(None)));
    assert!(app.nodes.is_empty());
    assert!(app.topology.is_none());
    assert!(!app.admin_allowed);
    assert!(app.visible.is_empty());
    assert!(app.profile.is_none());
}

#[test]
fn default_login_skips_picker() {
    let mut app = test_app();
    app.default_login = Some("ubuntu".to_owned());
    // Enter on a node connects directly as the default login (no picker).
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::Run { args, .. } => {
            assert_eq!(args, vec!["ssh", "-c", "root.example", "ubuntu@web-01"]);
        }
        other => panic!("expected direct Run, got {other:?}"),
    }
    assert_eq!(app.mode, Mode::Normal); // never opened the UserPicker
}

#[test]
fn settings_edit_persists_to_file() {
    let dir = std::env::temp_dir().join(format!("ttui-cfg-{}", std::process::id()));
    let path = dir.join("config.toml");
    let _ = std::fs::remove_file(&path);
    let mut app = test_app();
    app.config_path = path.clone();
    app.on_key(press('p'));
    assert_eq!(app.mode, Mode::Settings);
    // Type an SSH default login on the first (focused) row.
    for c in "ubuntu".chars() {
        app.on_key(press(c));
    }
    app.on_key(KeyEvent::from(KeyCode::Enter)); // save
    assert_eq!(app.mode, Mode::Normal);
    assert_eq!(app.default_login.as_deref(), Some("ubuntu"));
    // The file was written and reloads with the same value.
    let reloaded = InfraConfig::load(&path);
    assert_eq!(reloaded.default_login.as_deref(), Some("ubuntu"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn login_sso_omits_auth_connector() {
    let mut app = test_app();
    app.on_key(press('L'));
    // Tab to Auth, cycle ←/→ to "sso" (index 3): three Rights from "".
    app.on_key(KeyEvent::from(KeyCode::Tab)); // user
    app.on_key(KeyEvent::from(KeyCode::Tab)); // auth
    for _ in 0..3 {
        app.on_key(KeyEvent::from(KeyCode::Right));
    }
    assert_eq!(app.login_form.auth_str(), "sso");
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        // sso = browser flow: no `--auth` connector value is passed.
        Outcome::Run { args, .. } => {
            assert!(!args.iter().any(|a| a.starts_with("--auth")));
            assert!(args.contains(&"--proxy=root.example".to_owned()));
        }
        other => panic!("expected Run, got {other:?}"),
    }
}

#[test]
fn requests_tab_approve_and_create() {
    let mut app = test_app();
    app.on_key(press('7')); // -> Requests
    assert_eq!(app.tab, Tab::Requests);
    assert_eq!(app.requests.len(), 1);
    match app.on_key(press('a')) {
        Outcome::Run { args, .. } => assert_eq!(
            args,
            vec![
                "request",
                "review",
                "--approve",
                "-c",
                "root.example",
                "req-0001"
            ]
        ),
        other => panic!("expected Run, got {other:?}"),
    }
    app.on_key(press('n'));
    assert_eq!(app.mode, Mode::CreateRequest);
    for c in "admin,dba".chars() {
        app.on_key(press(c));
    }
    match app.on_key(KeyEvent::from(KeyCode::Enter)) {
        Outcome::Run { args, .. } => assert_eq!(
            args,
            vec![
                "request",
                "create",
                "-c",
                "root.example",
                "--roles=admin,dba"
            ]
        ),
        other => panic!("expected Run, got {other:?}"),
    }
}

#[test]
fn clamp_step_is_total_on_empty_list() {
    // Regression: `len - 1` used to underflow when the list was empty.
    assert_eq!(clamp_step(0, 0, true), 0);
    assert_eq!(clamp_step(0, 0, false), 0);
    // Normal clamping still stops at the ends (no wrap-around).
    assert_eq!(clamp_step(0, 3, true), 1);
    assert_eq!(clamp_step(2, 3, true), 2);
    assert_eq!(clamp_step(0, 3, false), 0);
}
