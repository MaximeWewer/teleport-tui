//! The concurrency seam: the background `Job`/`JobResult` protocol, the pure
//! `run_job` dispatch, and the `Dispatcher` that runs jobs off the UI thread (a
//! bounded worker pool plus the serial admin / after-action fan-outs). Split out
//! of `app` so the threading / channel / `Send + Sync` plumbing lives apart from
//! the view/update state in [`super::App`].
//!
//! A child module of `app`: it shares the parent's imports and model types
//! (`Repositories`, `Tab`, `AggRow`, `ProxyEvent`, the use cases) via `super::*`.

#[allow(clippy::wildcard_imports)]
use super::*;

/// A unit of CLI work to run off the UI thread.
#[derive(Debug)]
pub(super) enum Job {
    Clusters,
    Status,
    Nodes(ClusterContext),
    Kube(ClusterContext),
    Db(ClusterContext),
    Apps(ClusterContext),
    Requests(ClusterContext),
    Recordings(ClusterContext),
    Users,
    Roles,
    Tokens,
    Bots,
    Instances,
    /// List the current user's MFA devices (`tsh mfa ls`).
    Mfa,
    /// List active sessions to join (`tsh sessions ls -c <cluster>`).
    Sessions(ClusterContext),
    /// Remove a provision token by its secret value (`tctl tokens rm`).
    RemoveToken(String),
    /// Create a user with roles (`tctl users add`) → one-time invite URL.
    AddUser {
        user: String,
        roles: String,
    },
    /// Reset a user's credentials (`tctl users reset`) → one-time reset URL.
    ResetUser(String),
    GenerateToken(String),
    /// Probe whether the current identity has `tctl` admin rights.
    AdminProbe,
    /// Aggregate one tab's listing for a single cluster (rows tagged on apply).
    Aggregate {
        tab: Tab,
        ctx: ClusterContext,
    },
}

/// The result of a [`Job`], sent back to the UI thread.
pub(super) enum JobResult {
    Clusters(Result<ClusterTopology, AppError>),
    Status(Result<Option<Profile>, AppError>),
    Nodes(Result<Vec<SshNode>, AppError>),
    Kube(Result<Vec<KubeCluster>, AppError>),
    Db(Result<Vec<Database>, AppError>),
    Apps(Result<Vec<AppResource>, AppError>),
    Requests(Result<Vec<AccessRequest>, AppError>),
    Recordings(Result<Vec<SessionRecording>, AppError>),
    Users(Result<Vec<AdminUser>, AppError>),
    Roles(Result<Vec<AdminRole>, AppError>),
    Tokens(Result<Vec<ProvisionToken>, AppError>),
    Bots(Result<Vec<Bot>, AppError>),
    Instances(Result<Vec<Instance>, AppError>),
    Mfa(Result<Vec<MfaDevice>, AppError>),
    Sessions(Result<Vec<ActiveSession>, AppError>),
    TokenRemoved(Result<(), AppError>),
    Invite(Result<InviteLink, AppError>),
    Token(Result<GeneratedToken, AppError>),
    AdminAllowed(bool),
    /// One cluster's slice of a concurrent (`tsh -c`) aggregate. Carries `tab` +
    /// `cluster` so it caches per-cluster even after the user navigates away.
    Aggregate {
        tab: Tab,
        cluster: String,
        rows: Result<Vec<Vec<String>>, AppError>,
    },
    /// One cluster's slice of a serial admin/recordings fan-out (its rows, or a
    /// login-required placeholder), already tagged. Streamed one per cluster;
    /// caches per-cluster so partial progress survives navigation.
    AggregateAdmin {
        tab: Tab,
        cluster: String,
        rows: Vec<AggRow>,
    },
}

/// Run a job against the repositories. Pure dispatch — safe to call from a
/// worker thread (repos are `Send + Sync`).
fn run_job(repos: &Repositories, job: Job) -> JobResult {
    match job {
        Job::Clusters => JobResult::Clusters(ListClusters::new(repos.clusters.as_ref()).execute()),
        Job::Status => JobResult::Status(GetStatus::new(repos.auth.as_ref()).execute()),
        Job::Nodes(ctx) => JobResult::Nodes(ListNodes::new(repos.nodes.as_ref()).execute(&ctx)),
        Job::Kube(ctx) => JobResult::Kube(ListKube::new(repos.kube.as_ref()).execute(&ctx)),
        Job::Db(ctx) => JobResult::Db(ListDatabases::new(repos.databases.as_ref()).execute(&ctx)),
        Job::Apps(ctx) => JobResult::Apps(ListApps::new(repos.apps.as_ref()).execute(&ctx)),
        Job::Requests(ctx) => {
            JobResult::Requests(ListRequests::new(repos.requests.as_ref()).execute(&ctx))
        }
        Job::Recordings(ctx) => {
            JobResult::Recordings(ListRecordings::new(repos.recordings.as_ref()).execute(&ctx))
        }
        Job::Users => JobResult::Users(ListUsers::new(repos.admin.as_ref()).execute()),
        Job::Roles => JobResult::Roles(ListRoles::new(repos.admin.as_ref()).execute()),
        Job::Tokens => JobResult::Tokens(ListTokens::new(repos.admin.as_ref()).execute()),
        Job::Bots => JobResult::Bots(ListBots::new(repos.admin.as_ref()).execute()),
        Job::Instances => JobResult::Instances(ListInstances::new(repos.admin.as_ref()).execute()),
        Job::Mfa => JobResult::Mfa(ListMfaDevices::new(repos.auth.as_ref()).execute()),
        Job::Sessions(ctx) => {
            JobResult::Sessions(ListSessions::new(repos.sessions.as_ref()).execute(&ctx))
        }
        Job::RemoveToken(token) => {
            JobResult::TokenRemoved(RemoveToken::new(repos.admin.as_ref()).execute(&token))
        }
        Job::AddUser { user, roles } => {
            JobResult::Invite(AddUser::new(repos.admin.as_ref()).execute(&user, &roles))
        }
        Job::ResetUser(user) => {
            JobResult::Invite(ResetUser::new(repos.admin.as_ref()).execute(&user))
        }
        Job::GenerateToken(ty) => {
            JobResult::Token(GenerateToken::new(repos.admin.as_ref()).execute(&ty))
        }
        Job::AdminProbe => JobResult::AdminAllowed(repos.admin.can_admin()),
        Job::Aggregate { tab, ctx } => {
            let cluster = ctx.name.to_string();
            let rows = aggregate_rows(repos, tab, &ctx);
            JobResult::Aggregate { tab, cluster, rows }
        }
    }
}

/// One cluster's rows for an all-clusters admin fan-out. `tctl` targets the
/// currently logged-in proxy, so the caller re-selects `ctx` (`select_cluster`)
/// — which is why the fan-out runs serially on one thread, not the concurrent
/// per-cluster jobs used for cluster-scoped tabs (a parallel profile switch would
/// race). A cluster without a live session yields a single `login_required`
/// placeholder instead of erroring.
fn admin_cluster_rows(repos: &Repositories, tab: Tab, ctx: &ClusterContext) -> Vec<AggRow> {
    let cluster = ctx.name.to_string();
    // Recordings carries a per-row sid (for `tsh play`); the admin tabs don't.
    if tab == Tab::Recordings {
        return match repos.admin.select_cluster(&cluster) {
            Ok(()) => match ListRecordings::new(repos.recordings.as_ref()).execute(ctx) {
                Ok(recs) => recs
                    .into_iter()
                    .map(|r| AggRow {
                        cluster: cluster.clone(),
                        cells: r.row(),
                        login_required: false,
                        sid: Some(r.sid),
                    })
                    .collect(),
                Err(e) => vec![err_row(cluster, &e)],
            },
            Err(_) => vec![login_required_row(cluster)],
        };
    }
    match repos.admin.select_cluster(&cluster) {
        Ok(()) => match admin_rows(repos, tab) {
            Ok(rows) => rows
                .into_iter()
                .map(|cells| AggRow {
                    cluster: cluster.clone(),
                    cells,
                    login_required: false,
                    sid: None,
                })
                .collect(),
            Err(e) => vec![err_row(cluster, &e)],
        },
        Err(_) => vec![login_required_row(cluster)],
    }
}

/// Tag a cluster's plain display rows as `AggRow`s (concurrent resource path).
pub(super) fn agg_rows_of(cluster: &str, cells_list: Vec<Vec<String>>) -> Vec<AggRow> {
    cells_list
        .into_iter()
        .map(|cells| AggRow {
            cluster: cluster.to_owned(),
            cells,
            login_required: false,
            sid: None,
        })
        .collect()
}

fn err_row(cluster: String, e: &AppError) -> AggRow {
    AggRow {
        cluster,
        cells: vec![format!("⚠ {}", e.message())],
        login_required: false,
        sid: None,
    }
}

fn login_required_row(cluster: String) -> AggRow {
    AggRow {
        cluster,
        cells: vec!["⚠ not logged in".to_owned()],
        login_required: true,
        sid: None,
    }
}

/// Display rows for an admin `tab` against the *current* profile (Recordings is
/// handled separately in [`admin_cluster_rows`] because it also carries a sid).
fn admin_rows(repos: &Repositories, tab: Tab) -> Result<Vec<Vec<String>>, AppError> {
    fn rows<T: Resource>(items: Vec<T>) -> Vec<Vec<String>> {
        items.into_iter().map(|it| it.row()).collect()
    }
    match tab {
        Tab::Users => ListUsers::new(repos.admin.as_ref()).execute().map(rows),
        Tab::Roles => ListRoles::new(repos.admin.as_ref()).execute().map(rows),
        Tab::Tokens => ListTokens::new(repos.admin.as_ref()).execute().map(rows),
        Tab::Bots => ListBots::new(repos.admin.as_ref()).execute().map(rows),
        Tab::Inventory => ListInstances::new(repos.admin.as_ref()).execute().map(rows),
        _ => Ok(Vec::new()),
    }
}

/// Run the listing for `tab` scoped to `ctx`, returning each item's display row.
fn aggregate_rows(
    repos: &Repositories,
    tab: Tab,
    ctx: &ClusterContext,
) -> Result<Vec<Vec<String>>, AppError> {
    fn rows<T: Resource>(items: Vec<T>) -> Vec<Vec<String>> {
        items.into_iter().map(|it| it.row()).collect()
    }
    match tab {
        Tab::Ssh => ListNodes::new(repos.nodes.as_ref()).execute(ctx).map(rows),
        Tab::Kube => ListKube::new(repos.kube.as_ref()).execute(ctx).map(rows),
        Tab::Db => ListDatabases::new(repos.databases.as_ref())
            .execute(ctx)
            .map(rows),
        Tab::Apps => ListApps::new(repos.apps.as_ref()).execute(ctx).map(rows),
        Tab::Requests => ListRequests::new(repos.requests.as_ref())
            .execute(ctx)
            .map(rows),
        Tab::Recordings => ListRecordings::new(repos.recordings.as_ref())
            .execute(ctx)
            .map(rows),
        Tab::Users | Tab::Roles | Tab::Tokens | Tab::Bots | Tab::Inventory => Ok(Vec::new()),
    }
}

/// The concurrency seam. Owns the repository ports and the background job/proxy
/// channels, and knows how to run a [`Job`] — inline in `synchronous` mode (for
/// deterministic tests) or on a worker thread otherwise. Pulling this out keeps
/// the threading / channel / `Send + Sync` plumbing out of [`App`], which is
/// left to own view and session state.
#[derive(Debug)]
pub(super) struct Dispatcher {
    repos: Arc<Repositories>,
    job_tx: Sender<(u64, JobResult)>,
    job_rx: Receiver<(u64, JobResult)>,
    proxy_tx: Sender<ProxyEvent>,
    proxy_rx: Receiver<ProxyEvent>,
    /// Serialises every mutation of the global `~/.tsh` active profile
    /// (`tsh login --proxy`, via `select_cluster`). `tctl` has no cluster flag,
    /// so the admin fan-out and the post-action root restore both re-key the one
    /// shared profile; without this lock two concurrent worker threads could flip
    /// it mid-listing and make a `tctl` read return another cluster's data.
    profile_lock: Arc<Mutex<()>>,
    /// Bounded worker pool for [`Dispatcher::spawn_job`] (async mode only). A wide
    /// fan-out (one job per tab per online cluster) enqueues here instead of
    /// spawning an unbounded number of threads / concurrent `tsh` subprocesses.
    /// `None` in synchronous mode (jobs run inline). The serial fan-outs
    /// (`spawn_admin_stream`, `spawn_after_action`) keep dedicated threads.
    work_tx: Option<Sender<(u64, Job)>>,
    /// Run jobs inline instead of off-thread (used by tests for determinism).
    synchronous: bool,
}

impl Dispatcher {
    pub(super) fn new(repos: Repositories, synchronous: bool) -> Self {
        let (job_tx, job_rx) = mpsc::channel();
        let (proxy_tx, proxy_rx) = mpsc::channel();
        let repos = Arc::new(repos);
        // Async mode drains jobs through a bounded worker pool; sync mode runs
        // them inline (so no pool is needed).
        let work_tx = (!synchronous).then(|| Self::start_pool(&repos, &job_tx));
        Self {
            repos,
            job_tx,
            job_rx,
            proxy_tx,
            proxy_rx,
            profile_lock: Arc::new(Mutex::new(())),
            work_tx,
            synchronous,
        }
    }

    /// Start a small fixed pool of worker threads that pull queued jobs off a
    /// shared channel and send each result back on `job_tx`. Bounding the worker
    /// count caps how many `tsh`/`tctl` subprocesses one fan-out can run at once
    /// (a topology switch would otherwise spawn a thread per tab per cluster). The
    /// receiver lock is held only to dequeue — never across `run_job` — so the
    /// workers still execute jobs concurrently, up to the pool size.
    fn start_pool(
        repos: &Arc<Repositories>,
        job_tx: &Sender<(u64, JobResult)>,
    ) -> Sender<(u64, Job)> {
        let (work_tx, work_rx) = mpsc::channel::<(u64, Job)>();
        let work_rx = Arc::new(Mutex::new(work_rx));
        let workers = std::thread::available_parallelism().map_or(4, |n| n.get().clamp(2, 8));
        for _ in 0..workers {
            let rx = Arc::clone(&work_rx);
            let repos = Arc::clone(repos);
            let job_tx = job_tx.clone();
            std::thread::spawn(move || {
                loop {
                    // Dequeue under the lock, then drop it before running the job
                    // so another worker can pull the next job in parallel.
                    let next = {
                        let guard = rx.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        guard.recv()
                    };
                    let Ok((seq, job)) = next else {
                        break; // every sender dropped → the pool is shutting down
                    };
                    let _ = job_tx.send((seq, run_job(&repos, job)));
                }
            });
        }
        work_tx
    }

    /// Run a job. In synchronous mode the result is returned for the caller to
    /// apply immediately (deterministic tests); otherwise it runs on a worker
    /// thread and lands later via [`Dispatcher::drain_jobs`]. So a `Some` return
    /// means "apply this now", `None` means "it'll arrive on the channel".
    pub(super) fn spawn_job(&self, seq: u64, job: Job) -> Option<(u64, JobResult)> {
        if self.synchronous {
            return Some((seq, run_job(&self.repos, job)));
        }
        // Enqueue on the bounded pool instead of spawning a thread per job.
        if let Some(tx) = &self.work_tx {
            let _ = tx.send((seq, job));
        }
        None
    }

    /// All-clusters admin fan-out, **streamed serially**: `tctl` has no cluster
    /// flag, so we re-select each cluster in turn (one thread — a parallel switch
    /// would race), but emit one `AggregateAdmin` result *per cluster* as it
    /// finishes so the reachable clusters (root first) render without waiting for
    /// the leaves. The root profile is restored at the end. In synchronous mode
    /// the per-cluster results are returned for inline application (tests).
    pub(super) fn spawn_admin_stream(
        &self,
        seq: u64,
        tab: Tab,
        clusters: Vec<ClusterContext>,
        root: String,
    ) -> Vec<(u64, JobResult)> {
        if self.synchronous {
            let mut out = Vec::new();
            for ctx in &clusters {
                let rows = admin_cluster_rows(&self.repos, tab, ctx);
                self.restore_profile(&root);
                out.push((
                    seq,
                    JobResult::AggregateAdmin {
                        tab,
                        cluster: ctx.name.to_string(),
                        rows,
                    },
                ));
            }
            return out;
        }
        let repos = Arc::clone(&self.repos);
        let tx = self.job_tx.clone();
        let profile_lock = Arc::clone(&self.profile_lock);
        std::thread::spawn(move || {
            for ctx in &clusters {
                let cluster = ctx.name.to_string();
                // Hold the profile lock across the whole switch→read→restore, so a
                // second concurrent fan-out (or a `spawn_after_action` restore)
                // can't flip the global profile mid-listing and make this `tctl`
                // read return another cluster's rows.
                let rows = {
                    let _guard = profile_lock
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let rows = admin_cluster_rows(&repos, tab, ctx);
                    // Restore root while still holding the lock — the active profile
                    // is then only ever on a leaf inside this critical section. So
                    // if the app exits mid-fan (worker thread killed), the profile
                    // is left on root, not stranded on a leaf (which would break
                    // every later tsh/tctl call).
                    let _ = repos.admin.select_cluster(&root);
                    rows
                };
                // Keep going even if a send fails (app exiting).
                let _ = tx.send((seq, JobResult::AggregateAdmin { tab, cluster, rows }));
            }
        });
        Vec::new()
    }

    /// Post-interactive refresh, off the UI thread. Optionally restores the root
    /// profile first (a global `~/.tsh` mutation → taken under [`profile_lock`],
    /// serialised against [`Dispatcher::spawn_admin_stream`]), then re-reads
    /// status and — when the action was a login/logout (`reload_topology`) — the
    /// topology and admin probe. The restore is ordered *before* the reads by
    /// running them on one worker thread, so the blocking `tsh login --proxy`
    /// re-key never freezes the UI. Synchronous mode applies the results inline.
    ///
    /// [`profile_lock`]: Dispatcher::profile_lock
    pub(super) fn spawn_after_action(
        &self,
        restore_root: Option<String>,
        reload_topology: bool,
    ) -> Vec<(u64, JobResult)> {
        if self.synchronous {
            if let Some(root) = &restore_root {
                let _ = self.repos.admin.select_cluster(root);
            }
            let mut out = vec![(0, run_job(&self.repos, Job::Status))];
            if reload_topology {
                out.push((0, run_job(&self.repos, Job::Clusters)));
                out.push((0, run_job(&self.repos, Job::AdminProbe)));
            }
            return out;
        }
        let repos = Arc::clone(&self.repos);
        let tx = self.job_tx.clone();
        let profile_lock = Arc::clone(&self.profile_lock);
        std::thread::spawn(move || {
            if let Some(root) = restore_root {
                let _guard = profile_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = repos.admin.select_cluster(&root);
            }
            let _ = tx.send((0, run_job(&repos, Job::Status)));
            if reload_topology {
                let _ = tx.send((0, run_job(&repos, Job::Clusters)));
                let _ = tx.send((0, run_job(&repos, Job::AdminProbe)));
            }
        });
        Vec::new()
    }

    /// Drain all finished background jobs (FIFO), non-blocking.
    pub(super) fn drain_jobs(&self) -> Vec<(u64, JobResult)> {
        let mut out = Vec::new();
        while let Ok(item) = self.job_rx.try_recv() {
            out.push(item);
        }
        out
    }

    /// A clone of the proxy-event sender for a worker thread to report back on.
    pub(super) fn proxy_sender(&self) -> Sender<ProxyEvent> {
        self.proxy_tx.clone()
    }

    /// Synchronously re-select a profile (`tsh login --proxy`). Used to restore
    /// the root profile right after an all-clusters leaf login, before the next
    /// cluster/status refresh — a fast, valid-cert re-key, so blocking the UI
    /// briefly here is acceptable. Errors are non-fatal (the aggregate fan-out
    /// restores root again at its end anyway).
    fn restore_profile(&self, proxy: &str) {
        let _ = self.repos.admin.select_cluster(proxy);
    }

    /// Drain all completed background proxy launches, non-blocking.
    pub(super) fn drain_proxy(&self) -> Vec<ProxyEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = self.proxy_rx.try_recv() {
            out.push(ev);
        }
        out
    }
}
