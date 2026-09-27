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
    /// Remove a provision token by its name (`tctl tokens rm`), a join secret
    /// for the `token` method, so it travels as a wiped-on-drop `SecretString`.
    RemoveToken(SecretString),
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
    /// The admin-rights probe could not run at all (spawn failure / timeout):
    /// reported, then treated as "no admin rights".
    AdminProbeFailed(AppError),
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
    /// Re-selecting the root profile after a leaf-scoped operation failed, so
    /// `~/.tsh` may still point at a leaf. Surfaced (status bar + error log)
    /// instead of dropped: every later `tsh`/`tctl` call would read the leaf.
    RestoreFailed {
        root: String,
        error: AppError,
    },
}

/// Run a job against the repositories. Pure dispatch - safe to call from a
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
            JobResult::TokenRemoved(RemoveToken::new(repos.admin.as_ref()).execute(token.expose()))
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
        Job::AdminProbe => match repos.admin.can_admin() {
            Ok(ok) => JobResult::AdminAllowed(ok),
            Err(e) => JobResult::AdminProbeFailed(e.into()),
        },
        Job::Aggregate { tab, ctx } => {
            let cluster = ctx.name.to_string();
            let rows = aggregate_rows(repos, tab, &ctx);
            JobResult::Aggregate { tab, cluster, rows }
        }
    }
}

/// The error result of `job`, for when it cannot run at all (its cluster could
/// not be selected). Keeps the job's own result variant so the UI applies it
/// like any failed listing - never another cluster's rows under this label.
fn failed_job(job: Job, e: AppError) -> JobResult {
    match job {
        Job::Clusters => JobResult::Clusters(Err(e)),
        Job::Status => JobResult::Status(Err(e)),
        Job::Nodes(_) => JobResult::Nodes(Err(e)),
        Job::Kube(_) => JobResult::Kube(Err(e)),
        Job::Db(_) => JobResult::Db(Err(e)),
        Job::Apps(_) => JobResult::Apps(Err(e)),
        Job::Requests(_) => JobResult::Requests(Err(e)),
        Job::Recordings(_) => JobResult::Recordings(Err(e)),
        Job::Users => JobResult::Users(Err(e)),
        Job::Roles => JobResult::Roles(Err(e)),
        Job::Tokens => JobResult::Tokens(Err(e)),
        Job::Bots => JobResult::Bots(Err(e)),
        Job::Instances => JobResult::Instances(Err(e)),
        Job::Mfa => JobResult::Mfa(Err(e)),
        Job::Sessions(_) => JobResult::Sessions(Err(e)),
        Job::RemoveToken(_) => JobResult::TokenRemoved(Err(e)),
        Job::AddUser { .. } | Job::ResetUser(_) => JobResult::Invite(Err(e)),
        Job::GenerateToken(_) => JobResult::Token(Err(e)),
        Job::AdminProbe => JobResult::AdminProbeFailed(e),
        Job::Aggregate { tab, ctx } => JobResult::Aggregate {
            tab,
            cluster: ctx.name.to_string(),
            rows: Err(e),
        },
    }
}

/// Run `job` against `cluster` (re-keyed first), then restore `root`. If the
/// switch fails the job is not run (it would read whatever cluster the profile
/// is on) and its error result is returned instead. A failed restore adds a
/// [`JobResult::RestoreFailed`] after the job's result.
fn run_scoped(repos: &Repositories, job: Job, cluster: &str, root: &str) -> Vec<JobResult> {
    let result = match repos.admin.select_cluster(cluster) {
        Ok(()) => run_job(repos, job),
        Err(e) => failed_job(job, e.into()),
    };
    let mut out = vec![result];
    out.extend(restore_root(repos, root));
    out
}

/// Re-select the `root` profile; `Some(RestoreFailed)` if that fails.
fn restore_root(repos: &Repositories, root: &str) -> Option<JobResult> {
    repos
        .admin
        .select_cluster(root)
        .err()
        .map(|e| JobResult::RestoreFailed {
            root: root.to_owned(),
            error: e.into(),
        })
}

/// One cluster's rows for an all-clusters admin fan-out. `tctl` targets the
/// currently logged-in proxy, so the caller re-selects `ctx` (`select_cluster`),
/// which is why the fan-out runs serially on one thread, not the concurrent
/// per-cluster jobs used for cluster-scoped tabs (a parallel profile switch would
/// race). A cluster without a live session yields a single `login_required`
/// placeholder; any other switch failure yields an error row.
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
                        error: false,
                        sid: Some(r.sid),
                    })
                    .collect(),
                Err(e) => vec![err_row(cluster, &e)],
            },
            Err(e) => vec![select_failed_row(cluster, e)],
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
                    error: false,
                    sid: None,
                })
                .collect(),
            Err(e) => vec![err_row(cluster, &e)],
        },
        Err(e) => vec![select_failed_row(cluster, e)],
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
            error: false,
            sid: None,
        })
        .collect()
}

/// A placeholder row carrying a cluster's listing error.
pub(super) fn err_row(cluster: String, e: &AppError) -> AggRow {
    AggRow {
        cluster,
        cells: vec![format!("⚠ {}", e.message())],
        login_required: false,
        error: true,
        sid: None,
    }
}

/// The placeholder for a cluster whose profile could not be selected: a
/// login-required row (actionable with `L`) when only a fresh login can fix it,
/// otherwise the real error (network, backend, …).
fn select_failed_row(cluster: String, e: DomainError) -> AggRow {
    match e {
        DomainError::NotAuthenticated | DomainError::CertExpired => login_required_row(cluster),
        e => err_row(cluster, &e.into()),
    }
}

fn login_required_row(cluster: String) -> AggRow {
    AggRow {
        cluster,
        cells: vec!["⚠ not logged in".to_owned()],
        login_required: true,
        error: false,
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
/// channels, and knows how to run a [`Job`] - inline in `synchronous` mode (for
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
    /// receiver lock is held only to dequeue - never across `run_job` - so the
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

    /// Run a single-cluster admin (`tctl`) job against `cluster` by re-keying the
    /// profile to it first (`tsh login --proxy`), then restoring `root`. `tctl`
    /// has no cluster flag - it targets whatever cluster `~/.tsh` currently points
    /// at - so without this a scoped admin listing would hit a leaf profile (the
    /// UI's cluster selection does not re-key the profile) and error. Runs on a
    /// dedicated thread under [`profile_lock`], serialised against the admin
    /// fan-out and the after-action restore so the shared profile can't be flipped
    /// mid-listing. Restoring to root (not the leaf) leaves the profile where the
    /// follow-up admin *actions* (`tokens add`, `users add`, …) also work. The
    /// listing's `JobResult` type is unchanged; only its execution is wrapped.
    ///
    /// [`profile_lock`]: Dispatcher::profile_lock
    pub(super) fn spawn_admin_scoped(
        &self,
        seq: u64,
        job: Job,
        cluster: String,
        root: String,
    ) -> Vec<(u64, JobResult)> {
        if self.synchronous {
            return run_scoped(&self.repos, job, &cluster, &root)
                .into_iter()
                .map(|r| (seq, r))
                .collect();
        }
        let repos = Arc::clone(&self.repos);
        let tx = self.job_tx.clone();
        let profile_lock = Arc::clone(&self.profile_lock);
        std::thread::spawn(move || {
            // Switch, read and restore root all inside the critical section (see
            // spawn_admin_stream).
            let results = {
                let _guard = profile_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                run_scoped(&repos, job, &cluster, &root)
            };
            for result in results {
                let _ = tx.send((seq, result));
            }
        });
        Vec::new()
    }

    /// All-clusters admin fan-out, **streamed serially**: `tctl` has no cluster
    /// flag, so we re-select each cluster in turn (one thread - a parallel switch
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
                let restore = restore_root(&self.repos, &root);
                out.push((
                    seq,
                    JobResult::AggregateAdmin {
                        tab,
                        cluster: ctx.name.to_string(),
                        rows,
                    },
                ));
                out.extend(restore.map(|r| (seq, r)));
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
                let (rows, restore) = {
                    let _guard = profile_lock
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let rows = admin_cluster_rows(&repos, tab, ctx);
                    // Restore root while still holding the lock - the active profile
                    // is then only ever on a leaf inside this critical section. So
                    // if the app exits mid-fan (worker thread killed), the profile
                    // is left on root, not stranded on a leaf (which would break
                    // every later tsh/tctl call).
                    (rows, restore_root(&repos, &root))
                };
                // Keep going even if a send fails (app exiting).
                let _ = tx.send((seq, JobResult::AggregateAdmin { tab, cluster, rows }));
                if let Some(failed) = restore {
                    let _ = tx.send((seq, failed));
                }
            }
        });
        Vec::new()
    }

    /// Post-interactive refresh, off the UI thread. Optionally restores the root
    /// profile first (a global `~/.tsh` mutation → taken under [`profile_lock`],
    /// serialised against [`Dispatcher::spawn_admin_stream`]), then re-reads
    /// status and - when the action was a login/logout (`reload_topology`) - the
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
            let failed = restore_root
                .as_deref()
                .and_then(|root| self::restore_root(&self.repos, root));
            let mut out = vec![(0, run_job(&self.repos, Job::Status))];
            if reload_topology {
                out.push((0, run_job(&self.repos, Job::Clusters)));
                out.push((0, run_job(&self.repos, Job::AdminProbe)));
            }
            // Reported last so the refresh's own status doesn't hide it.
            out.extend(failed.map(|r| (0, r)));
            return out;
        }
        let repos = Arc::clone(&self.repos);
        let tx = self.job_tx.clone();
        let profile_lock = Arc::clone(&self.profile_lock);
        std::thread::spawn(move || {
            let failed = restore_root.and_then(|root| {
                let _guard = profile_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                self::restore_root(&repos, &root)
            });
            let _ = tx.send((0, run_job(&repos, Job::Status)));
            if reload_topology {
                let _ = tx.send((0, run_job(&repos, Job::Clusters)));
                let _ = tx.send((0, run_job(&repos, Job::AdminProbe)));
            }
            // Reported last so the refresh's own status doesn't hide it.
            if let Some(failed) = failed {
                let _ = tx.send((0, failed));
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

    /// Drain all completed background proxy launches, non-blocking.
    pub(super) fn drain_proxy(&self) -> Vec<ProxyEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = self.proxy_rx.try_recv() {
            out.push(ev);
        }
        out
    }
}
