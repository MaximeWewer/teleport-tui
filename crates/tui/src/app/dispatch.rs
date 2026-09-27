//! The concurrency seam: the background `Job`/`JobResult` protocol, the pure
//! `run_job` dispatch, and the `Dispatcher` that runs jobs off the UI thread (a
//! bounded worker pool plus the serial admin / after-action fan-outs). Split out
//! of `app` so the threading / channel / `Send + Sync` plumbing lives apart from
//! the view/update state in [`super::App`].
//!
//! A child module of `app`: it uses the parent's model types (`Repositories`,
//! `Tab`, `AggRow`, `ProxyEvent`) from `super`.

use std::collections::VecDeque;
use std::sync::Condvar;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use application::use_case::{
    AddUser, GenerateToken, GetStatus, ListApps, ListBots, ListClusters, ListDatabases,
    ListInstances, ListKube, ListMfaDevices, ListNodes, ListRecordings, ListRequests, ListRoles,
    ListSessions, ListTokens, ListUsers, ProbeAdminRights, RemoveToken, ResetUser, SelectCluster,
};
use domain::admin::{
    AdminRole, AdminUser, Bot, GeneratedToken, Instance, InviteLink, ProvisionToken,
};
use domain::cluster::{ClusterContext, ClusterTopology};
use domain::error::{DomainError, ReportableError};
use domain::mfa::MfaDevice;
use domain::node::SshNode;
use domain::profile::Profile;
use domain::recording::SessionRecording;
use domain::request::AccessRequest;
use domain::resource::{App as AppResource, Database, KubeCluster, Resource};
use domain::secret::SecretString;
use domain::session::ActiveSession;
use domain::value::{ClusterName, ResourceName, RoleList, TokenTypes};

use super::{AggRow, ProxyEvent, Repositories, Tab};

/// A unit of CLI work to run off the UI thread.
#[derive(Debug)]
pub(super) enum Job {
    Clusters,
    Status,
    /// A tab's listing (see [`list_tab`]): `ctx` is the cluster for a
    /// cluster-scoped tab, `None` for an admin tab (current profile).
    List {
        tab: Tab,
        ctx: Option<ClusterContext>,
    },
    /// List the current user's MFA devices (`tsh mfa ls`).
    Mfa,
    /// List active sessions to join (`tsh sessions ls -c <cluster>`).
    Sessions(ClusterContext),
    /// Remove a provision token by its name (`tctl tokens rm`), a join secret
    /// for the `token` method, so it travels as a wiped-on-drop `SecretString`.
    RemoveToken(SecretString),
    /// Create a user with roles (`tctl users add`) → one-time invite URL.
    AddUser {
        user: ResourceName,
        roles: RoleList,
    },
    /// Reset a user's credentials (`tctl users reset`) → one-time reset URL.
    ResetUser(ResourceName),
    GenerateToken(TokenTypes),
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
    Clusters(Result<ClusterTopology, DomainError>),
    Status(Result<Option<Profile>, DomainError>),
    List {
        tab: Tab,
        result: Result<Listing, DomainError>,
    },
    Mfa(Result<Vec<MfaDevice>, DomainError>),
    Sessions(Result<Vec<ActiveSession>, DomainError>),
    TokenRemoved(Result<(), DomainError>),
    Invite(Result<InviteLink, DomainError>),
    Token(Result<GeneratedToken, DomainError>),
    AdminAllowed(bool),
    /// The admin-rights probe could not run at all (spawn failure / timeout):
    /// reported, then treated as "no admin rights".
    AdminProbeFailed(DomainError),
    /// One cluster's slice of a concurrent (`tsh -c`) aggregate. Carries `tab` +
    /// `cluster` so it caches per-cluster even after the user navigates away.
    Aggregate {
        tab: Tab,
        cluster: ClusterName,
        rows: Result<Vec<AggRow>, DomainError>,
    },
    /// One cluster's slice of a serial admin/recordings fan-out (its rows, or a
    /// login-required placeholder), already tagged. Streamed one per cluster;
    /// caches per-cluster so partial progress survives navigation.
    AggregateAdmin {
        tab: Tab,
        cluster: ClusterName,
        rows: Vec<AggRow>,
    },
    /// Re-selecting the root profile after a leaf-scoped operation failed, so
    /// `~/.tsh` may still point at a leaf. Surfaced (status bar + error log)
    /// instead of dropped: every later `tsh`/`tctl` call would read the leaf.
    RestoreFailed {
        root: ClusterName,
        error: DomainError,
    },
}

impl Job {
    /// The listing job for `tab`: admin tabs need no cluster, cluster-scoped
    /// tabs need `ctx` (`None` without one, e.g. before the topology loads).
    pub(super) fn list(tab: Tab, ctx: Option<&ClusterContext>) -> Option<Self> {
        if tab.is_admin() {
            return Some(Self::List { tab, ctx: None });
        }
        ctx.map(|ctx| Self::List {
            tab,
            ctx: Some(ctx.clone()),
        })
    }
}

/// One tab's typed listing, as returned by its use case (see [`list_tab`]).
pub(super) enum Listing {
    Nodes(Vec<SshNode>),
    Kube(Vec<KubeCluster>),
    Db(Vec<Database>),
    Apps(Vec<AppResource>),
    Requests(Vec<AccessRequest>),
    Recordings(Vec<SessionRecording>),
    Users(Vec<AdminUser>),
    Roles(Vec<AdminRole>),
    Tokens(Vec<ProvisionToken>),
    Bots(Vec<Bot>),
    Instances(Vec<Instance>),
}

impl Listing {
    /// Each item's display row, tagged with `cluster` for the aggregate view.
    /// Recordings keep their `sid` (not a displayed column) so the aggregate
    /// can still `tsh play` them.
    pub(super) fn into_agg_rows(self, cluster: &ClusterName) -> Vec<AggRow> {
        fn tag<T: Resource>(cluster: &ClusterName, items: &[T]) -> Vec<AggRow> {
            agg_rows_of(cluster, items.iter().map(Resource::row).collect())
        }
        match self {
            Self::Nodes(v) => tag(cluster, &v),
            Self::Kube(v) => tag(cluster, &v),
            Self::Db(v) => tag(cluster, &v),
            Self::Apps(v) => tag(cluster, &v),
            Self::Requests(v) => tag(cluster, &v),
            Self::Users(v) => tag(cluster, &v),
            Self::Roles(v) => tag(cluster, &v),
            Self::Tokens(v) => tag(cluster, &v),
            Self::Bots(v) => tag(cluster, &v),
            Self::Instances(v) => tag(cluster, &v),
            Self::Recordings(v) => v
                .into_iter()
                .map(|r| AggRow {
                    cluster: cluster.clone(),
                    cells: r.row(),
                    login_required: false,
                    error: false,
                    sid: Some(r.sid),
                })
                .collect(),
        }
    }
}

/// The one Tab -> use-case table: run `tab`'s listing. Cluster-scoped tabs list
/// `ctx` (`tsh -c`); admin tabs (`tctl`) target the current profile and ignore
/// it. A cluster-scoped tab without a `ctx` is a caller bug (see [`Job::list`])
/// and reported as an invalid value rather than listing some other cluster.
fn list_tab(
    repos: &Repositories,
    tab: Tab,
    ctx: Option<&ClusterContext>,
) -> Result<Listing, DomainError> {
    let scoped = || ctx.ok_or(DomainError::InvalidValue { field: "cluster" });
    let admin = repos.admin.as_ref();
    match tab {
        Tab::Ssh => ListNodes::new(repos.nodes.as_ref())
            .execute(scoped()?)
            .map(Listing::Nodes),
        Tab::Kube => ListKube::new(repos.kube.as_ref())
            .execute(scoped()?)
            .map(Listing::Kube),
        Tab::Db => ListDatabases::new(repos.databases.as_ref())
            .execute(scoped()?)
            .map(Listing::Db),
        Tab::Apps => ListApps::new(repos.apps.as_ref())
            .execute(scoped()?)
            .map(Listing::Apps),
        Tab::Requests => ListRequests::new(repos.requests.as_ref())
            .execute(scoped()?)
            .map(Listing::Requests),
        Tab::Recordings => ListRecordings::new(repos.recordings.as_ref())
            .execute(scoped()?)
            .map(Listing::Recordings),
        Tab::Users => ListUsers::new(admin).execute().map(Listing::Users),
        Tab::Roles => ListRoles::new(admin).execute().map(Listing::Roles),
        Tab::Tokens => ListTokens::new(admin).execute().map(Listing::Tokens),
        Tab::Bots => ListBots::new(admin).execute().map(Listing::Bots),
        Tab::Inventory => ListInstances::new(admin).execute().map(Listing::Instances),
    }
}

/// Run a job against the repositories. Pure dispatch - safe to call from a
/// worker thread (repos are `Send + Sync`).
fn run_job(repos: &Repositories, job: Job) -> JobResult {
    match job {
        Job::Clusters => JobResult::Clusters(ListClusters::new(repos.clusters.as_ref()).execute()),
        Job::Status => JobResult::Status(GetStatus::new(repos.auth.as_ref()).execute()),
        Job::List { tab, ctx } => JobResult::List {
            tab,
            result: list_tab(repos, tab, ctx.as_ref()),
        },
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
        Job::AdminProbe => match ProbeAdminRights::new(repos.admin.as_ref()).execute() {
            Ok(ok) => JobResult::AdminAllowed(ok),
            Err(e) => JobResult::AdminProbeFailed(e),
        },
        Job::Aggregate { tab, ctx } => JobResult::Aggregate {
            tab,
            rows: list_tab(repos, tab, Some(&ctx)).map(|l| l.into_agg_rows(&ctx.name)),
            cluster: ctx.name,
        },
    }
}

/// The error result of `job`, for when it cannot run at all (its cluster could
/// not be selected). Keeps the job's own result variant so the UI applies it
/// like any failed listing - never another cluster's rows under this label.
fn failed_job(job: Job, e: DomainError) -> JobResult {
    match job {
        Job::Clusters => JobResult::Clusters(Err(e)),
        Job::Status => JobResult::Status(Err(e)),
        Job::List { tab, .. } => JobResult::List {
            tab,
            result: Err(e),
        },
        Job::Mfa => JobResult::Mfa(Err(e)),
        Job::Sessions(_) => JobResult::Sessions(Err(e)),
        Job::RemoveToken(_) => JobResult::TokenRemoved(Err(e)),
        Job::AddUser { .. } | Job::ResetUser(_) => JobResult::Invite(Err(e)),
        Job::GenerateToken(_) => JobResult::Token(Err(e)),
        Job::AdminProbe => JobResult::AdminProbeFailed(e),
        Job::Aggregate { tab, ctx } => JobResult::Aggregate {
            tab,
            cluster: ctx.name,
            rows: Err(e),
        },
    }
}

/// Run `job` against `cluster` (re-keyed first), then restore `root`. If the
/// switch fails the job is not run (it would read whatever cluster the profile
/// is on) and its error result is returned instead. A failed restore adds a
/// [`JobResult::RestoreFailed`] after the job's result.
fn run_scoped(
    repos: &Repositories,
    job: Job,
    cluster: &ClusterName,
    root: &ClusterName,
) -> Vec<JobResult> {
    let result = match select_cluster(repos, cluster) {
        Ok(()) => run_job(repos, job),
        Err(e) => failed_job(job, e),
    };
    let mut out = vec![result];
    out.extend(restore_root(repos, root));
    out
}

/// [`run_scoped`], unless `seq` is no longer the latest active-tab request. Called
/// once the profile lock is held: by then a newer tab load may have been issued
/// (the user flicked past this tab), and the UI discards a stale `seq`'s result
/// anyway, so the superseded job skips its ~3s of `tsh login` + `tctl` + restore
/// and yields nothing instead of delaying the job the user landed on.
pub(super) fn run_scoped_if_latest(
    repos: &Repositories,
    latest: &AtomicU64,
    seq: u64,
    job: Job,
    cluster: &ClusterName,
    root: &ClusterName,
) -> Vec<JobResult> {
    if latest.load(Ordering::Acquire) != seq {
        return Vec::new();
    }
    run_scoped(repos, job, cluster, root)
}

/// Make `cluster` the active profile (`tsh login <cluster>`).
fn select_cluster(repos: &Repositories, cluster: &ClusterName) -> Result<(), DomainError> {
    SelectCluster::new(repos.auth.as_ref()).execute(cluster)
}

/// Re-select the `root` profile; `Some(RestoreFailed)` if that fails.
fn restore_root(repos: &Repositories, root: &ClusterName) -> Option<JobResult> {
    select_cluster(repos, root)
        .err()
        .map(|error| JobResult::RestoreFailed {
            root: root.clone(),
            error,
        })
}

/// One cluster's rows for an all-clusters admin fan-out. `tctl` targets the
/// currently logged-in proxy, so the caller re-selects `ctx` (`select_cluster`),
/// which is why the fan-out runs serially on one thread, not the concurrent
/// per-cluster jobs used for cluster-scoped tabs (a parallel profile switch would
/// race). A cluster without a live session yields a single `login_required`
/// placeholder; any other switch failure yields an error row.
fn admin_cluster_rows(repos: &Repositories, tab: Tab, ctx: &ClusterContext) -> Vec<AggRow> {
    let cluster = ctx.name.clone();
    match select_cluster(repos, &cluster) {
        Ok(()) => match list_tab(repos, tab, Some(ctx)) {
            Ok(listing) => listing.into_agg_rows(&cluster),
            Err(e) => vec![err_row(cluster, &e)],
        },
        Err(e) => vec![select_failed_row(cluster, e)],
    }
}

/// Tag a cluster's plain display rows as `AggRow`s (concurrent resource path).
pub(super) fn agg_rows_of(cluster: &ClusterName, cells_list: Vec<Vec<String>>) -> Vec<AggRow> {
    cells_list
        .into_iter()
        .map(|cells| AggRow {
            cluster: cluster.clone(),
            cells,
            login_required: false,
            error: false,
            sid: None,
        })
        .collect()
}

/// A placeholder row carrying a cluster's listing error.
pub(super) fn err_row(cluster: ClusterName, e: &DomainError) -> AggRow {
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
fn select_failed_row(cluster: ClusterName, e: DomainError) -> AggRow {
    match e {
        DomainError::NotAuthenticated | DomainError::CertExpired => login_required_row(cluster),
        e => err_row(cluster, &e),
    }
}

fn login_required_row(cluster: ClusterName) -> AggRow {
    AggRow {
        cluster,
        cells: vec!["⚠ not logged in".to_owned()],
        login_required: true,
        error: false,
        sid: None,
    }
}

/// Which queue a pooled job goes to, and how it can go stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Lane {
    /// The active tab's listing: runs first; dropped unrun if a newer tab
    /// request was issued meanwhile (its result would be discarded anyway).
    Tab,
    /// Background warm-up of another tab: runs only when nothing else is
    /// queued; dropped unrun if its batch was superseded (cluster change).
    Prefetch,
    /// Anything else (status, topology, actions, aggregate slices): runs first
    /// and is never dropped.
    Other,
}

/// One queued pool job.
#[derive(Debug)]
pub(super) struct Work {
    pub(super) seq: u64,
    pub(super) job: Job,
    pub(super) lane: Lane,
}

#[derive(Debug, Default)]
struct Queues {
    /// Jobs the user is waiting on (active tab, status, actions, aggregate).
    urgent: VecDeque<Work>,
    /// Prefetch jobs, only dequeued when nothing urgent is queued.
    background: VecDeque<Work>,
    /// Set when the dispatcher is dropped: workers exit.
    closed: bool,
}

/// The worker pool's two-level FIFO: urgent jobs always dequeue before
/// background prefetches, so the tab the user is looking at never waits behind
/// a batch warming the others.
#[derive(Debug, Default)]
pub(super) struct WorkQueue {
    queues: Mutex<Queues>,
    ready: Condvar,
}

impl WorkQueue {
    fn lock(&self) -> std::sync::MutexGuard<'_, Queues> {
        self.queues
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn push(&self, work: Work) {
        let mut q = self.lock();
        if work.lane == Lane::Prefetch {
            q.background.push_back(work);
        } else {
            q.urgent.push_back(work);
        }
        drop(q);
        self.ready.notify_one();
    }

    /// Block until a job is queued (urgent first) or the queue is closed (`None`).
    pub(super) fn pop(&self) -> Option<Work> {
        let mut q = self.lock();
        loop {
            if q.closed {
                return None;
            }
            if let Some(work) = q.urgent.pop_front().or_else(|| q.background.pop_front()) {
                return Some(work);
            }
            q = self
                .ready
                .wait(q)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    pub(super) fn close(&self) {
        self.lock().closed = true;
        self.ready.notify_all();
    }
}

/// The latest generation of each droppable [`Lane`], shared with the workers.
#[derive(Debug, Default)]
pub(super) struct Generations {
    /// The latest active-tab request (`App::tab_req`).
    pub(super) tab: AtomicU64,
    /// The current prefetch batch (`App::prefetch_seq`).
    pub(super) prefetch: AtomicU64,
}

impl Generations {
    /// Whether a job queued at `seq` on `lane` was superseded before it ran.
    pub(super) fn is_stale(&self, lane: Lane, seq: u64) -> bool {
        match lane {
            Lane::Tab => self.tab.load(Ordering::Acquire) != seq,
            Lane::Prefetch => self.prefetch.load(Ordering::Acquire) != seq,
            Lane::Other => false,
        }
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
    /// The latest active-tab request and prefetch batch, so a queued job can
    /// tell it was superseded before doing any work (pool jobs, and scoped admin
    /// jobs via [`run_scoped_if_latest`]).
    generations: Arc<Generations>,
    /// Bounded worker pool for [`Dispatcher::spawn_job`] (async mode only). A wide
    /// fan-out (one job per tab per online cluster) enqueues here instead of
    /// spawning an unbounded number of threads / concurrent `tsh` subprocesses.
    /// `None` in synchronous mode (jobs run inline). The serial fan-outs
    /// (`spawn_admin_stream`, `spawn_after_action`) keep dedicated threads.
    pool: Option<Arc<WorkQueue>>,
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
        let generations = Arc::new(Generations::default());
        let pool = (!synchronous).then(|| Self::start_pool(&repos, &job_tx, &generations));
        Self {
            repos,
            job_tx,
            job_rx,
            proxy_tx,
            proxy_rx,
            profile_lock: Arc::new(Mutex::new(())),
            generations,
            pool,
            synchronous,
        }
    }

    /// Start a small fixed pool of worker threads that pull queued jobs off a
    /// shared [`WorkQueue`] and send each result back on `job_tx`. Bounding the
    /// worker count caps how many `tsh`/`tctl` subprocesses one fan-out can run at
    /// once (a topology switch would otherwise spawn a thread per tab per
    /// cluster). The queue lock is held only to dequeue - never across `run_job` -
    /// so the workers still execute jobs concurrently, up to the pool size. A job
    /// superseded while it queued is dropped unrun (its result would be discarded
    /// anyway), so tab flicks or a cluster switch don't keep the pool busy with
    /// dead work.
    fn start_pool(
        repos: &Arc<Repositories>,
        job_tx: &Sender<(u64, JobResult)>,
        generations: &Arc<Generations>,
    ) -> Arc<WorkQueue> {
        let queue = Arc::new(WorkQueue::default());
        let workers = std::thread::available_parallelism().map_or(4, |n| n.get().clamp(2, 8));
        for _ in 0..workers {
            let queue = Arc::clone(&queue);
            let repos = Arc::clone(repos);
            let job_tx = job_tx.clone();
            let generations = Arc::clone(generations);
            std::thread::spawn(move || {
                // `None` once the dispatcher is dropped → the pool shuts down.
                while let Some(Work { seq, job, lane }) = queue.pop() {
                    if generations.is_stale(lane, seq) {
                        continue;
                    }
                    let _ = job_tx.send((seq, run_job(&repos, job)));
                }
            });
        }
        queue
    }

    /// Run a job. In synchronous mode the result is returned for the caller to
    /// apply immediately (deterministic tests); otherwise it runs on a worker
    /// thread and lands later via [`Dispatcher::drain_jobs`]. So a `Some` return
    /// means "apply this now", `None` means "it'll arrive on the channel".
    /// `lane` picks the queue and says how the job can go stale (see [`Lane`]).
    pub(super) fn spawn_job(&self, seq: u64, job: Job, lane: Lane) -> Option<(u64, JobResult)> {
        if self.synchronous {
            return Some((seq, run_job(&self.repos, job)));
        }
        // Enqueue on the bounded pool instead of spawning a thread per job.
        if let Some(pool) = &self.pool {
            pool.push(Work { seq, job, lane });
        }
        None
    }

    /// Record `seq` as the latest active-tab request; older queued tab jobs and
    /// scoped admin jobs then skip their work.
    pub(super) fn note_tab_request(&self, seq: u64) {
        self.generations.tab.store(seq, Ordering::Release);
    }

    /// Record `seq` as the current prefetch batch; queued jobs of older batches
    /// then skip their work.
    pub(super) fn note_prefetch_batch(&self, seq: u64) {
        self.generations.prefetch.store(seq, Ordering::Release);
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
    /// listing's `JobResult` type is unchanged; only its execution is wrapped. A job
    /// superseded by a newer tab request while it waited for the lock is skipped
    /// ([`run_scoped_if_latest`]).
    ///
    /// [`profile_lock`]: Dispatcher::profile_lock
    pub(super) fn spawn_admin_scoped(
        &self,
        seq: u64,
        job: Job,
        cluster: ClusterName,
        root: ClusterName,
    ) -> Vec<(u64, JobResult)> {
        if self.synchronous {
            return run_scoped_if_latest(
                &self.repos,
                &self.generations.tab,
                seq,
                job,
                &cluster,
                &root,
            )
            .into_iter()
            .map(|r| (seq, r))
            .collect();
        }
        let repos = Arc::clone(&self.repos);
        let tx = self.job_tx.clone();
        let profile_lock = Arc::clone(&self.profile_lock);
        let generations = Arc::clone(&self.generations);
        std::thread::spawn(move || {
            // Switch, read and restore root all inside the critical section (see
            // spawn_admin_stream). A job superseded while it waited for the lock
            // does none of it.
            let results = {
                let _guard = profile_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                run_scoped_if_latest(&repos, &generations.tab, seq, job, &cluster, &root)
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
        root: ClusterName,
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
                        cluster: ctx.name.clone(),
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
                let cluster = ctx.name.clone();
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
        restore_root: Option<ClusterName>,
        reload_topology: bool,
    ) -> Vec<(u64, JobResult)> {
        if self.synchronous {
            let failed = restore_root
                .as_ref()
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

impl Drop for Dispatcher {
    /// Stop the pool's workers (they would otherwise block on the queue forever).
    fn drop(&mut self) {
        if let Some(pool) = &self.pool {
            pool.close();
        }
    }
}
