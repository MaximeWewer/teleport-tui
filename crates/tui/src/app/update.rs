//! The update loop: dispatching background `Job`s and applying their
//! `JobResult`s, plus the aggregate/refresh bookkeeping. A child `impl super::App`.
//!
//! Split out of `app`; the model types are imported from `super`.

use domain::admin::{GeneratedToken, InviteLink};
use domain::cluster::{ClusterContext, ClusterTopology};
use domain::error::{DomainError, ReportableError};
use domain::mfa::MfaDevice;
use domain::profile::Profile;
use domain::resource::Resource;
use domain::session::ActiveSession;
use domain::value::ClusterName;

use super::dispatch::{Job, JobResult, Lane, Listing, agg_rows_of, err_row};
use super::{AggRow, App, Mode, PREFETCH_BASE, Tab};

impl App {
    /// Dispatch an auxiliary (ungated) job: status / clusters.
    pub(super) fn dispatch_aux(&mut self, job: Job) {
        self.send(0, job, Lane::Other);
    }

    /// Dispatch the active-tab data job, marking the tab as loading and tagging
    /// the request so stale results (from a superseded request) are discarded.
    fn dispatch_tab(&mut self, job: Job) {
        let seq = self.begin_tab_request();
        self.send(seq, job, Lane::Tab);
    }

    /// Start a new active-tab request: bump (and publish to the dispatcher) the
    /// request counter, and mark the tab as loading. Returns the request's seq.
    fn begin_tab_request(&mut self) -> u64 {
        self.tab_req += 1;
        self.dispatcher.note_tab_request(self.tab_req);
        self.loading = true;
        // Clear stale rows so the spinner shows an empty table, not the
        // previous tab's selection indices, until the result lands.
        self.visible.clear();
        self.table.select(None);
        self.tab_req
    }

    fn send(&mut self, seq: u64, job: Job, lane: Lane) {
        // In synchronous mode the result comes back immediately; apply it here so
        // tests observe state without a tick. Otherwise it lands via `tick`.
        if let Some((seq, result)) = self.dispatcher.spawn_job(seq, job, lane) {
            self.apply(seq, result);
        }
    }

    pub(super) fn apply(&mut self, seq: u64, result: JobResult) {
        match result {
            JobResult::Clusters(r) => self.ok_or_report(r, Self::apply_topology),
            JobResult::Status(r) => self.ok_or_report(r, Self::apply_status),
            JobResult::Token(r) => self.ok_or_report(r, Self::show_token),
            JobResult::TokenRemoved(r) => self.ok_or_report(r, |app, ()| {
                app.status = Some("token removed".to_owned());
                // Refetch so the removed token disappears from the list.
                app.invalidate_tab(Tab::Tokens);
            }),
            JobResult::Mfa(r) => self.ok_or_report(r, Self::show_mfa),
            JobResult::Sessions(r) => self.ok_or_report(r, Self::show_sessions),
            JobResult::Invite(r) => self.ok_or_report(r, Self::show_invite),
            JobResult::AdminAllowed(ok) => self.apply_admin_allowed(ok),
            JobResult::AdminProbeFailed(e) => {
                self.report(&e);
                self.apply_admin_allowed(false);
            }
            JobResult::Aggregate { tab, cluster, rows } => {
                self.apply_agg_result(seq, tab, &cluster, rows);
            }
            JobResult::AggregateAdmin { tab, cluster, rows } => {
                self.apply_agg_cluster(seq, tab, &cluster, rows, true);
            }
            JobResult::RestoreFailed { root, error } => self.report_restore_failed(&root, &error),
            JobResult::List { tab, result } => self.apply_tab(seq, tab, result),
        }
    }

    /// Hand an `Ok` value to `on_ok`; report an `Err`.
    fn ok_or_report<T>(
        &mut self,
        result: Result<T, DomainError>,
        on_ok: impl FnOnce(&mut Self, T),
    ) {
        match result {
            Ok(value) => on_ok(self, value),
            Err(e) => self.report(&e),
        }
    }

    /// Drop `tab`'s cached listing (it changed server-side) and reload it if it
    /// is on screen; otherwise it is refetched on the next visit.
    fn invalidate_tab(&mut self, tab: Tab) {
        self.cache_key.remove(&tab);
        if self.tab == tab {
            self.reload_active();
        }
    }

    fn apply_topology(&mut self, topo: ClusterTopology) {
        // Only drop the aggregate caches when the *online cluster set*
        // actually changed. A routine refresh (notably the one after a
        // leaf login) leaves them intact, so we don't re-fan every tab
        // across every cluster - only the current tab, whose cache was
        // dropped on purpose (submit_login), re-fans to pick up the leaf.
        let online = |t: &ClusterTopology| {
            let mut v: Vec<String> = t
                .all()
                .iter()
                .filter(|c| c.is_online())
                .map(|c| c.name.to_string())
                .collect();
            v.sort();
            v
        };
        let changed = self
            .topology
            .as_ref()
            .is_none_or(|old| online(old) != online(&topo));
        self.topology = Some(topo);
        if changed {
            self.agg.cache.clear();
        }
        self.reload_active();
        // Warm every other tab in the background so switches are instant.
        self.prefetch_all();
    }

    fn apply_status(&mut self, profile: Option<Profile>) {
        // No active session (logout / expiry): wipe every listing so no
        // stale resource stays on screen.
        if profile.is_none() {
            self.clear_session();
        }
        self.profile = profile;
    }

    fn show_token(&mut self, token: GeneratedToken) {
        // Display once; the token is held in zeroizing memory, never logged.
        self.token_view = Some(token.into());
        self.mode = Mode::ShowToken;
        self.status = Some("token generated".to_owned());
    }

    fn show_mfa(&mut self, devices: Vec<MfaDevice>) {
        self.mfa_devices.set(devices);
        self.status = Some(format!("{} MFA device(s)", self.mfa_devices.len()));
        self.mode = Mode::ShowMfa;
    }

    fn show_sessions(&mut self, sessions: Vec<ActiveSession>) {
        self.sessions.set(sessions);
        self.status = Some(format!("{} active session(s)", self.sessions.len()));
        self.mode = Mode::ShowSessions;
    }

    fn show_invite(&mut self, link: InviteLink) {
        // Show the one-time URL; it is held zeroized and never logged.
        self.status = Some(format!("setup URL ready for {}", link.user));
        self.invite_view = Some(link.into());
        self.mode = Mode::ShowInvite;
        // A freshly added user won't be in the cached list → refresh.
        self.invalidate_tab(Tab::Users);
    }

    /// Log a failed root-profile restore and say which profile is stranded: every
    /// later `tsh`/`tctl` call reads the leaf until the user re-logs in.
    fn report_restore_failed(&mut self, root: &ClusterName, error: &DomainError) {
        self.report(error);
        self.status = Some(format!(
            "[{}] could not switch the profile back to {root}: {}",
            error.code(),
            error.message()
        ));
    }

    /// Apply the admin-rights probe's verdict.
    fn apply_admin_allowed(&mut self, ok: bool) {
        self.admin_allowed = ok;
        self.admin_probed = true;
        // The admin tabs are warmed optimistically by the Clusters handler
        // (in parallel with this slow probe), so no prefetch is needed
        // here - that would only duplicate the in-flight ~3s tctl calls.
        if !ok && self.tab.admin_gated() && !self.admin_group_reachable() {
            // Rights denied *on the root cluster* while on an Admin/Recordings
            // tab → fall back to SSH. A leaf-profile denial is inconclusive
            // (tctl can't target a leaf), so the tab stays put there.
            self.switch_tab(Tab::Ssh);
        }
    }

    /// Apply one cluster's slice of a concurrent (`tsh -c`) fan-out. An `Err`
    /// (offline/network) renders an error row like the admin path, but is not
    /// cached, so the next visit retries.
    fn apply_agg_result(
        &mut self,
        seq: u64,
        tab: Tab,
        cluster: &ClusterName,
        rows: Result<Vec<AggRow>, DomainError>,
    ) {
        match rows {
            Ok(agg) => self.apply_agg_cluster(seq, tab, cluster, agg, true),
            Err(e) => {
                let agg = vec![err_row(cluster.clone(), &e)];
                self.apply_agg_cluster(seq, tab, cluster, agg, false);
            }
        }
    }

    /// Apply one cluster's slice of an all-clusters fan-out. When `cache` is set
    /// the rows are cached per `(tab, cluster)` regardless of the active view, so
    /// partial progress survives navigating away (a transient error is not
    /// cached, so it retries); the live view is updated only when this slice
    /// belongs to the current fan-out (matching `agg.seq` and active `tab`).
    fn apply_agg_cluster(
        &mut self,
        seq: u64,
        tab: Tab,
        cluster: &ClusterName,
        rows: Vec<AggRow>,
        cache: bool,
    ) {
        if cache {
            self.agg.cache.insert((tab, cluster.clone()), rows.clone());
        }
        // Only touch the visible aggregate if this slice is for it.
        if seq != self.agg.seq || tab != self.tab {
            return;
        }
        self.agg.pending = self.agg.pending.saturating_sub(1);
        self.agg.rows.extend(rows);
        if self.agg.pending == 0 {
            self.loading = false;
        }
        self.recompute_visible();
        self.set_agg_status();
    }

    /// Status line for the aggregate view: reachable row count plus any clusters
    /// still needing a login.
    fn set_agg_status(&mut self) {
        let reachable = self.agg.rows.iter().filter(|r| !r.login_required).count();
        let need_login = self.agg.rows.iter().filter(|r| r.login_required).count();
        self.status = Some(if need_login > 0 {
            format!(
                "{reachable} {} across all clusters · {need_login} cluster(s) need login (L)",
                self.tab.title()
            )
        } else {
            format!("{reachable} {} across all clusters", self.tab.title())
        });
    }

    /// Apply a tab-data result. `seq >= PREFETCH_BASE` marks a background
    /// prefetch: it fills the tab's cache without disturbing the active view.
    fn apply_tab(&mut self, seq: u64, tab: Tab, result: Result<Listing, DomainError>) {
        let prefetch = seq >= PREFETCH_BASE;
        if prefetch {
            if seq != self.prefetch_seq {
                return; // batch superseded by a cluster change
            }
        } else if seq != self.tab_req {
            return; // a newer active-tab request was issued; this result is stale.
        }
        let outcome = result.map(|l| self.lists.store(l));

        if prefetch {
            // Background fill: cache the tab silently; the active view is untouched
            // unless this result happens to be for the active tab (rare race).
            // On error, leave it uncached → refetched on first visit.
            if outcome.is_ok() {
                let key = self.desired_key(tab);
                self.cache_key.insert(tab, key);
                // A successful root-scoped admin listing (`tctl get users`, …)
                // *proves* we have admin rights, so reveal the admin tabs now
                // (with their data already warm) instead of waiting on the
                // separate, equally-slow `tctl status` probe.
                if tab.is_admin() && !self.admin_allowed {
                    self.admin_allowed = true;
                    self.admin_probed = true;
                }
            }
            if tab == self.tab {
                self.loading = false;
                self.recompute_visible();
            }
            return;
        }

        self.loading = false;
        match outcome {
            Ok(n) => {
                self.recompute_visible();
                // Mark this tab as cached for the current context.
                let key = self.desired_key(tab);
                self.cache_key.insert(tab, key);
                self.status = Some(format!("{n} {}", tab.title()));
            }
            Err(e) => {
                self.clear_active();
                self.cache_key.remove(&tab); // failed load -> retry next visit
                self.recompute_visible();
                self.report(&e);
            }
        }
    }

    /// Background-load every applicable tab for the current context so switching
    /// tabs is instant. Skips the active tab (loaded by `reload_active`), hidden
    /// tabs, already-cached tabs, and aggregate mode (own per-tab fan-out cache).
    pub(super) fn prefetch_all(&mut self) {
        if self.agg.enabled {
            return;
        }
        let cluster = self
            .topology
            .as_ref()
            .map(|t| t.selected().name.to_string());
        // Only bump the generation when the target cluster actually changes, so
        // repeated calls for the same context don't drop each other's batches.
        if self.prefetch_cluster != cluster {
            self.prefetch_seq += 1;
            self.prefetch_cluster = cluster;
        }
        let seq = self.prefetch_seq;
        self.dispatcher.note_prefetch_batch(seq);
        let ctx = self.topology.as_ref().map(|t| t.selected().clone());
        for tab in Tab::ALL {
            if tab == self.tab {
                continue;
            }
            // Admin-gated tabs (admin group + Recordings): warm them optimistically
            // until the probe actually denies rights - their `tctl`/`tsh` listings
            // are slow, so don't wait on the equally slow probe. Still skip commands
            // the local `tsh` can't run. Everything else is gated on visibility.
            let want = if tab.admin_gated() {
                (!self.admin_probed || self.admin_allowed) && self.tab_supported(tab)
            } else {
                self.tab_visible(tab)
            };
            if !want {
                continue;
            }
            if self.cache_key.get(&tab) == Some(&self.desired_key(tab)) {
                continue; // already cached for this context
            }
            if let Some(job) = Job::list(tab, ctx.as_ref()) {
                self.send(seq, job, Lane::Prefetch);
            }
        }
    }

    /// Called by the event loop after an interactive `tsh` action returns.
    /// Always refreshes the profile; reloads the topology after login/logout.
    pub(crate) fn after_action(&mut self) {
        // An all-clusters leaf login may have left the active profile on that
        // leaf. Put it back on root before refetching, so `tsh clusters`/`status`
        // read from root's (full) viewpoint rather than the leaf's. Both the
        // restore and the follow-up reads run on a worker thread (so the blocking
        // `tsh login --proxy` re-key never freezes the UI) and in order (the
        // restore happens-before the reads it protects). Admin rights can change
        // across login/logout, so an auth action also re-probes.
        let restore_root = self.pending_root_restore.take();
        let reload_topology = self.last_was_auth;
        if reload_topology {
            self.status = Some("refreshing session…".to_owned());
        }
        for (seq, result) in self
            .dispatcher
            .spawn_after_action(restore_root, reload_topology)
        {
            self.apply(seq, result);
        }
    }

    /// Dispatch a background reload of the data backing the active tab.
    pub(super) fn reload_active(&mut self) {
        // All-clusters aggregate. Cluster-scoped tabs fan out one concurrent job
        // per cluster (`tsh -c`); tabs with no cluster flag (admin tabs +
        // Recordings) run a serial fan-out that re-selects each cluster's profile
        // and streams results as they arrive.
        if self.agg.enabled {
            if self.tab.serial_aggregation() {
                self.dispatch_aggregate_admin();
            } else {
                self.dispatch_aggregate();
            }
            return;
        }
        if self.tab.is_admin() {
            let job = Job::List {
                tab: self.tab,
                ctx: None,
            };
            // Admin listings go through `tctl`, which targets the profile's current
            // cluster (not the UI's -c). Re-key the selected cluster first so a leaf
            // profile can't make this error; the fan-out already does this per
            // cluster in all-clusters mode.
            self.dispatch_admin_scoped(job);
            return;
        }
        // Cluster-scoped tabs need a selected cluster context.
        let Some(ctx) = self.topology.as_ref().map(|t| t.selected().clone()) else {
            return;
        };
        self.dispatch_tab(Job::List {
            tab: self.tab,
            ctx: Some(ctx),
        });
    }

    /// Dispatch a single-cluster admin listing that must run against the selected
    /// cluster's profile - re-keys it (and restores root) around the `tctl` call
    /// via [`Dispatcher::spawn_admin_scoped`]. Falls back to a plain dispatch if
    /// the topology isn't known yet (nothing to re-key to).
    fn dispatch_admin_scoped(&mut self, job: Job) {
        let Some((cluster, root)) = self
            .topology
            .as_ref()
            .map(|t| (t.selected().name.clone(), t.root().name.clone()))
        else {
            self.dispatch_tab(job);
            return;
        };
        let seq = self.begin_tab_request();
        for (seq, result) in self.dispatcher.spawn_admin_scoped(seq, job, cluster, root) {
            self.apply(seq, result);
        }
    }

    /// Fan out one aggregate job per online cluster for the active tab. A
    /// completed fan-out is cached per tab, so revisiting a tab in all-clusters
    /// mode shows instantly instead of refanning (cleared on `r`/topology change).
    /// Seed the aggregate view from the per-cluster cache and return the online
    /// clusters not yet cached (to be fetched). Bumps `agg.seq` (invalidating any
    /// in-flight fan-out) and resets the view; cached clusters render immediately.
    fn seed_agg_from_cache(&mut self, clusters: &[ClusterContext]) -> Vec<ClusterContext> {
        self.agg.seq += 1;
        self.agg.rows.clear();
        self.visible.clear(); // count reads (0) until cached/fresh rows land
        self.table.select(None);
        let tab = self.tab;
        // The cluster we were just viewing scoped already has its rows in memory —
        // promote them into the aggregate cache so we render them instantly instead
        // of refetching the cluster we just left.
        if let Some((name, rows)) = self.scoped_agg_seed(tab)
            && !self.agg.cache.contains_key(&(tab, name.clone()))
        {
            self.agg.cache.insert((tab, name), rows);
        }
        let mut missing = Vec::new();
        for ctx in clusters {
            if let Some(rows) = self.agg.cache.get(&(tab, ctx.name.clone())) {
                self.agg.rows.extend(rows.clone());
            } else {
                missing.push(ctx.clone());
            }
        }
        self.agg.pending = missing.len();
        self.loading = !missing.is_empty();
        self.recompute_visible();
        self.set_agg_status();
        missing
    }

    /// The cluster whose rows the current scoped listing holds, paired with those
    /// rows as [`AggRow`]s - when the scoped cache is still valid. Lets the
    /// aggregate reuse data already fetched for a cluster instead of refetching it
    /// on the scoped → all-clusters switch.
    ///
    /// The seed cluster differs by tab: admin listings go through `tctl` against
    /// the **root** proxy (see `admin_cluster_rows`), so their scoped rows belong
    /// to root regardless of the picker selection; every other tab holds the
    /// **selected** cluster's rows. Recordings rebuilds its rows explicitly to keep
    /// each row's `sid` (needed to `tsh play` from the aggregate).
    fn scoped_agg_seed(&self, tab: Tab) -> Option<(ClusterName, Vec<AggRow>)> {
        if self.cache_key.get(&tab) != Some(&self.desired_key(tab)) {
            return None; // scoped data is stale / for another cluster
        }
        let topo = self.topology.as_ref()?;
        let cluster = if tab.is_admin() {
            topo.root().name.clone()
        } else {
            topo.selected().name.clone()
        };
        // Recordings carries a per-row sid the plain cells can't reconstruct.
        if tab != Tab::Recordings {
            let rows = agg_rows_of(&cluster, self.lists.rows(tab));
            return Some((cluster, rows));
        }
        let rows = self
            .lists
            .recordings
            .iter()
            .map(|r| AggRow {
                cluster: cluster.clone(),
                cells: r.row(),
                login_required: false,
                error: false,
                sid: Some(r.sid.clone()),
            })
            .collect();
        Some((cluster, rows))
    }

    fn online_clusters(&self) -> Option<Vec<ClusterContext>> {
        self.topology
            .as_ref()
            .map(|t| t.all().iter().filter(|c| c.is_online()).cloned().collect())
    }

    fn dispatch_aggregate(&mut self) {
        let Some(clusters) = self.online_clusters() else {
            return;
        };
        // Cached clusters render instantly; fetch only the missing ones.
        let missing = self.seed_agg_from_cache(&clusters);
        let seq = self.agg.seq;
        let tab = self.tab;
        for ctx in missing {
            self.send(seq, Job::Aggregate { tab, ctx }, Lane::Other);
        }
    }

    /// All-clusters admin/recordings: a serial fan-out (not the concurrent `-c`
    /// path) because these commands have no cluster flag and each cluster is
    /// reached by re-selecting its profile - a parallel switch would race. Cached
    /// clusters render instantly; only the missing ones are re-fetched.
    fn dispatch_aggregate_admin(&mut self) {
        let (Some(clusters), Some(root)) = (
            self.online_clusters(),
            self.topology.as_ref().map(|t| t.root().name.clone()),
        ) else {
            return;
        };
        let missing = self.seed_agg_from_cache(&clusters);
        if missing.is_empty() {
            return;
        }
        let seq = self.agg.seq;
        let tab = self.tab;
        // Streamed serially: each cluster's rows render (and cache) as they arrive.
        for (seq, result) in self.dispatcher.spawn_admin_stream(seq, tab, missing, root) {
            self.apply(seq, result);
        }
    }

    pub(super) fn recompute_visible(&mut self) {
        let needle = self.input.to_lowercase();
        let filtering = self.mode == Mode::Search && !needle.is_empty();
        let keep = |matched: bool| !filtering || matched;
        self.visible = if self.aggregating() {
            self.agg
                .rows
                .iter()
                .enumerate()
                .filter(|(_, r)| keep(r.matches(&needle)))
                .map(|(i, _)| i)
                .collect()
        } else {
            self.lists.indices(self.tab, &needle, keep)
        };
        let sel = if self.visible.is_empty() {
            None
        } else {
            Some(
                self.table
                    .selected()
                    .unwrap_or(0)
                    .min(self.visible.len() - 1),
            )
        };
        self.table.select(sel);
    }
}
