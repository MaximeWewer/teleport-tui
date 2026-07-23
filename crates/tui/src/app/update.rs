//! The update loop: dispatching background `Job`s and applying their
//! `JobResult`s, plus the aggregate/refresh bookkeeping. A child `impl super::App`.
//!
//! Split out of `app`; model types and imports arrive via `super::*`.

#[allow(clippy::wildcard_imports)]
use super::*;

impl App {
    /// Dispatch an auxiliary (ungated) job: status / clusters.
    pub(super) fn dispatch_aux(&mut self, job: Job) {
        self.send(0, job);
    }

    /// Dispatch the active-tab data job, marking the tab as loading and tagging
    /// the request so stale results (from a superseded request) are discarded.
    fn dispatch_tab(&mut self, job: Job) {
        self.tab_req += 1;
        self.loading = true;
        // Clear stale rows so the spinner shows an empty table, not the
        // previous tab's selection indices, until the result lands.
        self.visible.clear();
        self.table.select(None);
        let seq = self.tab_req;
        self.send(seq, job);
    }

    fn send(&mut self, seq: u64, job: Job) {
        // In synchronous mode the result comes back immediately; apply it here so
        // tests observe state without a tick. Otherwise it lands via `tick`.
        if let Some((seq, result)) = self.dispatcher.spawn_job(seq, job) {
            self.apply(seq, result);
        }
    }

    pub(super) fn apply(&mut self, seq: u64, result: JobResult) {
        match result {
            JobResult::Clusters(Ok(topo)) => {
                // Only drop the aggregate caches when the *online cluster set*
                // actually changed. A routine refresh (notably the one after a
                // leaf login) leaves them intact, so we don't re-fan every tab
                // across every cluster — only the current tab, whose cache was
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
                    self.agg_cache.clear();
                }
                self.reload_active();
                // Warm every other tab in the background so switches are instant.
                self.prefetch_all();
            }
            JobResult::Status(Ok(profile)) => {
                // No active session (logout / expiry): wipe every listing so no
                // stale resource stays on screen.
                if profile.is_none() {
                    self.clear_session();
                }
                self.profile = profile;
            }
            JobResult::Token(Ok(token)) => {
                // Display once; the token is held in zeroizing memory, never logged.
                self.token_view = Some(token.into());
                self.mode = Mode::ShowToken;
                self.status = Some("token generated".to_owned());
            }
            JobResult::Clusters(Err(e)) | JobResult::Status(Err(e)) | JobResult::Token(Err(e)) => {
                self.report(&e);
            }
            JobResult::AdminAllowed(ok) => {
                self.admin_allowed = ok;
                self.admin_probed = true;
                // The admin tabs are warmed optimistically by the Clusters handler
                // (in parallel with this slow probe), so no prefetch is needed
                // here — that would only duplicate the in-flight ~3s tctl calls.
                if !ok && self.tab.admin_gated() && !self.admin_group_reachable() {
                    // Rights denied *on the root cluster* while on an Admin/Recordings
                    // tab → fall back to SSH. A leaf-profile denial is inconclusive
                    // (tctl can't target a leaf), so the tab stays put there.
                    self.switch_tab(Tab::Ssh);
                }
            }
            JobResult::TokenRemoved(result) => match result {
                Ok(()) => {
                    self.status = Some("token removed".to_owned());
                    // Refetch so the removed token disappears from the list.
                    self.cache_key.remove(&Tab::Tokens);
                    if self.tab == Tab::Tokens {
                        self.reload_active();
                    }
                }
                Err(e) => self.report(&e),
            },
            JobResult::Mfa(result) => match result {
                Ok(devices) => {
                    self.mfa_devices = devices;
                    self.mfa_sel = 0;
                    self.status = Some(format!("{} MFA device(s)", self.mfa_devices.len()));
                    self.mode = Mode::ShowMfa;
                }
                Err(e) => self.report(&e),
            },
            JobResult::Sessions(result) => match result {
                Ok(sessions) => {
                    self.sessions = sessions;
                    self.sessions_sel = 0;
                    self.status = Some(format!("{} active session(s)", self.sessions.len()));
                    self.mode = Mode::ShowSessions;
                }
                Err(e) => self.report(&e),
            },
            JobResult::Invite(result) => match result {
                Ok(link) => {
                    // Show the one-time URL; it is held zeroized and never logged.
                    self.status = Some(format!("setup URL ready for {}", link.user));
                    self.invite_view = Some(link.into());
                    self.mode = Mode::ShowInvite;
                    // A freshly added user won't be in the cached list → refresh.
                    self.cache_key.remove(&Tab::Users);
                    if self.tab == Tab::Users {
                        self.reload_active();
                    }
                }
                Err(e) => self.report(&e),
            },
            JobResult::Aggregate { tab, cluster, rows } => {
                // An `Err` (offline/network) yields `None` → not cached, retries.
                let agg = rows.ok().map(|cells| agg_rows_of(&cluster, cells));
                self.apply_agg_cluster(seq, tab, &cluster, agg);
            }
            JobResult::AggregateAdmin { tab, cluster, rows } => {
                self.apply_agg_cluster(seq, tab, &cluster, Some(rows));
            }
            other => self.apply_tab(seq, other),
        }
    }

    /// Apply one cluster's slice of an all-clusters fan-out. The rows are cached
    /// per `(tab, cluster)` **unconditionally** (when `Some`) so partial progress
    /// survives navigating away; the live view is updated only when this slice
    /// belongs to the current fan-out (matching `agg_seq` and active `tab`).
    fn apply_agg_cluster(&mut self, seq: u64, tab: Tab, cluster: &str, rows: Option<Vec<AggRow>>) {
        if let Some(rows) = &rows {
            self.agg_cache
                .insert((tab, cluster.to_owned()), rows.clone());
        }
        // Only touch the visible aggregate if this slice is for it.
        if seq != self.agg_seq || tab != self.tab {
            return;
        }
        self.agg_pending = self.agg_pending.saturating_sub(1);
        if let Some(rows) = rows {
            self.agg_rows.extend(rows);
        }
        if self.agg_pending == 0 {
            self.loading = false;
        }
        self.recompute_visible();
        self.set_agg_status();
    }

    /// Status line for the aggregate view: reachable row count plus any clusters
    /// still needing a login.
    fn set_agg_status(&mut self) {
        let reachable = self.agg_rows.iter().filter(|r| !r.login_required).count();
        let need_login = self.agg_rows.iter().filter(|r| r.login_required).count();
        self.status = Some(if need_login > 0 {
            format!(
                "{reachable} {} across all clusters · {need_login} cluster(s) need login (L)",
                self.tab.title()
            )
        } else {
            format!("{reachable} {} across all clusters", self.tab.title())
        });
    }

    /// Store a tab-data result into its vec, returning which tab it belongs to
    /// and the load outcome (row count or error). No UI side effects.
    fn store_tab_result(&mut self, result: JobResult) -> (Tab, Result<usize, AppError>) {
        match result {
            JobResult::Nodes(r) => (Tab::Ssh, r.map(|v| set_vec(&mut self.nodes, v))),
            JobResult::Kube(r) => (Tab::Kube, r.map(|v| set_vec(&mut self.kube, v))),
            JobResult::Db(r) => (Tab::Db, r.map(|v| set_vec(&mut self.dbs, v))),
            JobResult::Apps(r) => (Tab::Apps, r.map(|v| set_vec(&mut self.apps, v))),
            JobResult::Requests(r) => (Tab::Requests, r.map(|v| set_vec(&mut self.requests, v))),
            JobResult::Recordings(r) => {
                (Tab::Recordings, r.map(|v| set_vec(&mut self.recordings, v)))
            }
            JobResult::Users(r) => (Tab::Users, r.map(|v| set_vec(&mut self.users, v))),
            JobResult::Roles(r) => (Tab::Roles, r.map(|v| set_vec(&mut self.roles, v))),
            JobResult::Bots(r) => (Tab::Bots, r.map(|v| set_vec(&mut self.bots, v))),
            JobResult::Instances(r) => (Tab::Inventory, r.map(|v| set_vec(&mut self.instances, v))),
            JobResult::Tokens(r) => (Tab::Tokens, r.map(|v| set_vec(&mut self.tokens, v))),
            JobResult::Clusters(_)
            | JobResult::Status(_)
            | JobResult::Token(_)
            | JobResult::TokenRemoved(_)
            | JobResult::Invite(_)
            | JobResult::Mfa(_)
            | JobResult::Sessions(_)
            | JobResult::AdminAllowed(_)
            // These variants are routed directly in `apply`; reaching here would
            // be a routing bug — degrade to a no-op load rather than panicking.
            | JobResult::Aggregate { .. }
            | JobResult::AggregateAdmin { .. } => (self.tab, Ok(0)),
        }
    }

    /// Apply a tab-data result. `seq >= PREFETCH_BASE` marks a background
    /// prefetch: it fills the tab's cache without disturbing the active view.
    fn apply_tab(&mut self, seq: u64, result: JobResult) {
        let prefetch = seq >= PREFETCH_BASE;
        if prefetch {
            if seq != self.prefetch_seq {
                return; // batch superseded by a cluster change
            }
        } else if seq != self.tab_req {
            return; // a newer active-tab request was issued; this result is stale.
        }
        let (tab, outcome) = self.store_tab_result(result);

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
        if self.aggregate {
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
        let ctx = self.topology.as_ref().map(|t| t.selected().clone());
        for tab in Tab::ALL {
            if tab == self.tab {
                continue;
            }
            // Admin-gated tabs (admin group + Recordings): warm them optimistically
            // until the probe actually denies rights — their `tctl`/`tsh` listings
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
            let job = match tab {
                Tab::Ssh => ctx.clone().map(Job::Nodes),
                Tab::Kube => ctx.clone().map(Job::Kube),
                Tab::Db => ctx.clone().map(Job::Db),
                Tab::Apps => ctx.clone().map(Job::Apps),
                Tab::Requests => ctx.clone().map(Job::Requests),
                Tab::Recordings => ctx.clone().map(Job::Recordings),
                Tab::Users => Some(Job::Users),
                Tab::Roles => Some(Job::Roles),
                Tab::Tokens => Some(Job::Tokens),
                Tab::Bots => Some(Job::Bots),
                Tab::Inventory => Some(Job::Instances),
            };
            if let Some(job) = job {
                self.send(seq, job);
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
        if self.aggregate {
            if self.tab.serial_aggregation() {
                self.dispatch_aggregate_admin();
            } else {
                self.dispatch_aggregate();
            }
            return;
        }
        if self.tab.is_admin() {
            let job = match self.tab {
                Tab::Users => Job::Users,
                Tab::Roles => Job::Roles,
                Tab::Tokens => Job::Tokens,
                Tab::Bots => Job::Bots,
                Tab::Inventory => Job::Instances,
                _ => return, // non-admin tab can't reach the admin branch
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
        let job = match self.tab {
            Tab::Ssh => Job::Nodes(ctx),
            Tab::Kube => Job::Kube(ctx),
            Tab::Db => Job::Db(ctx),
            Tab::Apps => Job::Apps(ctx),
            Tab::Requests => Job::Requests(ctx),
            Tab::Recordings => Job::Recordings(ctx),
            Tab::Users | Tab::Roles | Tab::Tokens | Tab::Bots | Tab::Inventory => return,
        };
        self.dispatch_tab(job);
    }

    /// Dispatch a single-cluster admin listing that must run against the selected
    /// cluster's profile — re-keys it (and restores root) around the `tctl` call
    /// via [`Dispatcher::spawn_admin_scoped`]. Falls back to a plain dispatch if
    /// the topology isn't known yet (nothing to re-key to).
    fn dispatch_admin_scoped(&mut self, job: Job) {
        let Some((cluster, root)) = self
            .topology
            .as_ref()
            .map(|t| (t.selected().name.to_string(), t.root().name.to_string()))
        else {
            self.dispatch_tab(job);
            return;
        };
        self.tab_req += 1;
        self.loading = true;
        self.visible.clear();
        self.table.select(None);
        let seq = self.tab_req;
        if let Some((seq, result)) = self.dispatcher.spawn_admin_scoped(seq, job, cluster, root) {
            self.apply(seq, result);
        }
    }

    /// Fan out one aggregate job per online cluster for the active tab. A
    /// completed fan-out is cached per tab, so revisiting a tab in all-clusters
    /// mode shows instantly instead of refanning (cleared on `r`/topology change).
    /// Seed the aggregate view from the per-cluster cache and return the online
    /// clusters not yet cached (to be fetched). Bumps `agg_seq` (invalidating any
    /// in-flight fan-out) and resets the view; cached clusters render immediately.
    fn seed_agg_from_cache(&mut self, clusters: &[ClusterContext]) -> Vec<ClusterContext> {
        self.agg_seq += 1;
        self.agg_rows.clear();
        self.visible.clear(); // count reads (0) until cached/fresh rows land
        self.table.select(None);
        let tab = self.tab;
        // The cluster we were just viewing scoped already has its rows in memory —
        // promote them into the aggregate cache so we render them instantly instead
        // of refetching the cluster we just left.
        if let Some((name, rows)) = self.scoped_agg_seed(tab)
            && !self.agg_cache.contains_key(&(tab, name.clone()))
        {
            self.agg_cache.insert((tab, name), rows);
        }
        let mut missing = Vec::new();
        for ctx in clusters {
            if let Some(rows) = self.agg_cache.get(&(tab, ctx.name.to_string())) {
                self.agg_rows.extend(rows.clone());
            } else {
                missing.push(ctx.clone());
            }
        }
        self.agg_pending = missing.len();
        self.loading = !missing.is_empty();
        self.recompute_visible();
        self.set_agg_status();
        missing
    }

    /// The cluster whose rows the current scoped listing holds, paired with those
    /// rows as [`AggRow`]s — when the scoped cache is still valid. Lets the
    /// aggregate reuse data already fetched for a cluster instead of refetching it
    /// on the scoped → all-clusters switch.
    ///
    /// The seed cluster differs by tab: admin listings go through `tctl` against
    /// the **root** proxy (see `admin_cluster_rows`), so their scoped rows belong
    /// to root regardless of the picker selection; every other tab holds the
    /// **selected** cluster's rows. Recordings rebuilds its rows explicitly to keep
    /// each row's `sid` (needed to `tsh play` from the aggregate).
    fn scoped_agg_seed(&self, tab: Tab) -> Option<(String, Vec<AggRow>)> {
        if self.cache_key.get(&tab) != Some(&self.desired_key(tab)) {
            return None; // scoped data is stale / for another cluster
        }
        let topo = self.topology.as_ref()?;
        let cluster = if tab.is_admin() {
            topo.root().name.to_string()
        } else {
            topo.selected().name.to_string()
        };
        let cells = |list: Vec<Vec<String>>| Some((cluster.clone(), agg_rows_of(&cluster, list)));
        match tab {
            Tab::Ssh => cells(self.nodes.iter().map(Resource::row).collect()),
            Tab::Kube => cells(self.kube.iter().map(Resource::row).collect()),
            Tab::Db => cells(self.dbs.iter().map(Resource::row).collect()),
            Tab::Apps => cells(self.apps.iter().map(Resource::row).collect()),
            Tab::Requests => cells(self.requests.iter().map(Resource::row).collect()),
            Tab::Users => cells(self.users.iter().map(Resource::row).collect()),
            Tab::Roles => cells(self.roles.iter().map(Resource::row).collect()),
            Tab::Tokens => cells(self.tokens.iter().map(Resource::row).collect()),
            Tab::Bots => cells(self.bots.iter().map(Resource::row).collect()),
            Tab::Inventory => cells(self.instances.iter().map(Resource::row).collect()),
            // Recordings carries a per-row sid the plain cells can't reconstruct.
            Tab::Recordings => {
                let rows = self
                    .recordings
                    .iter()
                    .map(|r| AggRow {
                        cluster: cluster.clone(),
                        cells: r.row(),
                        login_required: false,
                        sid: Some(r.sid.clone()),
                    })
                    .collect();
                Some((cluster, rows))
            }
        }
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
        let seq = self.agg_seq;
        let tab = self.tab;
        for ctx in missing {
            self.send(seq, Job::Aggregate { tab, ctx });
        }
    }

    /// All-clusters admin/recordings: a serial fan-out (not the concurrent `-c`
    /// path) because these commands have no cluster flag and each cluster is
    /// reached by re-selecting its profile — a parallel switch would race. Cached
    /// clusters render instantly; only the missing ones are re-fetched.
    fn dispatch_aggregate_admin(&mut self) {
        let (Some(clusters), Some(root)) = (
            self.online_clusters(),
            self.topology.as_ref().map(|t| t.root().name.to_string()),
        ) else {
            return;
        };
        let missing = self.seed_agg_from_cache(&clusters);
        if missing.is_empty() {
            return;
        }
        let seq = self.agg_seq;
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
            self.agg_rows
                .iter()
                .enumerate()
                .filter(|(_, r)| keep(r.matches(&needle)))
                .map(|(i, _)| i)
                .collect()
        } else {
            match self.tab {
                Tab::Ssh => indices(&self.nodes, &needle, keep),
                Tab::Kube => indices(&self.kube, &needle, keep),
                Tab::Db => indices(&self.dbs, &needle, keep),
                Tab::Apps => indices(&self.apps, &needle, keep),
                Tab::Requests => indices(&self.requests, &needle, keep),
                Tab::Recordings => indices(&self.recordings, &needle, keep),
                Tab::Users => indices(&self.users, &needle, keep),
                Tab::Roles => indices(&self.roles, &needle, keep),
                Tab::Tokens => indices(&self.tokens, &needle, keep),
                Tab::Bots => indices(&self.bots, &needle, keep),
                Tab::Inventory => indices(&self.instances, &needle, keep),
            }
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
