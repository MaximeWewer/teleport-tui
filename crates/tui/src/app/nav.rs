//! Navigation & view-state: tab switching/visibility, selection & scrolling,
//! picker movement, and clearing per-tab/session state. A child `impl super::App`.
//!
//! Split out of `app`; model types and imports arrive via `super::*`.

#[allow(clippy::wildcard_imports)]
use super::*;

impl App {
    pub(super) fn clear_active(&mut self) {
        match self.tab {
            Tab::Ssh => self.nodes.clear(),
            Tab::Kube => self.kube.clear(),
            Tab::Db => self.dbs.clear(),
            Tab::Apps => self.apps.clear(),
            Tab::Requests => self.requests.clear(),
            Tab::Recordings => self.recordings.clear(),
            Tab::Users => self.users.clear(),
            Tab::Roles => self.roles.clear(),
            Tab::Tokens => self.tokens.clear(),
            Tab::Bots => self.bots.clear(),
            Tab::Inventory => self.instances.clear(),
        }
    }

    /// Wipe every cached listing and the topology on logout/expiry, so nothing
    /// from the old session lingers on screen. Returns to the SSH tab.
    pub(super) fn clear_session(&mut self) {
        self.nodes.clear();
        self.kube.clear();
        self.dbs.clear();
        self.apps.clear();
        self.requests.clear();
        self.recordings.clear();
        self.users.clear();
        self.roles.clear();
        self.tokens.clear();
        self.bots.clear();
        self.instances.clear();
        self.invite_view = None;
        self.mfa_devices.clear();
        self.mfa_sel = 0;
        self.mode = Mode::Normal;
        self.sessions.clear();
        self.sessions_sel = 0;
        self.agg_rows.clear();
        self.agg_cache.clear();
        self.cache_key.clear();
        self.topology = None;
        self.admin_allowed = false;
        self.aggregate = false;
        self.agg_seq += 1; // drop any in-flight aggregate fan-out from the old session
        self.tab = Tab::Ssh;
        self.loading = false;
        self.recompute_visible();
    }

    /// True when the active view is the all-clusters aggregate (every tab
    /// aggregates in this mode).
    pub(crate) fn aggregating(&self) -> bool {
        self.aggregate
    }

    pub(super) fn selected_index(&self) -> Option<usize> {
        let row = self.table.selected()?;
        self.visible.get(row).copied()
    }

    pub(crate) fn selected_node(&self) -> Option<&SshNode> {
        self.nodes.get(self.selected_index()?)
    }

    /// Whether a tab is reachable: hidden when the admin group is unreachable
    /// (see [`Self::admin_group_reachable`]) or when the installed `tsh` doesn't
    /// support its command. SSH (`ls`) is always available.
    pub(crate) fn tab_visible(&self, tab: Tab) -> bool {
        if tab.admin_gated() && !self.admin_group_reachable() {
            return false;
        }
        self.tab_supported(tab)
    }

    /// Whether the admin / Recordings tab group should be shown. The `tctl`
    /// rights probe (`can_admin`) runs against the *currently selected profile
    /// cluster*, and `tctl` has no cluster flag — so on a leaf it always errors,
    /// making a `false` verdict there a false negative. We therefore hide the
    /// group only when we probed **on the root cluster** and were denied; a leaf
    /// profile (or a not-yet-probed session) keeps it visible, and a genuine lack
    /// of rights then simply errors when a tab is opened rather than the whole
    /// group vanishing. Logged out → nothing to show.
    pub(crate) fn admin_group_reachable(&self) -> bool {
        if self.profile.is_none() {
            return false;
        }
        if self.admin_allowed || !self.admin_probed {
            return true;
        }
        !self.probe_ran_on_root()
    }

    /// True when the active profile's cluster is the topology root — the only
    /// context in which a `can_admin` denial is trustworthy.
    fn probe_ran_on_root(&self) -> bool {
        match (self.profile.as_ref(), self.topology.as_ref()) {
            (Some(p), Some(t)) => p.cluster == t.root().name.as_str(),
            _ => false,
        }
    }

    /// Whether the installed `tsh` supports the command backing `tab`, ignoring
    /// admin gating. Used by the optimistic prefetch, which warms admin-gated
    /// tabs before the (slow) rights probe returns but must still skip commands
    /// the local `tsh` can't run.
    pub(crate) fn tab_supported(&self, tab: Tab) -> bool {
        match tab {
            Tab::Kube => self.caps.supports("kube"),
            Tab::Db => self.caps.supports("db"),
            Tab::Apps => self.caps.supports("apps"),
            Tab::Requests => self.caps.supports("request"),
            Tab::Recordings => self.caps.supports("recordings"),
            Tab::Ssh | Tab::Users | Tab::Roles | Tab::Tokens | Tab::Bots | Tab::Inventory => true,
        }
    }

    /// Next/previous tab in cycle order, skipping tabs hidden by rights or by the
    /// installed `tsh`'s capabilities (so Tab/Shift-Tab never lands on one).
    pub(super) fn next_visible_tab(&self, forward: bool) -> Tab {
        let mut t = if forward {
            self.tab.next()
        } else {
            self.tab.prev()
        };
        // ALL has 7 entries; at most one full lap is ever needed.
        for _ in 0..Tab::ALL.len() {
            if self.tab_visible(t) {
                return t;
            }
            t = if forward { t.next() } else { t.prev() };
        }
        Tab::Ssh
    }

    pub(super) fn switch_tab(&mut self, tab: Tab) {
        if tab == self.tab {
            return;
        }
        self.tab = tab;
        self.input.clear();
        self.mode = Mode::Normal;
        self.table.select(None);
        // Show cached data instantly on a hit; only fetch (like `r`) on a miss.
        // In all-clusters mode every tab is aggregated and served from
        // `agg_cache` inside the dispatch_aggregate* helpers, not the scoped
        // `cache_key`.
        let aggregated = self.aggregate;
        if !aggregated && self.cache_key.get(&tab) == Some(&self.desired_key(tab)) {
            self.loading = false;
            self.recompute_visible();
            self.status = Some(format!("{} {} (cached)", self.active_len(), tab.title()));
        } else {
            self.reload_active();
        }
    }

    /// Cache marker for `tab`: the cluster name for cluster-scoped tabs, or a
    /// constant for root-scoped admin tabs.
    pub(super) fn desired_key(&self, tab: Tab) -> String {
        if tab.is_admin() {
            "@admin".to_owned()
        } else {
            self.topology
                .as_ref()
                .map(|t| t.selected().name.to_string())
                .unwrap_or_default()
        }
    }

    fn active_len(&self) -> usize {
        match self.tab {
            Tab::Ssh => self.nodes.len(),
            Tab::Kube => self.kube.len(),
            Tab::Db => self.dbs.len(),
            Tab::Apps => self.apps.len(),
            Tab::Requests => self.requests.len(),
            Tab::Recordings => self.recordings.len(),
            Tab::Users => self.users.len(),
            Tab::Roles => self.roles.len(),
            Tab::Tokens => self.tokens.len(),
            Tab::Bots => self.bots.len(),
            Tab::Inventory => self.instances.len(),
        }
    }

    pub(super) fn move_selection(&mut self, forward: bool) {
        if self.visible.is_empty() {
            return;
        }
        let next = clamp_step(
            self.table.selected().unwrap_or(0),
            self.visible.len(),
            forward,
        );
        self.table.select(Some(next));
    }

    pub(super) fn move_picker(&mut self, forward: bool) {
        // Entry 0 is "All clusters", entries 1.. are the real clusters.
        let Some(count) = self.topology.as_ref().map(|t| t.all().len() + 1) else {
            return;
        };
        let next = clamp_step(self.picker.selected().unwrap_or(0), count, forward);
        self.picker.select(Some(next));
    }

    pub(super) fn confirm_picker(&mut self) {
        let Some(sel) = self.picker.selected() else {
            return;
        };
        self.mode = Mode::Normal;
        if sel == 0 {
            // "All clusters" → aggregate view.
            self.aggregate = true;
            self.reload_active();
            return;
        }
        // A real cluster (index offset by the "All" entry) → scoped view.
        // Invalidate any in-flight aggregate fan-out so a late leaf can't clobber
        // the loading flag/status of the scoped fetch we're about to start.
        self.aggregate = false;
        self.agg_seq += 1;
        let name = self
            .topology
            .as_ref()
            .and_then(|t| t.all().get(sel - 1))
            .map(|c| c.name.clone());
        if let Some(name) = name
            && let Some(topo) = self.topology.as_mut()
        {
            match topo.select(&name) {
                Ok(()) => {
                    self.reload_active();
                    // Warm the other tabs for the newly selected cluster.
                    self.prefetch_all();
                }
                Err(e) => self.report(&e),
            }
        }
    }

    pub(super) fn move_tool_picker(&mut self, forward: bool) {
        if self.tool_choices.is_empty() {
            return;
        }
        let next = clamp_step(
            self.tool_picker.selected().unwrap_or(0),
            self.tool_choices.len(),
            forward,
        );
        self.tool_picker.select(Some(next));
    }

    pub(super) fn move_user_picker(&mut self, forward: bool) {
        if self.user_choices.is_empty() {
            return;
        }
        let next = clamp_step(
            self.user_picker.selected().unwrap_or(0),
            self.user_choices.len(),
            forward,
        );
        self.user_picker.select(Some(next));
    }
}
