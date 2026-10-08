//! Navigation & view-state: tab switching/visibility, selection & scrolling,
//! picker movement, and clearing per-tab/session state. A child `impl super::App`.
//!
//! Split out of `app`; the model types are imported from `super`.

use domain::node::SshNode;
use domain::profile::ProfileSummary;
use domain::value::ClusterName;

use super::listings::Listings;
use super::{App, Mode, Outcome, PickerEntry, Tab, clamp_step, unix_now};

impl App {
    pub(super) fn clear_active(&mut self) {
        self.lists.clear_tab(self.tab);
    }

    /// Wipe every cached listing and the topology on logout/expiry, so nothing
    /// from the old session lingers on screen. Returns to the SSH tab.
    pub(super) fn clear_session(&mut self) {
        self.lists = Listings::default();
        self.invite_view = None;
        self.mfa_devices.clear();
        self.mode = Mode::Normal;
        self.sessions.clear();
        self.agg.rows.clear();
        self.agg.cache.clear();
        self.cache_key.clear();
        self.topology = None;
        self.admin_allowed = false;
        self.agg.enabled = false;
        self.agg.seq += 1; // drop any in-flight aggregate fan-out from the old session
        self.tab = Tab::Ssh;
        self.loading = false;
        self.recompute_visible();
    }

    /// True when the active view is the all-clusters aggregate (every tab
    /// aggregates in this mode).
    pub(crate) const fn aggregating(&self) -> bool {
        self.agg.enabled
    }

    pub(super) fn selected_index(&self) -> Option<usize> {
        let row = self.table.selected()?;
        self.visible.get(row).copied()
    }

    pub(crate) fn selected_node(&self) -> Option<&SshNode> {
        self.lists.nodes.get(self.selected_index()?)
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
    /// cluster*, and `tctl` has no cluster flag - so on a leaf it always errors,
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

    /// True when the active profile's cluster is the topology root - the only
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
        // `agg.cache` inside the dispatch_aggregate* helpers, not the scoped
        // `cache_key`.
        let aggregated = self.agg.enabled;
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
        self.lists.len(self.tab)
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

    /// The `c` picker's rows, in display order: "All clusters" and the active
    /// profile's clusters (root first) when the topology is known, then every
    /// other `tsh` profile.
    pub(crate) fn picker_entries(&self) -> Vec<PickerEntry<'_>> {
        let mut entries = Vec::new();
        if let Some(topo) = &self.topology {
            entries.push(PickerEntry::AllClusters);
            entries.extend(topo.all().map(PickerEntry::Cluster));
        }
        entries.extend(
            self.profiles
                .iter()
                .filter(|p| !p.active)
                .map(PickerEntry::Profile),
        );
        entries
    }

    pub(super) fn move_picker(&mut self, forward: bool) {
        let count = self.picker_entries().len();
        if count == 0 {
            return;
        }
        let next = clamp_step(self.picker.selected().unwrap_or(0), count, forward);
        self.picker.select(Some(next));
    }

    pub(super) fn confirm_picker(&mut self) -> Outcome {
        /// The chosen entry, owned, so `self` can be mutated to act on it.
        enum Choice {
            All,
            Cluster(ClusterName),
            Profile(ProfileSummary),
        }
        let Some(sel) = self.picker.selected() else {
            return Outcome::Continue;
        };
        let choice = match self.picker_entries().get(sel) {
            Some(PickerEntry::AllClusters) => Choice::All,
            Some(PickerEntry::Cluster(c)) => Choice::Cluster(c.name.clone()),
            Some(PickerEntry::Profile(p)) => Choice::Profile((*p).clone()),
            None => return Outcome::Continue,
        };
        self.mode = Mode::Normal;
        match choice {
            Choice::All => {
                // "All clusters" -> aggregate view.
                self.agg.enabled = true;
                self.reload_active();
            }
            Choice::Cluster(name) => self.select_scoped_cluster(&name),
            Choice::Profile(p) => return self.choose_profile(&p),
        }
        Outcome::Continue
    }

    /// Scope the view to one cluster of the active profile.
    fn select_scoped_cluster(&mut self, name: &ClusterName) {
        // Invalidate any in-flight aggregate fan-out so a late leaf can't clobber
        // the loading flag/status of the scoped fetch we're about to start.
        self.agg.enabled = false;
        self.agg.seq += 1;
        let Some(topo) = self.topology.as_mut() else {
            return;
        };
        match topo.select(name) {
            Ok(()) => {
                self.reload_active();
                // Warm the other tabs for the newly selected cluster.
                self.prefetch_all();
            }
            Err(e) => self.report(&e),
        }
    }

    /// Switch to another `tsh` profile (another proxy). A still-valid one is
    /// switched to in the background (`tsh login --proxy`, no prompt); an
    /// expired one needs the terminal for a fresh interactive login.
    fn choose_profile(&mut self, p: &ProfileSummary) -> Outcome {
        if let Some(running) = &self.profile_switching {
            self.status = Some(format!("already switching to profile {running}…"));
            return Outcome::Continue;
        }
        if p.is_expired_at(unix_now()) {
            return self.interactive_profile_login(&p.proxy);
        }
        self.profile_switching = Some(p.proxy.clone());
        self.loading = true;
        self.status = Some(format!("switching to profile {}…", p.proxy));
        for (seq, result) in self
            .dispatcher
            .spawn_profile_switch(self.profile_gen + 1, p.proxy.clone())
        {
            self.apply(seq, result);
        }
        Outcome::Continue
    }

    pub(super) fn move_tool_picker(&mut self, forward: bool) {
        self.tool_choices.step(forward);
    }

    pub(super) fn move_user_picker(&mut self, forward: bool) {
        self.user_choices.step(forward);
    }
}
