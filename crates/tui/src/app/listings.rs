//! The per-tab resource listings [`super::App`] holds for the scoped view: one
//! typed vec per tab, plus the generic row/search/count views the update loop
//! needs, so the Tab -> vec mapping lives here instead of in every caller.
//! Also [`PickList`], the items + selection pair behind every popup list, and
//! [`AggView`], the all-clusters view's rows and fan-out bookkeeping.

use std::collections::HashMap;

use domain::admin::{AdminRole, AdminUser, Bot, Instance, ProvisionToken};
use domain::node::SshNode;
use domain::recording::SessionRecording;
use domain::request::AccessRequest;
use domain::resource::{App as AppResource, Database, KubeCluster, Resource};
use domain::value::ClusterName;

use super::dispatch::Listing;
use super::{AggRow, Tab, clamp_step};

/// The last loaded listing of every tab (empty until loaded).
#[derive(Debug, Default)]
pub(crate) struct Listings {
    pub(crate) nodes: Vec<SshNode>,
    pub(crate) kube: Vec<KubeCluster>,
    pub(crate) dbs: Vec<Database>,
    pub(crate) apps: Vec<AppResource>,
    pub(crate) requests: Vec<AccessRequest>,
    pub(crate) recordings: Vec<SessionRecording>,
    pub(crate) users: Vec<AdminUser>,
    pub(crate) roles: Vec<AdminRole>,
    /// Provision tokens (Tokens tab): name/type/labels/expiry from
    /// `tctl tokens ls`. A `token`-method name is the join secret, held in a
    /// `SecretString` (wiped on drop) and rendered masked.
    pub(crate) tokens: Vec<ProvisionToken>,
    /// Machine ID bots (Bots tab) and connected agent instances (Inventory tab).
    pub(crate) bots: Vec<Bot>,
    pub(crate) instances: Vec<Instance>,
}

impl Listings {
    /// Store a typed listing into its tab's vec and return the row count.
    pub(super) fn store(&mut self, listing: Listing) -> usize {
        fn set<T>(dst: &mut Vec<T>, value: Vec<T>) -> usize {
            *dst = value;
            dst.len()
        }
        match listing {
            Listing::Nodes(v) => set(&mut self.nodes, v),
            Listing::Kube(v) => set(&mut self.kube, v),
            Listing::Db(v) => set(&mut self.dbs, v),
            Listing::Apps(v) => set(&mut self.apps, v),
            Listing::Requests(v) => set(&mut self.requests, v),
            Listing::Recordings(v) => set(&mut self.recordings, v),
            Listing::Users(v) => set(&mut self.users, v),
            Listing::Roles(v) => set(&mut self.roles, v),
            Listing::Tokens(v) => set(&mut self.tokens, v),
            Listing::Bots(v) => set(&mut self.bots, v),
            Listing::Instances(v) => set(&mut self.instances, v),
        }
    }

    /// Drop `tab`'s rows (e.g. after a failed reload).
    pub(super) fn clear_tab(&mut self, tab: Tab) {
        match tab {
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

    /// `tab`'s items as generic resources (display row + search).
    fn items(&self, tab: Tab) -> Vec<&dyn Resource> {
        fn dyns<T: Resource>(items: &[T]) -> Vec<&dyn Resource> {
            items.iter().map(|it| it as &dyn Resource).collect()
        }
        match tab {
            Tab::Ssh => dyns(&self.nodes),
            Tab::Kube => dyns(&self.kube),
            Tab::Db => dyns(&self.dbs),
            Tab::Apps => dyns(&self.apps),
            Tab::Requests => dyns(&self.requests),
            Tab::Recordings => dyns(&self.recordings),
            Tab::Users => dyns(&self.users),
            Tab::Roles => dyns(&self.roles),
            Tab::Tokens => dyns(&self.tokens),
            Tab::Bots => dyns(&self.bots),
            Tab::Inventory => dyns(&self.instances),
        }
    }

    /// Number of rows loaded for `tab`.
    pub(super) fn len(&self, tab: Tab) -> usize {
        self.items(tab).len()
    }

    /// Each of `tab`'s items as a display row.
    pub(super) fn rows(&self, tab: Tab) -> Vec<Vec<String>> {
        self.items(tab).iter().map(|it| it.row()).collect()
    }

    /// Indices of `tab`'s items kept by the search predicate, preserving order.
    pub(super) fn indices(
        &self,
        tab: Tab,
        needle: &str,
        keep: impl Fn(bool) -> bool,
    ) -> Vec<usize> {
        self.items(tab)
            .iter()
            .enumerate()
            .filter(|(_, it)| keep(it.matches(needle)))
            .map(|(i, _)| i)
            .collect()
    }
}

/// A popup list's items plus its selected row (pickers, MFA devices, active
/// sessions, SSH forwards), kept together so the selection can't drift out of
/// range of the items it points into.
#[derive(Debug)]
pub(crate) struct PickList<T> {
    items: Vec<T>,
    sel: usize,
}

impl<T> Default for PickList<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            sel: 0,
        }
    }
}

impl<T> PickList<T> {
    pub(crate) fn items(&self) -> &[T] {
        &self.items
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The selected row (0 when empty; see [`PickList::selected`]).
    pub(crate) fn selected_index(&self) -> usize {
        self.sel
    }

    pub(crate) fn selected(&self) -> Option<&T> {
        self.items.get(self.sel)
    }

    /// Replace the items and select the first.
    pub(crate) fn set(&mut self, items: Vec<T>) {
        self.items = items;
        self.sel = 0;
    }

    pub(crate) fn clear(&mut self) {
        self.set(Vec::new());
    }

    pub(crate) fn push(&mut self, item: T) {
        self.items.push(item);
    }

    /// Move the selection by one row, stopping at either end.
    pub(crate) fn step(&mut self, forward: bool) {
        self.sel = clamp_step(self.sel, self.items.len(), forward);
    }

    /// Pull the selection back inside the items (after they shrank).
    pub(crate) fn clamp(&mut self) {
        self.sel = self.sel.min(self.items.len().saturating_sub(1));
    }

    /// Remove and return the selected item, keeping the selection in range.
    pub(crate) fn remove_selected(&mut self) -> Option<T> {
        let removed = (self.sel < self.items.len()).then(|| self.items.remove(self.sel));
        self.clamp();
        removed
    }
}

/// The all-clusters aggregate view: its rows plus the bookkeeping of the
/// per-cluster fan-out that fills them.
#[derive(Debug, Default)]
pub(crate) struct AggView {
    /// When on, the active tab lists every cluster.
    pub(crate) enabled: bool,
    pub(crate) rows: Vec<AggRow>,
    /// Generation of the current fan-out: slices of an older one are dropped.
    pub(crate) seq: u64,
    /// Clusters of the current fan-out that have not reported yet.
    pub(crate) pending: usize,
    /// Per-`(tab, cluster)` cache of an all-clusters fan-out: each cluster's rows
    /// are cached independently as they arrive, so **partial** progress survives
    /// navigating away - on return, cached clusters render instantly and only the
    /// missing ones are re-fetched (no restart from zero). Cleared per-cluster on
    /// login, per-tab on `r`, and wholesale on topology change / logout.
    pub(crate) cache: HashMap<(Tab, ClusterName), Vec<AggRow>>,
}
