//! The per-tab resource listings [`super::App`] holds for the scoped view: one
//! typed vec per tab, plus the generic row/search/count views the update loop
//! needs, so the Tab -> vec mapping lives here instead of in every caller.

use domain::admin::{AdminRole, AdminUser, Bot, Instance, ProvisionToken};
use domain::node::SshNode;
use domain::recording::SessionRecording;
use domain::request::AccessRequest;
use domain::resource::{App as AppResource, Database, KubeCluster, Resource};

use super::Tab;
use super::dispatch::Listing;

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
