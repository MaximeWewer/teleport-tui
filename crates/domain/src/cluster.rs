//! Root / leaf (trusted cluster) model. Central to this deployment.

use crate::error::DomainError;
use crate::value::ClusterName;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterKind {
    Root,
    Leaf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterStatus {
    Online,
    Offline,
}

/// A single cluster the user can target. Listings are always scoped to one of
/// these (or aggregated across all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterContext {
    pub name: ClusterName,
    pub kind: ClusterKind,
    pub status: ClusterStatus,
}

impl ClusterContext {
    #[must_use]
    pub fn is_online(&self) -> bool {
        self.status == ClusterStatus::Online
    }
}

/// The root cluster plus its leaves, and which one is currently selected.
/// Invariant: exactly one root.
#[derive(Debug, Clone)]
pub struct ClusterTopology {
    clusters: Vec<ClusterContext>,
    selected: usize,
}

impl ClusterTopology {
    /// Build from the clusters returned by `tsh clusters`. `selected_name` is
    /// the cluster the CLI reported as current; falls back to the root.
    ///
    /// # Errors
    /// Returns [`DomainError`] if the list is empty or has no root.
    pub fn new(
        clusters: Vec<ClusterContext>,
        selected_name: Option<&ClusterName>,
    ) -> Result<Self, DomainError> {
        if clusters.is_empty() {
            return Err(DomainError::Backend {
                code: "NO_CLUSTERS",
                detail: "cluster list is empty".to_owned(),
            });
        }
        let root = clusters.iter().position(|c| c.kind == ClusterKind::Root);
        let Some(root_idx) = root else {
            return Err(DomainError::Backend {
                code: "NO_ROOT_CLUSTER",
                detail: "no root cluster in topology".to_owned(),
            });
        };
        let selected = selected_name
            .and_then(|n| clusters.iter().position(|c| &c.name == n))
            .unwrap_or(root_idx);
        Ok(Self { clusters, selected })
    }

    #[must_use]
    pub fn all(&self) -> &[ClusterContext] {
        &self.clusters
    }

    #[must_use]
    // The `[0]` fallback is invariant-safe: `new` guarantees a non-empty list and
    // no method removes elements, so `clusters[0]` always exists.
    #[allow(clippy::indexing_slicing)]
    pub fn selected(&self) -> &ClusterContext {
        // `selected` is a valid index by construction; if that invariant ever
        // broke, degrade to the first cluster rather than panic.
        self.clusters
            .get(self.selected)
            .unwrap_or(&self.clusters[0])
    }

    #[must_use]
    // The `[0]` fallback is invariant-safe (non-empty list; see `selected`); a
    // root is also guaranteed by `new`, so `find` never actually misses.
    #[allow(clippy::indexing_slicing)]
    pub fn root(&self) -> &ClusterContext {
        self.clusters
            .iter()
            .find(|c| c.kind == ClusterKind::Root)
            .unwrap_or(&self.clusters[0])
    }

    pub fn leaves(&self) -> impl Iterator<Item = &ClusterContext> + '_ {
        self.clusters.iter().filter(|c| c.kind == ClusterKind::Leaf)
    }

    /// Select a cluster by name. Validating against the real topology prevents
    /// targeting an arbitrary, unverified cluster name.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidValue`] if the name is unknown.
    pub fn select(&mut self, name: &ClusterName) -> Result<(), DomainError> {
        match self.clusters.iter().position(|c| &c.name == name) {
            Some(idx) => {
                self.selected = idx;
                Ok(())
            }
            None => Err(DomainError::InvalidValue {
                field: "cluster_name",
            }),
        }
    }
}
