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
///
/// Invariant: exactly one root. It is held apart from the other clusters, so
/// "there is a root" and "the selection always resolves" hold by construction
/// rather than by index bookkeeping.
#[derive(Debug, Clone)]
pub struct ClusterTopology {
    root: ClusterContext,
    /// Every other listed cluster (the leaves), in listing order.
    others: Vec<ClusterContext>,
    /// Index into `others`; `None` selects the root.
    selected: Option<usize>,
}

impl ClusterTopology {
    /// Build from the clusters returned by `tsh clusters`.
    ///
    /// `selected_name` is the cluster the CLI reported as current; falls back
    /// to the root.
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
        let mut root = None;
        let mut others = Vec::with_capacity(clusters.len() - 1);
        for c in clusters {
            if root.is_none() && c.kind == ClusterKind::Root {
                root = Some(c);
            } else {
                others.push(c);
            }
        }
        let Some(root) = root else {
            return Err(DomainError::Backend {
                code: "NO_ROOT_CLUSTER",
                detail: "no root cluster in topology".to_owned(),
            });
        };
        let mut topo = Self {
            root,
            others,
            selected: None,
        };
        if let Some(name) = selected_name {
            // An unknown current cluster keeps the root selected.
            let _ = topo.select(name);
        }
        Ok(topo)
    }

    /// Every cluster, root first, then the others in listing order.
    pub fn all(&self) -> impl Iterator<Item = &ClusterContext> + '_ {
        std::iter::once(&self.root).chain(&self.others)
    }

    #[must_use]
    pub fn selected(&self) -> &ClusterContext {
        // `select` only stores indices it found, so this always resolves; the
        // root fallback just keeps the method total.
        self.selected
            .and_then(|i| self.others.get(i))
            .unwrap_or(&self.root)
    }

    #[must_use]
    pub const fn root(&self) -> &ClusterContext {
        &self.root
    }

    pub fn leaves(&self) -> impl Iterator<Item = &ClusterContext> + '_ {
        self.others.iter().filter(|c| c.kind == ClusterKind::Leaf)
    }

    /// Select a cluster by name.
    ///
    /// Validating against the real topology prevents targeting an arbitrary,
    /// unverified cluster name.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidValue`] if the name is unknown.
    pub fn select(&mut self, name: &ClusterName) -> Result<(), DomainError> {
        if self.root.name == *name {
            self.selected = None;
            return Ok(());
        }
        match self.others.iter().position(|c| &c.name == name) {
            Some(idx) => {
                self.selected = Some(idx);
                Ok(())
            }
            None => Err(DomainError::InvalidValue {
                field: "cluster_name",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster(name: &str, kind: ClusterKind) -> ClusterContext {
        ClusterContext {
            name: ClusterName::try_from(name).unwrap(),
            kind,
            status: ClusterStatus::Online,
        }
    }

    fn name(s: &str) -> ClusterName {
        ClusterName::try_from(s).unwrap()
    }

    /// Root deliberately not first, so `root()` can't pass by accident.
    fn topology(selected: Option<&str>) -> ClusterTopology {
        let clusters = vec![
            cluster("leaf-a", ClusterKind::Leaf),
            cluster("root", ClusterKind::Root),
            cluster("leaf-b", ClusterKind::Leaf),
        ];
        ClusterTopology::new(clusters, selected.map(name).as_ref()).unwrap()
    }

    fn backend_code(err: DomainError) -> &'static str {
        match err {
            DomainError::Backend { code, .. } => code,
            other => panic!("expected a backend error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_an_empty_list() {
        let err = ClusterTopology::new(Vec::new(), None).unwrap_err();
        assert_eq!(backend_code(err), "NO_CLUSTERS");
    }

    #[test]
    fn rejects_a_list_without_a_root() {
        let leaves = vec![cluster("leaf", ClusterKind::Leaf)];
        let err = ClusterTopology::new(leaves, None).unwrap_err();
        assert_eq!(backend_code(err), "NO_ROOT_CLUSTER");
    }

    #[test]
    fn selection_defaults_to_the_root() {
        assert_eq!(topology(None).selected().name.as_str(), "root");
        // A current cluster the CLI reported but that isn't listed: root too.
        assert_eq!(topology(Some("gone")).selected().name.as_str(), "root");
    }

    #[test]
    fn selection_honours_the_reported_current_cluster() {
        assert_eq!(topology(Some("leaf-b")).selected().name.as_str(), "leaf-b");
    }

    #[test]
    fn root_and_leaves_are_found_wherever_they_are_listed() {
        let topo = topology(Some("leaf-a"));
        assert_eq!(topo.root().name.as_str(), "root");
        let leaves: Vec<_> = topo.leaves().map(|c| c.name.as_str()).collect();
        assert_eq!(leaves, ["leaf-a", "leaf-b"]);
        assert_eq!(topo.all().count(), 3);
    }

    #[test]
    fn all_lists_the_root_first_then_the_others_in_order() {
        let topo = topology(None);
        let names: Vec<_> = topo.all().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["root", "leaf-a", "leaf-b"]);
    }

    #[test]
    fn select_switches_only_to_a_known_cluster() {
        let mut topo = topology(None);
        topo.select(&name("leaf-a")).unwrap();
        assert_eq!(topo.selected().name.as_str(), "leaf-a");

        let err = topo.select(&name("evil.example.com")).unwrap_err();
        assert!(matches!(
            err,
            DomainError::InvalidValue {
                field: "cluster_name"
            }
        ));
        // A rejected selection leaves the previous one (and the list) intact.
        assert_eq!(topo.selected().name.as_str(), "leaf-a");
        assert_eq!(topo.all().count(), 3);
    }

    #[test]
    fn online_reflects_the_status() {
        let mut c = cluster("root", ClusterKind::Root);
        assert!(c.is_online());
        c.status = ClusterStatus::Offline;
        assert!(!c.is_online());
    }
}
