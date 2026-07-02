//! Additional cluster resources (Kubernetes, databases, apps) and a common
//! `Resource` trait so the UI can render any of them generically.

use crate::value::ResourceName;

/// A displayable, searchable cluster resource. Keeps the UI generic across
/// resource kinds without leaking presentation into the entities.
pub trait Resource {
    /// Column headers for the table view.
    fn columns() -> &'static [&'static str]
    where
        Self: Sized;
    /// One row of cell strings, aligned with [`Resource::columns`].
    fn row(&self) -> Vec<String>;
    /// Case-insensitive match against the search needle. CONTRACT: `needle` is
    /// already lowercased by the caller, so impls lowercase only the haystack —
    /// this avoids re-lowercasing the needle once per item on every keystroke.
    fn matches(&self, needle: &str) -> bool;

    /// Full `(label, values)` breakdown for a detail popup: every field,
    /// untruncated. Each field is a **list of values** (a scalar is a one-element
    /// list) so the view can render multi-valued fields — roles, labels — one
    /// item per line instead of a comma blob. Defaults to pairing
    /// [`Resource::columns`] with [`Resource::row`] as single-element lists;
    /// override to split multi-valued fields and surface fields the table omits.
    fn details(&self) -> Vec<(String, Vec<String>)>
    where
        Self: Sized,
    {
        Self::columns()
            .iter()
            .map(|c| (*c).to_owned())
            .zip(self.row().into_iter().map(|v| vec![v]))
            .collect()
    }
}

/// `k=v` pairs as one string per label — for the multi-line detail view.
#[must_use]
pub fn label_list(labels: &[(String, String)]) -> Vec<String> {
    labels.iter().map(|(k, v)| format!("{k}={v}")).collect()
}

fn labels_blob(labels: &[(String, String)]) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeCluster {
    pub name: ResourceName,
    pub labels: Vec<(String, String)>,
}

impl Resource for KubeCluster {
    fn columns() -> &'static [&'static str] {
        &["KUBE CLUSTER", "LABELS"]
    }
    fn row(&self) -> Vec<String> {
        vec![self.name.to_string(), labels_blob(&self.labels)]
    }
    fn matches(&self, needle: &str) -> bool {
        self.name.as_str().to_lowercase().contains(needle)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Database {
    pub name: ResourceName,
    pub protocol: String,
    pub uri: String,
    pub labels: Vec<(String, String)>,
}

impl Resource for Database {
    fn columns() -> &'static [&'static str] {
        &["DATABASE", "PROTOCOL", "URI", "LABELS"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.name.to_string(),
            self.protocol.clone(),
            self.uri.clone(),
            labels_blob(&self.labels),
        ]
    }
    fn matches(&self, needle: &str) -> bool {
        self.name.as_str().to_lowercase().contains(needle)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    pub name: ResourceName,
    pub uri: String,
    pub public_addr: String,
    pub labels: Vec<(String, String)>,
}

impl Resource for App {
    fn columns() -> &'static [&'static str] {
        &["APP", "PUBLIC ADDRESS", "URI", "LABELS"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.name.to_string(),
            self.public_addr.clone(),
            self.uri.clone(),
            labels_blob(&self.labels),
        ]
    }
    fn matches(&self, needle: &str) -> bool {
        self.name.as_str().to_lowercase().contains(needle)
    }
}
