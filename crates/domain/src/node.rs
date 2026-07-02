//! SSH node entity — the MVP resource.

use crate::resource::Resource;
use crate::value::Hostname;

/// A reachable SSH node in a cluster. `id` is Teleport's UUID, `hostname` the
/// human name, `labels` the static metadata used for search/filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshNode {
    pub id: String,
    pub hostname: Hostname,
    pub address: String,
    pub labels: Vec<(String, String)>,
}

impl SshNode {
    /// True if `needle` (assumed already lowercased) is a substring of the
    /// hostname. Search is intentionally scoped to the hostname only (not
    /// labels/address).
    #[must_use]
    pub fn matches(&self, needle: &str) -> bool {
        self.hostname.as_str().to_lowercase().contains(needle)
    }
}

impl Resource for SshNode {
    fn columns() -> &'static [&'static str] {
        &["HOSTNAME", "ADDRESS", "LABELS"]
    }
    fn row(&self) -> Vec<String> {
        let labels = self
            .labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        let addr = if self.address.is_empty() {
            "-".to_owned()
        } else {
            self.address.clone()
        };
        vec![self.hostname.to_string(), addr, labels]
    }
    fn matches(&self, needle: &str) -> bool {
        SshNode::matches(self, needle)
    }
}
