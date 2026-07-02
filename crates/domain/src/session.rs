//! Active sessions (`tsh sessions ls`) — live sessions one can join.

use crate::resource::Resource;

/// One live session, identified by `id` (the id passed to `tsh join`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSession {
    pub id: String,
    pub kind: String,
    pub host: String,
    pub login: String,
    pub started_by: String,
    pub created: String,
}

impl Resource for ActiveSession {
    fn columns() -> &'static [&'static str] {
        &["KIND", "HOST", "LOGIN", "STARTED BY", "CREATED"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.kind.clone(),
            self.host.clone(),
            self.login.clone(),
            self.started_by.clone(),
            self.created.clone(),
        ]
    }
    fn matches(&self, needle: &str) -> bool {
        self.host.to_lowercase().contains(needle)
            || self.login.to_lowercase().contains(needle)
            || self.started_by.to_lowercase().contains(needle)
            || self.kind.to_lowercase().contains(needle)
            || self.id.to_lowercase().contains(needle)
    }
}
