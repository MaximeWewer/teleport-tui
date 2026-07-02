//! Access request entity (Teleport's just-in-time access workflow).

use crate::resource::Resource;
use crate::value::RequestId;

/// Lifecycle state. Teleport marshals this as an integer enum in the V3 spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    None,
    Pending,
    Approved,
    Denied,
    Promoted,
    Unknown,
}

impl RequestState {
    #[must_use]
    pub fn from_code(code: i64) -> Self {
        match code {
            0 => Self::None,
            1 => Self::Pending,
            2 => Self::Approved,
            3 => Self::Denied,
            4 => Self::Promoted,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Promoted => "promoted",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn is_pending(self) -> bool {
        self == Self::Pending
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    pub id: RequestId,
    pub user: String,
    pub roles: Vec<String>,
    pub state: RequestState,
    pub reason: String,
    pub created: String,
}

impl Resource for AccessRequest {
    fn columns() -> &'static [&'static str] {
        &["ID", "USER", "ROLES", "STATE", "REASON"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.user.clone(),
            self.roles.join(","),
            self.state.label().to_owned(),
            self.reason.clone(),
        ]
    }
    fn matches(&self, needle: &str) -> bool {
        // `needle` is already lowercased by the caller (see `Resource::matches`).
        self.id.as_str().to_lowercase().contains(needle)
            || self.user.to_lowercase().contains(needle)
            || self.state.label().contains(needle)
            || self.roles.iter().any(|r| r.to_lowercase().contains(needle))
    }
    fn details(&self) -> Vec<(String, Vec<String>)> {
        // `row` omits the creation time; the detail view shows it.
        vec![
            ("ID".to_owned(), vec![self.id.to_string()]),
            ("USER".to_owned(), vec![self.user.clone()]),
            ("ROLES".to_owned(), self.roles.clone()),
            ("STATE".to_owned(), vec![self.state.label().to_owned()]),
            ("REASON".to_owned(), vec![self.reason.clone()]),
            ("CREATED".to_owned(), vec![self.created.clone()]),
        ]
    }
}
