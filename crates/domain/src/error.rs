//! Domain errors with **stable codes** for JSON export.
//!
//! Every error exposes a never-changing `code()` (the analysis key) plus a
//! `category()`. Adapters fold their I/O failures into these domain-level
//! variants so the whole app reports a single, structured error vocabulary.

use std::fmt;

/// Coarse classification used for filtering exported error logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Auth,
    Network,
    Parse,
    Input,
    Internal,
}

impl Category {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Network => "network",
            Self::Parse => "parse",
            Self::Input => "input",
            Self::Internal => "internal",
        }
    }
}

/// Anything that can be exported as a structured (NDJSON) error record.
/// Implemented by every error type across the layers.
pub trait ReportableError {
    fn code(&self) -> &'static str;
    fn category(&self) -> Category;
    fn message(&self) -> String;
    fn cause(&self) -> Option<String> {
        None
    }
}

#[derive(Debug)]
pub enum DomainError {
    /// A value object failed validation.
    InvalidValue { field: &'static str },
    /// No valid Teleport session (not logged in).
    NotAuthenticated,
    /// Certificate expired — re-login required.
    CertExpired,
    /// A leaf cluster is unreachable.
    ClusterOffline { cluster: String },
    /// The Teleport CLI was not found on this machine.
    BinaryNotFound,
    /// CLI returned non-zero / unexpected output (adapter-level failure folded
    /// into the domain vocabulary).
    Backend { code: &'static str, detail: String },
    /// Could not parse CLI output.
    Parse { detail: String },
}

impl ReportableError for DomainError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidValue { .. } => "INPUT_INVALID",
            Self::NotAuthenticated => "NOT_LOGGED_IN",
            Self::CertExpired => "CERT_EXPIRED",
            Self::ClusterOffline { .. } => "LEAF_OFFLINE",
            Self::BinaryNotFound => "TSH_NOT_FOUND",
            Self::Backend { code, .. } => code,
            Self::Parse { .. } => "JSON_PARSE",
        }
    }

    fn category(&self) -> Category {
        match self {
            Self::InvalidValue { .. } => Category::Input,
            Self::NotAuthenticated | Self::CertExpired => Category::Auth,
            Self::ClusterOffline { .. } | Self::BinaryNotFound | Self::Backend { .. } => {
                Category::Network
            }
            Self::Parse { .. } => Category::Parse,
        }
    }

    fn message(&self) -> String {
        match self {
            Self::InvalidValue { field } => format!("invalid value for `{field}`"),
            Self::NotAuthenticated => "not logged in to a Teleport cluster".to_owned(),
            Self::CertExpired => "Teleport certificate has expired".to_owned(),
            Self::ClusterOffline { cluster } => format!("leaf cluster `{cluster}` is offline"),
            Self::BinaryNotFound => "Teleport CLI (tsh) not found".to_owned(),
            Self::Backend { detail, .. } | Self::Parse { detail } => detail.clone(),
        }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code(), self.message())
    }
}

impl std::error::Error for DomainError {}
