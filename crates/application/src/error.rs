//! Application-level error. Wraps domain errors so use cases return a single
//! type; delegates the stable code/category for JSON export.

use domain::error::{Category, DomainError, ReportableError};

#[derive(Debug)]
pub enum AppError {
    Domain(DomainError),
}

impl From<DomainError> for AppError {
    fn from(e: DomainError) -> Self {
        Self::Domain(e)
    }
}

impl ReportableError for AppError {
    fn code(&self) -> &'static str {
        match self {
            Self::Domain(e) => e.code(),
        }
    }
    fn category(&self) -> Category {
        match self {
            Self::Domain(e) => e.category(),
        }
    }
    fn message(&self) -> String {
        match self {
            Self::Domain(e) => e.message(),
        }
    }
    fn cause(&self) -> Option<String> {
        match self {
            Self::Domain(e) => e.cause(),
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AppError {}
