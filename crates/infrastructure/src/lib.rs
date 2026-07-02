//! Infrastructure layer — adapters that implement the domain ports.
//!
//! The only place that touches the outside world: subprocess exec
//! ([`process`]), `tsh` JSON parsing + mapping ([`tsh`]), per-OS binary/path
//! resolution ([`platform`]), structured NDJSON error export ([`logging`]),
//! and redaction ([`redact`]). Security rules from PLAN.md (no-shell, input
//! validation, output sanitisation, no secrets in logs/argv) live here.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod capability;
pub mod config;
pub mod logging;
pub mod platform;
pub mod process;
pub mod redact;
pub mod tctl;
pub mod tsh;
