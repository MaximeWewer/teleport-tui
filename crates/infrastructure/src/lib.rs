//! Infrastructure layer - adapters that implement the domain ports.
//!
//! The only place that touches the outside world: subprocess exec
//! ([`process`]), the `tsh` and `tctl` adapters (JSON parsing + mapping,
//! [`tsh`], [`tctl`]), CLI capability probing ([`capability`]), the config
//! file ([`config`]), per-OS binary/path resolution ([`platform`]), structured
//! NDJSON error export ([`logging`]) and redaction ([`redact`]). The security
//! rules (no shell, input validation, output sanitisation, no secrets in logs)
//! are enforced here.
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
