//! Domain layer — the pure business core of teleport-tui.
//!
//! Hexagonal architecture, innermost ring: **no dependencies**, **no I/O**.
//! Defines value objects, entities/aggregates, ports (traits), and the stable
//! error vocabulary used for JSON export. Infrastructure depends on these
//! traits; the dependency rule points inward only.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod admin;
pub mod capability;
pub mod cluster;
pub mod error;
pub mod mfa;
pub mod node;
pub mod port;
pub mod profile;
pub mod recording;
pub mod request;
pub mod resource;
pub mod session;
pub mod value;
