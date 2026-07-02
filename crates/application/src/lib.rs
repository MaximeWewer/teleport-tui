//! Application layer — use cases that orchestrate the domain through its ports.
//! Depends only on `domain`, so use cases are testable with fake adapters.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod command;
pub mod error;
pub mod use_case;
