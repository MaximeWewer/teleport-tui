//! Runtime CLI capabilities — what the *installed* `tsh` actually supports.
//!
//! Detection is **runtime** (probe the binary), never `#[cfg(target_os)]`: an
//! old `tsh` on Linux exposes fewer commands than a recent one, and the OS of
//! compilation says nothing about it. The UI uses this to hide actions the
//! local `tsh` cannot perform, instead of failing in the middle of one.

use std::collections::BTreeSet;

/// The set of top-level `tsh` subcommands available at runtime.
///
/// A probe that fails (binary unreadable, unexpected help format) yields the
/// **permissive** [`Capabilities::unknown`]: every command is reported as
/// supported, so a detection miss never hides working features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    commands: BTreeSet<String>,
    /// `false` = probe did not run / failed → treat everything as supported.
    probed: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::unknown()
    }
}

impl Capabilities {
    /// A confirmed set of supported top-level commands (e.g. `ssh`, `kube`).
    #[must_use]
    pub fn probed<I, S>(commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            commands: commands.into_iter().map(Into::into).collect(),
            probed: true,
        }
    }

    /// Permissive fallback: nothing was probed, so everything is "supported".
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            commands: BTreeSet::new(),
            probed: false,
        }
    }

    /// True if `command` is available. Always true when not probed (permissive).
    #[must_use]
    pub fn supports(&self, command: &str) -> bool {
        !self.probed || self.commands.contains(command)
    }

    /// Whether a real probe produced this set (vs. the permissive fallback).
    #[must_use]
    pub fn is_probed(&self) -> bool {
        self.probed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_permissive() {
        let caps = Capabilities::unknown();
        assert!(caps.supports("kube"));
        assert!(caps.supports("anything"));
        assert!(!caps.is_probed());
    }

    #[test]
    fn probed_reports_membership() {
        let caps = Capabilities::probed(["ssh", "kube"]);
        assert!(caps.supports("ssh"));
        assert!(caps.supports("kube"));
        assert!(!caps.supports("db"));
        assert!(caps.is_probed());
    }
}
