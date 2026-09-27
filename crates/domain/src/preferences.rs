//! The user-editable defaults (the Settings screen), persisted between runs.
//! A plain value: where and how it is stored is the [`PreferencesStore`] port's
//! concern.
//!
//! [`PreferencesStore`]: crate::port::PreferencesStore

use crate::auth::{AuthMethod, MfaMode};

/// Persisted defaults. Free-text fields hold what the user typed; each is
/// parsed into its newtype where it is used, so an invalid value falls back to
/// prompting instead of reaching `tsh`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preferences {
    /// Login-form proxy address.
    pub proxy: Option<String>,
    /// Login-form Teleport user.
    pub user: Option<String>,
    pub auth: Option<AuthMethod>,
    pub mfa: Option<MfaMode>,
    /// SSH login that skips the login picker.
    pub default_login: Option<String>,
    /// Kubernetes user that skips the user picker.
    pub kube_user: Option<String>,
    /// Database user that skips the prompt.
    pub db_user: Option<String>,
    /// Auto-refresh interval (applied on next launch).
    pub refresh_seconds: Option<u64>,
    /// Kubernetes launchers offered when opening a kube cluster.
    pub kube_tools: Vec<String>,
}
