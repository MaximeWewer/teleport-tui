//! Active session profile (`tsh status`).

/// The currently authenticated profile. Absence (logged out) is represented by
/// `Option<Profile>` at the port boundary, not by an empty `Profile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub username: String,
    pub cluster: String,
    pub roles: Vec<String>,
    pub logins: Vec<String>,
    pub kubernetes_enabled: bool,
    pub kubernetes_users: Vec<String>,
    /// RFC3339 expiry of the session certificate (as reported by `tsh`).
    pub valid_until: String,
}
