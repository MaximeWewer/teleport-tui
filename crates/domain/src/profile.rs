//! Session profiles (`tsh status`): the active one in detail, plus a summary
//! of every profile `tsh` knows (one per proxy logged in to).

use crate::value::ProxyAddr;

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

/// One `tsh` profile: a proxy the user has logged in to, active or not. A user
/// with several Teleport clusters behind different proxies has one per proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSummary {
    /// The proxy address `tsh login --proxy=` takes to switch to this profile.
    pub proxy: ProxyAddr,
    /// The cluster this profile has selected (usually the proxy's root).
    pub cluster: String,
    pub username: String,
    /// RFC3339 expiry of the profile's certificate (as reported by `tsh`).
    pub valid_until: String,
    /// `valid_until` as Unix seconds; `None` when it could not be read.
    pub expires_at: Option<i64>,
    /// Whether this is the profile every flagless `tsh`/`tctl` call targets.
    pub active: bool,
}

impl ProfileSummary {
    /// Whether the certificate has expired at `now` (Unix seconds). An unknown
    /// expiry reads as valid: the non-interactive switch then finds out.
    #[must_use]
    pub fn is_expired_at(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|t| t <= now)
    }
}

/// Everything one `tsh status` reports: the active profile (`None` when logged
/// out) and every known profile, the active one included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionStatus {
    pub active: Option<Profile>,
    pub profiles: Vec<ProfileSummary>,
}

impl SessionStatus {
    /// The profiles one could switch to (every one but the active).
    pub fn others(&self) -> impl Iterator<Item = &ProfileSummary> + '_ {
        self.profiles.iter().filter(|p| !p.active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(proxy: &str, active: bool, expires_at: Option<i64>) -> ProfileSummary {
        ProfileSummary {
            proxy: ProxyAddr::try_from(proxy).unwrap(),
            cluster: proxy.to_owned(),
            username: "alice".to_owned(),
            valid_until: String::new(),
            expires_at,
            active,
        }
    }

    #[test]
    fn expiry_is_judged_against_the_given_clock() {
        let p = summary("a.example.com:443", false, Some(100));
        assert!(!p.is_expired_at(99));
        assert!(p.is_expired_at(100));
        assert!(!summary("a.example.com:443", false, None).is_expired_at(i64::MAX));
    }

    #[test]
    fn others_skips_the_active_profile() {
        let status = SessionStatus {
            active: None,
            profiles: vec![
                summary("a.example.com:443", true, None),
                summary("b.example.com:443", false, None),
            ],
        };
        let others: Vec<_> = status.others().map(|p| p.proxy.as_str()).collect();
        assert_eq!(others, ["b.example.com:443"]);
    }
}
