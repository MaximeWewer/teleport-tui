//! Read-only administrative resources surfaced via `tctl get` (root cluster).
//! Editing is intentionally out of scope, except join-token generation.

use crate::resource::{Resource, label_list};
use crate::value::ResourceName;

/// A freshly generated join token (`tctl tokens add`). The `token` field is a
/// **secret**: it is shown once in the UI and must never be logged. `Debug` is
/// hand-written to mask it, so the guarantee is structural — a stray `{:?}` (a
/// log line, a panic message on an unwrapped `Result<GeneratedToken>`) can't leak
/// the token, regardless of caller discipline.
#[derive(Clone, PartialEq, Eq)]
pub struct GeneratedToken {
    pub token: String,
    pub roles: Vec<String>,
    pub expires: String,
    pub ca_pins: Vec<String>,
}

impl core::fmt::Debug for GeneratedToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GeneratedToken")
            .field("token", &"<redacted>")
            .field("roles", &self.roles)
            .field("expires", &self.expires)
            .field("ca_pins", &self.ca_pins)
            .finish()
    }
}

/// A one-time account-setup URL from `tctl users add` / `tctl users reset`. The
/// `url` embeds a secret invitation token — show once, never log. Domain is
/// dependency-free, so it is a plain `String`; the caller moves it into
/// zeroizing storage immediately. `Debug` masks the `url` (see [`GeneratedToken`]).
#[derive(Clone, PartialEq, Eq)]
pub struct InviteLink {
    pub user: String,
    pub url: String,
}

impl core::fmt::Debug for InviteLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InviteLink")
            .field("user", &self.user)
            .field("url", &"<redacted>")
            .finish()
    }
}

/// An existing provision (join) token from `tctl tokens ls`. The listing shows
/// only the same non-secret columns `tctl tokens ls` prints — the token's *name*
/// (its identifier), its type(s), labels and expiry. A freshly *generated*
/// token's secret value is a separate concern (see [`GeneratedToken`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionToken {
    pub name: String,
    pub types: Vec<String>,
    pub labels: Vec<(String, String)>,
    pub expires: String,
}

impl Resource for ProvisionToken {
    fn columns() -> &'static [&'static str] {
        &["TOKEN", "TYPE", "LABELS", "EXPIRES"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            self.types.join(","),
            labels_blob(&self.labels),
            if self.expires.is_empty() {
                "never".to_owned()
            } else {
                self.expires.clone()
            },
        ]
    }
    fn matches(&self, needle: &str) -> bool {
        self.name.to_lowercase().contains(needle)
            || self.types.iter().any(|t| t.to_lowercase().contains(needle))
            || self.labels.iter().any(|(k, v)| {
                k.to_lowercase().contains(needle) || v.to_lowercase().contains(needle)
            })
    }
    fn details(&self) -> Vec<(String, Vec<String>)> {
        vec![
            ("TOKEN".to_owned(), vec![self.name.clone()]),
            ("TYPE".to_owned(), self.types.clone()),
            ("LABELS".to_owned(), label_list(&self.labels)),
            (
                "EXPIRES".to_owned(),
                vec![if self.expires.is_empty() {
                    "never".to_owned()
                } else {
                    self.expires.clone()
                }],
            ),
        ]
    }
}

/// Human TTL: whole hours/minutes where possible, else seconds. `0` → `-`.
fn fmt_ttl(secs: u64) -> String {
    if secs == 0 {
        "-".to_owned()
    } else if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// A Machine ID bot (`tctl bots ls`). Read-only listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bot {
    pub name: ResourceName,
    pub roles: Vec<String>,
    pub user: String,
    pub max_ttl_secs: u64,
    pub labels: Vec<(String, String)>,
}

impl Resource for Bot {
    fn columns() -> &'static [&'static str] {
        &["BOT", "ROLES", "USER", "MAX TTL"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.name.to_string(),
            self.roles.join(","),
            self.user.clone(),
            fmt_ttl(self.max_ttl_secs),
        ]
    }
    fn matches(&self, needle: &str) -> bool {
        self.name.as_str().to_lowercase().contains(needle)
            || self.user.to_lowercase().contains(needle)
            || self.roles.iter().any(|r| r.to_lowercase().contains(needle))
    }
    fn details(&self) -> Vec<(String, Vec<String>)> {
        // `row` omits labels; the detail view surfaces them, one per line.
        vec![
            ("BOT".to_owned(), vec![self.name.to_string()]),
            ("ROLES".to_owned(), self.roles.clone()),
            ("USER".to_owned(), vec![self.user.clone()]),
            ("MAX TTL".to_owned(), vec![fmt_ttl(self.max_ttl_secs)]),
            ("LABELS".to_owned(), label_list(&self.labels)),
        ]
    }
}

/// A connected Teleport agent instance (`tctl inventory ls`). Read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub server_id: String,
    pub hostname: String,
    pub version: String,
    pub services: Vec<String>,
    pub last_seen: String,
}

impl Resource for Instance {
    fn columns() -> &'static [&'static str] {
        &["HOSTNAME", "VERSION", "SERVICES", "LAST SEEN"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.hostname.clone(),
            self.version.clone(),
            self.services.join(","),
            self.last_seen.clone(),
        ]
    }
    fn matches(&self, needle: &str) -> bool {
        self.hostname.to_lowercase().contains(needle)
            || self.version.to_lowercase().contains(needle)
            || self
                .services
                .iter()
                .any(|s| s.to_lowercase().contains(needle))
    }
    fn details(&self) -> Vec<(String, Vec<String>)> {
        // `row` omits the server id (UUID); the detail view shows it.
        vec![
            ("SERVER ID".to_owned(), vec![self.server_id.clone()]),
            ("HOSTNAME".to_owned(), vec![self.hostname.clone()]),
            ("VERSION".to_owned(), vec![self.version.clone()]),
            ("SERVICES".to_owned(), self.services.clone()),
            ("LAST SEEN".to_owned(), vec![self.last_seen.clone()]),
        ]
    }
}

fn labels_blob(labels: &[(String, String)]) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminUser {
    pub name: ResourceName,
    pub roles: Vec<String>,
    pub labels: Vec<(String, String)>,
}

impl Resource for AdminUser {
    fn columns() -> &'static [&'static str] {
        &["USER", "ROLES", "LABELS"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.name.to_string(),
            self.roles.join(","),
            labels_blob(&self.labels),
        ]
    }
    fn matches(&self, needle: &str) -> bool {
        self.name.as_str().to_lowercase().contains(needle)
    }
    fn details(&self) -> Vec<(String, Vec<String>)> {
        vec![
            ("USER".to_owned(), vec![self.name.to_string()]),
            ("ROLES".to_owned(), self.roles.clone()),
            ("LABELS".to_owned(), label_list(&self.labels)),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRole {
    pub name: ResourceName,
    pub description: String,
    pub labels: Vec<(String, String)>,
}

impl Resource for AdminRole {
    fn columns() -> &'static [&'static str] {
        &["ROLE", "DESCRIPTION", "LABELS"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.name.to_string(),
            self.description.clone(),
            labels_blob(&self.labels),
        ]
    }
    fn matches(&self, needle: &str) -> bool {
        self.name.as_str().to_lowercase().contains(needle)
    }
    fn details(&self) -> Vec<(String, Vec<String>)> {
        vec![
            ("ROLE".to_owned(), vec![self.name.to_string()]),
            ("DESCRIPTION".to_owned(), vec![self.description.clone()]),
            ("LABELS".to_owned(), label_list(&self.labels)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_masks_generated_token_secret() {
        let t = GeneratedToken {
            token: "s3cr3t-join-token".to_owned(),
            roles: vec!["Node".to_owned()],
            expires: "2026-07-01T00:00:00Z".to_owned(),
            ca_pins: vec!["sha256:abc".to_owned()],
        };
        let dbg = format!("{t:?}");
        assert!(
            !dbg.contains("s3cr3t-join-token"),
            "token leaked via Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("Node")); // non-secret fields still shown
    }

    #[test]
    fn debug_masks_invite_url_secret() {
        let inv = InviteLink {
            user: "bob".to_owned(),
            url: "https://proxy.example/web/invite/s3cr3t123".to_owned(),
        };
        let dbg = format!("{inv:?}");
        assert!(
            !dbg.contains("s3cr3t123"),
            "invite URL leaked via Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("bob"));
    }
}
