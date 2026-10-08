//! Validated value objects (newtypes). Construction enforces invariants, so an
//! invalid `ClusterName`/`Hostname`/`Login` cannot exist downstream.

use crate::error::DomainError;

/// Reject control characters and whitespace in identifiers that will become
/// process arguments (defence-in-depth against argv/terminal injection). A
/// leading `-` is also rejected: even with argv-only execution (no shell), a
/// value like `--foo` reaching a *positional* argument is reparsed by `tsh`/
/// `tctl` as a flag (classic argument injection). Resource/cluster names come
/// from the backend, which an attacker may influence, so this is enforced for
/// every newtype.
fn is_safe_ident(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && !s.starts_with('-')
        && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Like [`is_safe_ident`] but for human-chosen labels that may hold spaces
/// (e.g. an MFA device name): control characters and a leading `-` are still
/// rejected, plain spaces are not.
fn is_safe_label(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.starts_with('-') && !s.chars().any(char::is_control)
}

macro_rules! string_newtype {
    ($name:ident, $field:literal, $max:literal, $extra:expr) => {
        string_newtype!($name, $field, $max, is_safe_ident, $extra);
    };
    ($name:ident, $field:literal, $max:literal, $base:path, $extra:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = DomainError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                let extra: fn(&str) -> bool = $extra;
                if $base(&value, $max) && extra(&value) {
                    Ok(Self(value))
                } else {
                    Err(DomainError::InvalidValue { field: $field })
                }
            }
        }

        impl TryFrom<&str> for $name {
            type Error = DomainError;
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::try_from(value.to_owned())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

// Cluster names are DNS-ish: letters, digits, dot, hyphen.
string_newtype!(ClusterName, "cluster_name", 253, |s: &str| {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
});

// SSH target host. DNS-ish charset (letters, digits, dot, hyphen); the
// no-leading-`-` rule in `is_safe_ident` blocks option injection into the ssh
// layer (e.g. `-oProxyCommand=…`, `-L…`). A bare `user@host` form is NOT
// accepted here - model the login separately as a `Login`.
string_newtype!(Hostname, "hostname", 253, |s: &str| {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
});

string_newtype!(Login, "login", 64, |s: &str| {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
});

// Names of kube clusters / databases / apps passed to `tsh ... -c`, and of
// admin users/roles/bots. `@` is allowed because SSO users are usually named
// by email (`alice@example.com`); it is inert in a positional argv slot (no
// shell) and these names are never spliced into a `user@host` target. The
// leading-`-` rule from `is_safe_ident` still applies.
string_newtype!(ResourceName, "resource_name", 256, |s: &str| {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
});

// Comma-separated role names (`tctl users add --roles=`, `tsh request create
// --roles=`). The list is one argv value; `tctl`/`tsh` reject unknown roles.
string_newtype!(RoleList, "roles", 256, |s: &str| {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ','))
});

// Comma-separated join-token type(s) (`tctl tokens add --type=`), e.g.
// `node,app`. Chars only (allowlist); `tctl` rejects unknown types itself.
string_newtype!(TokenTypes, "token_type", 128, |s: &str| {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ','))
});

// Access-request id (UUID-like) passed to `tsh request show/review`.
string_newtype!(RequestId, "request_id", 64, |s: &str| {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
});

// Session id (UUID-like) of a live or recorded session (`tsh join`/`tsh play`).
string_newtype!(SessionId, "session_id", 64, |s: &str| {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
});

// A free-form identifier that becomes a single argv value: a Teleport user or
// proxy address (`tsh login`), a database user, a Kubernetes user/pod/
// container/namespace. No charset beyond `is_safe_ident` (kube users may hold
// `:`, `@`, `/`), so it is only ever passed as `--flag=value` or after `--`.
string_newtype!(Identifier, "identifier", 256, |_: &str| true);

// A Teleport proxy address (`host:port`, or `[v6]:port`) as `tsh login
// --proxy=` takes it; it identifies a `tsh` profile. Always passed in the
// `--proxy=value` form, and `is_safe_ident` already rejects a leading `-`.
string_newtype!(ProxyAddr, "proxy_addr", 260, |s: &str| {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
});

// Name of a registered MFA device (`tsh mfa rm <name>`). Chosen by the user at
// registration, so spaces are allowed; control chars and a leading `-` are not.
string_newtype!(DeviceName, "mfa_device", 256, is_safe_label, |_: &str| true);

/// Operating system the client runs on. Detected at runtime; gates per-OS
/// behaviour (binary name, paths). Capabilities themselves are probed, not
/// inferred from this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsKind {
    Linux,
    Macos,
    Windows,
    Other,
}

impl OsKind {
    #[must_use]
    pub fn current() -> Self {
        match std::env::consts::OS {
            "linux" => Self::Linux,
            "macos" => Self::Macos,
            "windows" => Self::Windows,
            _ => Self::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_control_chars() {
        assert!(ClusterName::try_from("").is_err());
        assert!(Hostname::try_from("bad\nname").is_err());
        assert!(Login::try_from("a b").is_err());
        assert!(ClusterName::try_from("root;rm -rf").is_err());
    }

    #[test]
    fn accepts_valid() {
        assert_eq!(
            ClusterName::try_from("root.example.com").unwrap().as_str(),
            "root.example.com"
        );
        assert!(Login::try_from("admin").is_ok());
        assert!(Hostname::try_from("host-admin").is_ok());
    }

    #[test]
    fn rejects_leading_dash_argument_injection() {
        // A value parsed as a flag if it slips into a positional argv slot.
        assert!(ClusterName::try_from("--foo").is_err());
        assert!(ResourceName::try_from("-c").is_err());
        assert!(Login::try_from("-oProxyCommand=evil").is_err());
        assert!(Hostname::try_from("-L8080:localhost:80").is_err());
        assert!(RequestId::try_from("-x").is_err());
    }

    #[test]
    fn hostname_rejects_shell_and_unicode_metachars() {
        // The old no-op validator accepted these; the DNS charset must not.
        for bad in [
            "a;b",
            "a$b",
            "user@host",
            "a|b",
            "a b",
            "évil",
            "a\u{202e}b",
        ] {
            assert!(Hostname::try_from(bad).is_err(), "should reject {bad:?}");
        }
        assert!(Hostname::try_from("node-01.root.example.com").is_ok());
    }

    #[test]
    fn identifier_session_id_and_device_name() {
        assert!(Identifier::try_from("system:masters").is_ok());
        assert!(Identifier::try_from("proxy.example.com:443").is_ok());
        assert!(Identifier::try_from("-as").is_err());
        assert!(Identifier::try_from("a b").is_err());
        assert!(SessionId::try_from("0b9a3c1e-7f2d-4c1a-9e3b-1f2a3b4c5d6e").is_ok());
        assert!(SessionId::try_from("-x").is_err());
        assert!(DeviceName::try_from("my yubikey").is_ok());
        assert!(DeviceName::try_from("-rf").is_err());
        assert!(DeviceName::try_from("bad\nname").is_err());
    }

    #[test]
    fn proxy_addr_accepts_host_port_only() {
        assert!(ProxyAddr::try_from("proxy.example.com:443").is_ok());
        assert!(ProxyAddr::try_from("[::1]:3080").is_ok());
        for bad in [
            "--proxy=evil",
            "a b:443",
            "https://x.example.com",
            "x;y:1",
            "",
        ] {
            assert!(ProxyAddr::try_from(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn role_list_and_token_types_charsets() {
        assert!(RoleList::try_from("dba,sre.admin").is_ok());
        assert!(RoleList::try_from("-dba").is_err());
        assert!(RoleList::try_from("dba sre").is_err());
        assert!(TokenTypes::try_from("node,app").is_ok());
        assert!(TokenTypes::try_from("--type=node").is_err());
        assert!(TokenTypes::try_from("node.app").is_err());
    }

    #[test]
    fn resource_name_accepts_sso_email_usernames() {
        assert!(ResourceName::try_from("alice@example.com").is_ok());
        assert!(ResourceName::try_from("-alice@example.com").is_err());
        assert!(ResourceName::try_from("a@b c").is_err());
    }
}
