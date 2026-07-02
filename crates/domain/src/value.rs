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

macro_rules! string_newtype {
    ($name:ident, $field:literal, $max:literal, $extra:expr) => {
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
                if is_safe_ident(&value, $max) && extra(&value) {
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
// accepted here — model the login separately as a `Login`.
string_newtype!(Hostname, "hostname", 253, |s: &str| {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
});

string_newtype!(Login, "login", 64, |s: &str| {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
});

// Names of kube clusters / databases / apps passed to `tsh ... -c`.
string_newtype!(ResourceName, "resource_name", 256, |s: &str| {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
});

// Access-request id (UUID-like) passed to `tsh request show/review`.
string_newtype!(RequestId, "request_id", 64, |s: &str| {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
});

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
}
