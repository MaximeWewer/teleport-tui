//! `tsh login` options as closed value types: the authentication method
//! (`--auth`) and the preferred MFA mode (`--mfa-mode`). Parsing is the single
//! validation point, so a config typo or an unsupported value is caught where it
//! is read instead of reaching `tsh` as a free string.

use crate::error::DomainError;
use crate::value::ResourceName;

/// How `tsh login` authenticates (`--auth`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    /// `--auth=local`: password (and second factor) typed in the terminal.
    Local,
    /// `--auth=passwordless`: a passkey / security key, no password.
    Passwordless,
    /// The cluster's default SSO connector: no `--auth` flag, `tsh` opens the
    /// browser itself.
    Sso,
    /// A specific auth connector by name (`--auth=<name>`, e.g. a second OIDC,
    /// SAML or GitHub connector). `tsh` accepts any connector name here, so this
    /// is the escape hatch; the name is still a validated [`ResourceName`].
    Connector(ResourceName),
}

impl AuthMethod {
    /// The fixed choices offered by the login/settings dropdowns (a
    /// [`AuthMethod::Connector`] comes only from the config file).
    pub const CHOICES: [Self; 3] = [Self::Local, Self::Passwordless, Self::Sso];

    /// The config / display spelling (round-trips through [`TryFrom`]).
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Local => "local",
            Self::Passwordless => "passwordless",
            Self::Sso => "sso",
            Self::Connector(name) => name.as_str(),
        }
    }

    /// The `--auth` value to pass, or `None` for the default SSO flow (which
    /// takes no connector value).
    #[must_use]
    pub fn flag_value(&self) -> Option<&str> {
        match self {
            Self::Sso => None,
            other => Some(other.as_str()),
        }
    }
}

impl TryFrom<&str> for AuthMethod {
    type Error = DomainError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "local" => Self::Local,
            "passwordless" => Self::Passwordless,
            "sso" => Self::Sso,
            other => Self::Connector(
                ResourceName::try_from(other)
                    .map_err(|_| DomainError::InvalidValue { field: "auth" })?,
            ),
        })
    }
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Preferred MFA mode for `tsh login --mfa-mode`. The variants are exactly the
/// values `tsh` (v18) accepts: `auto, cross-platform, platform, otp, sso,
/// browser`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MfaMode {
    Auto,
    /// Roaming authenticators, e.g. a security key such as a Yubikey.
    CrossPlatform,
    /// The machine's built-in authenticator (TPM / Touch ID).
    Platform,
    /// A one-time code typed in the terminal.
    Otp,
    Sso,
    Browser,
}

impl MfaMode {
    /// Every mode, in the order the dropdowns offer them.
    pub const CHOICES: [Self; 6] = [
        Self::Otp,
        Self::CrossPlatform,
        Self::Platform,
        Self::Sso,
        Self::Browser,
        Self::Auto,
    ];

    /// The `--mfa-mode` / config spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::CrossPlatform => "cross-platform",
            Self::Platform => "platform",
            Self::Otp => "otp",
            Self::Sso => "sso",
            Self::Browser => "browser",
        }
    }
}

impl TryFrom<&str> for MfaMode {
    type Error = DomainError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "auto" => Ok(Self::Auto),
            // `webauthn` is what older versions of the settings screen saved for
            // security keys; tsh itself rejects it, so read it as its successor.
            "cross-platform" | "webauthn" => Ok(Self::CrossPlatform),
            "platform" => Ok(Self::Platform),
            "otp" => Ok(Self::Otp),
            "sso" => Ok(Self::Sso),
            "browser" => Ok(Self::Browser),
            _ => Err(DomainError::InvalidValue { field: "mfa" }),
        }
    }
}

impl std::fmt::Display for MfaMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_method_parses_builtins_and_named_connectors() {
        assert_eq!(AuthMethod::try_from("local").unwrap(), AuthMethod::Local);
        assert_eq!(AuthMethod::try_from("sso").unwrap().flag_value(), None);
        let okta = AuthMethod::try_from("okta-sso").unwrap();
        assert_eq!(okta.flag_value(), Some("okta-sso"));
        assert!(matches!(okta, AuthMethod::Connector(_)));
        // Not a usable connector name: flag-like, whitespace, empty.
        for bad in ["--proxy=evil", "my connector", ""] {
            assert!(AuthMethod::try_from(bad).is_err(), "{bad:?}");
        }
        for m in AuthMethod::CHOICES {
            assert_eq!(AuthMethod::try_from(m.as_str()).unwrap(), m);
        }
    }

    #[test]
    fn mfa_mode_accepts_only_tsh_values() {
        for m in MfaMode::CHOICES {
            assert_eq!(MfaMode::try_from(m.as_str()).unwrap(), m);
        }
        assert_eq!(
            MfaMode::try_from("webauthn").unwrap(),
            MfaMode::CrossPlatform
        );
        assert!(MfaMode::try_from("yubikey").is_err());
        assert!(MfaMode::try_from("").is_err());
    }
}
