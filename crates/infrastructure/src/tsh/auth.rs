//! `tsh status` / `tsh mfa ls` → profile + MFA devices, and `tsh login <cluster>`
//! to re-select the active profile. DTOs + gateway adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`TshCli`, `tsh_adapter!`, `parse_json`,
//! `classify_failure`, `sorted_labels`, `MetaDto`) and imports come via `super::*`.

#![allow(clippy::question_mark, clippy::wildcard_imports)]
use super::*;

#[derive(Debug, DeJson)]
struct StatusDto {
    #[nserde(default)]
    active: Option<ActiveDto>,
}

#[derive(Debug, DeJson)]
struct ActiveDto {
    #[nserde(default)]
    username: String,
    #[nserde(default)]
    cluster: String,
    #[nserde(default)]
    roles: Vec<String>,
    #[nserde(default)]
    logins: Vec<String>,
    #[nserde(default)]
    kubernetes_enabled: bool,
    #[nserde(default)]
    kubernetes_users: Vec<String>,
    #[nserde(default)]
    valid_until: String,
}

tsh_adapter!(TshAuthGateway);

impl<R: CommandRunner> AuthGateway for TshAuthGateway<R> {
    fn status(&self) -> Result<Option<Profile>, DomainError> {
        match self.cli.run(args(&["status", "--format=json"])) {
            Ok(stdout) => parse_status_json(&stdout),
            // Logged out is a normal state, not an error.
            Err(DomainError::NotAuthenticated) => Ok(None),
            Err(other) => Err(other),
        }
    }

    fn list_mfa_devices(&self) -> Result<Vec<MfaDevice>, DomainError> {
        parse_mfa_devices(&self.cli.run(args(&["mfa", "ls", "--format=json"]))?)
    }

    fn select_cluster(&self, cluster: &ClusterName) -> Result<(), DomainError> {
        // `cluster` becomes a *positional* argv element; being a `ClusterName`
        // it can't be empty or flag-like (no leading `-`).
        // `tsh login <cluster>` (POSITIONAL) selects a cluster under the current
        // proxy - the root or a trusted leaf - so a following `tctl` call (or a
        // `tsh` command without a cluster flag), which targets whatever cluster
        // the profile has selected, hits the right one.
        // NOT `tsh login --proxy=<cluster>`: `--proxy` is a proxy *address*, not a
        // cluster, so passing a cluster name there left the selected cluster (and
        // thus `tctl`) pointed at the previous one. With a valid cached cert this
        // is instant and silent. Failures go through the shared classifier, so a
        // network error or an expired cert stays distinguishable (with its
        // redacted stderr) from a plain "login required".
        match self.cli.run(vec!["login".to_owned(), cluster.to_string()]) {
            Ok(_) => Ok(()),
            // Without a cached session tsh tries to prompt for credentials, which
            // fails here (stdin is not a tty): that is "login required" too.
            Err(DomainError::Backend { detail, .. }) if needs_interactive_login(&detail) => {
                Err(DomainError::NotAuthenticated)
            }
            Err(e) => Err(e),
        }
    }
}

/// Messages a `tsh` (v18) login emits when it needs to prompt but has no
/// terminal. Taken verbatim from the tsh binary's own strings, not guessed:
/// the error its prompt package returns when stdin is not a tty (password /
/// OTP prompts), its relogin guard, and Go's `ENOTTY` text from a failed
/// raw-mode switch.
const NO_TTY_LOGIN_ERRORS: &[&str] = &[
    "underlying reader is not a terminal",
    "cannot relogin in non-interactive session",
    "inappropriate ioctl for device",
];

/// Whether a failed `tsh login` stderr shows it wanted to prompt the user
/// (password / MFA / SSO), i.e. only an interactive login can fix it.
fn needs_interactive_login(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    NO_TTY_LOGIN_ERRORS.iter().any(|m| s.contains(m))
}

#[derive(Debug, DeJson)]
struct MfaDeviceDto {
    metadata: MfaMetaDto,
    #[nserde(default, rename = "addedAt")]
    added_at: String,
    #[nserde(default, rename = "lastUsed")]
    last_used: String,
    // Exactly one of these is present; its presence identifies the device kind.
    // Declared as empty markers - nanoserde ignores the (public, non-secret)
    // inner fields like `publicKeyCbor`.
    #[nserde(default)]
    totp: Option<MfaMarker>,
    #[nserde(default)]
    webauthn: Option<MfaMarker>,
    #[nserde(default)]
    sso: Option<MfaMarker>,
}

/// Presence marker for a device-kind object (`totp`/`webauthn`/`sso`). The lone
/// optional field is never set from JSON - it exists only so nanoserde generates
/// an unknown-field-skipping parser (a zero-field struct rejects inner fields
/// like `publicKeyCbor`).
#[derive(Debug, Default, DeJson)]
struct MfaMarker {
    #[nserde(default)]
    #[allow(dead_code)]
    _present: Option<bool>,
}

#[derive(Debug, DeJson)]
struct MfaMetaDto {
    #[nserde(rename = "Name")]
    name: String,
}

fn parse_mfa_devices(stdout: &str) -> Result<Vec<MfaDevice>, DomainError> {
    let dtos: Vec<MfaDeviceDto> = parse_json(stdout)?;
    Ok(dtos
        .into_iter()
        .map(|d| {
            let kind = if d.webauthn.is_some() {
                "webauthn"
            } else if d.totp.is_some() {
                "totp"
            } else if d.sso.is_some() {
                "sso"
            } else {
                "other"
            };
            MfaDevice {
                name: d.metadata.name,
                kind: kind.to_owned(),
                added: d.added_at,
                last_used: d.last_used,
            }
        })
        .collect())
}

fn parse_status_json(stdout: &str) -> Result<Option<Profile>, DomainError> {
    let dto: StatusDto = parse_json(stdout)?;
    Ok(dto.active.map(|a| Profile {
        username: a.username,
        cluster: a.cluster,
        roles: a.roles,
        logins: a.logins,
        kubernetes_enabled: a.kubernetes_enabled,
        kubernetes_users: a.kubernetes_users,
        valid_until: a.valid_until,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::CommandOutcome;

    /// Runner that fails every command with `stderr`.
    #[derive(Debug)]
    struct FailingRunner {
        stderr: &'static str,
    }
    impl CommandRunner for FailingRunner {
        fn run(&self, _req: &CommandRequest) -> std::io::Result<CommandOutcome> {
            Ok(CommandOutcome {
                status: Some(1),
                stdout: String::new(),
                stderr: self.stderr.to_owned(),
            })
        }
    }

    fn select_with(stderr: &'static str) -> DomainError {
        TshAuthGateway::new(FailingRunner { stderr }, "tsh".into())
            .select_cluster(&ClusterName::try_from("leaf.example").unwrap())
            .unwrap_err()
    }

    #[test]
    fn select_cluster_distinguishes_failures() {
        assert!(matches!(
            select_with("ERROR: not logged in"),
            DomainError::NotAuthenticated
        ));
        for no_tty in [
            "ERROR: underlying reader is not a terminal",
            "ERROR: cannot relogin in non-interactive session",
            "ERROR: inappropriate ioctl for device",
        ] {
            assert!(
                matches!(select_with(no_tty), DomainError::NotAuthenticated),
                "{no_tty:?} should read as login required"
            );
        }
        // A server-side error that merely mentions a password is not a prompt
        // tsh couldn't show: keep its detail instead of hiding it as "login".
        assert!(matches!(
            select_with("ERROR: password authentication is disabled for this cluster"),
            DomainError::Backend { .. }
        ));
        assert!(matches!(
            select_with("ERROR: your certificate has expired"),
            DomainError::CertExpired
        ));
        match select_with("ERROR: dial tcp 10.0.0.1:443: connection refused") {
            DomainError::Backend { detail, .. } => assert!(detail.contains("connection refused")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn parses_mfa_devices() {
        // Shape from a real `tsh mfa ls --format=json` (public-key fields elided).
        let json = r#"[
            {"kind":"mfa_device","version":"v1","metadata":{"Name":"2fa-web","Namespace":"default"},
             "id":"dea0ba8d","addedAt":"2025-10-01T12:30:59Z","lastUsed":"2025-10-01T12:30:59Z","totp":{}},
            {"kind":"mfa_device","version":"v1","metadata":{"Name":"BItwarden","Namespace":"default"},
             "id":"f786a3f2","addedAt":"2026-02-23T12:53:36Z","lastUsed":"2026-06-29T16:28:11Z",
             "webauthn":{"credentialId":"zCNH+xUmSQ==","publicKeyCbor":"pQ==","attestationType":"none"}}
        ]"#;
        let devs = parse_mfa_devices(json).unwrap();
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].name, "2fa-web");
        assert_eq!(devs[0].kind, "totp");
        assert_eq!(devs[1].name, "BItwarden");
        assert_eq!(devs[1].kind, "webauthn");
    }
    #[test]
    fn parses_status_active_profile() {
        let p = parse_status_json(include_str!("../../tests/fixtures/status.json"))
            .unwrap()
            .expect("active profile");
        assert_eq!(p.username, "maxime.wewer");
        assert_eq!(p.cluster, "root.example.com");
        assert!(p.kubernetes_enabled);
        assert!(p.logins.contains(&"root".to_owned()));
    }
    #[test]
    fn parses_status_logged_out() {
        let p =
            parse_status_json(include_str!("../../tests/fixtures/status_loggedout.json")).unwrap();
        assert!(p.is_none());
    }
}
