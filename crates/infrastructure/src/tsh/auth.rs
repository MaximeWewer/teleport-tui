//! `tsh status` / `tsh mfa ls` → profile + MFA devices. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`run_json`, `run_scoped_ls`,
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

#[derive(Debug, Clone)]
pub struct TshAuthGateway<R: CommandRunner> {
    runner: R,
    tsh: PathBuf,
}

impl<R: CommandRunner> TshAuthGateway<R> {
    pub fn new(runner: R, tsh: PathBuf) -> Self {
        Self { runner, tsh }
    }
}

impl<R: CommandRunner> AuthGateway for TshAuthGateway<R> {
    fn status(&self) -> Result<Option<Profile>, DomainError> {
        let args = vec!["status".to_owned(), "--format=json".to_owned()];
        match run_cli(&self.runner, &self.tsh, args, "TSH_SPAWN_FAILED") {
            Ok(stdout) => parse_status_json(&stdout),
            // Logged out is a normal state, not an error.
            Err(DomainError::NotAuthenticated) => Ok(None),
            Err(other) => Err(other),
        }
    }

    fn list_mfa_devices(&self) -> Result<Vec<MfaDevice>, DomainError> {
        let args = vec![
            "mfa".to_owned(),
            "ls".to_owned(),
            "--format=json".to_owned(),
        ];
        parse_mfa_devices(&run_cli(&self.runner, &self.tsh, args, "TSH_SPAWN_FAILED")?)
    }
}

#[derive(Debug, DeJson)]
struct MfaDeviceDto {
    metadata: MfaMetaDto,
    #[nserde(default, rename = "addedAt")]
    added_at: String,
    #[nserde(default, rename = "lastUsed")]
    last_used: String,
    // Exactly one of these is present; its presence identifies the device kind.
    // Declared as empty markers — nanoserde ignores the (public, non-secret)
    // inner fields like `publicKeyCbor`.
    #[nserde(default)]
    totp: Option<MfaMarker>,
    #[nserde(default)]
    webauthn: Option<MfaMarker>,
    #[nserde(default)]
    sso: Option<MfaMarker>,
}

/// Presence marker for a device-kind object (`totp`/`webauthn`/`sso`). The lone
/// optional field is never set from JSON — it exists only so nanoserde generates
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
    let dtos: Vec<MfaDeviceDto> =
        DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
            detail: e.to_string(),
        })?;
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
    let dto: StatusDto = DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
        detail: e.to_string(),
    })?;
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
