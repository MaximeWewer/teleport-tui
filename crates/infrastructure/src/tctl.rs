//! `tctl` adapter: read-only admin listings (`tctl get users|roles`). `tctl`
//! always targets the *currently logged-in* proxy (it has no cluster flag), so
//! the all-clusters admin view re-selects each cluster via [`select_cluster`]
//! (`tsh login --proxy`) before listing. Editing is out of scope; token
//! *generation* is handled interactively by the UI (terminal handed to `tctl`,
//! never captured).
//!
//! [`select_cluster`]: domain::port::AdminRepository::select_cluster

// nanoserde's derived `DeJson` impls expand to `?`-style blocks clippy flags.
#![allow(clippy::question_mark)]

use std::collections::HashMap;
use std::path::PathBuf;

use domain::admin::{
    AdminRole, AdminUser, Bot, GeneratedToken, Instance, InviteLink, ProvisionToken,
};
use domain::error::DomainError;
use domain::port::AdminRepository;
use domain::value::ResourceName;
use nanoserde::DeJson;
use zeroize::Zeroizing;

use crate::process::{CommandRequest, CommandRunner};
use crate::tsh::{classify_failure, run_cli, sorted_labels};

#[derive(Debug, DeJson)]
struct UserDto {
    metadata: UserMetaDto,
    spec: UserSpecDto,
}

#[derive(Debug, DeJson)]
struct UserMetaDto {
    name: String,
    #[nserde(default)]
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, DeJson)]
struct UserSpecDto {
    #[nserde(default)]
    roles: Vec<String>,
}

#[derive(Debug, DeJson)]
struct RoleDto {
    metadata: RoleMetaDto,
}

#[derive(Debug, DeJson)]
struct RoleMetaDto {
    name: String,
    #[nserde(default)]
    description: String,
    #[nserde(default)]
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct TctlAdminRepository<R: CommandRunner> {
    runner: R,
    tctl: PathBuf,
    /// `tsh` binary, used only to re-select the active profile for all-clusters
    /// admin (`tsh login --proxy=…`); `tctl` itself has no cluster flag.
    tsh: PathBuf,
}

impl<R: CommandRunner> TctlAdminRepository<R> {
    pub fn new(runner: R, tctl: PathBuf, tsh: PathBuf) -> Self {
        Self { runner, tctl, tsh }
    }

    fn get(&self, kind: &str) -> Result<String, DomainError> {
        let args = vec![
            "get".to_owned(),
            kind.to_owned(),
            "--format=json".to_owned(),
        ];
        run_cli(&self.runner, &self.tctl, args, "TCTL_SPAWN_FAILED")
    }

    /// Run a `tctl` subcommand and return stdout (non-secret listings).
    fn run_json(&self, args: Vec<String>) -> Result<String, DomainError> {
        run_cli(&self.runner, &self.tctl, args, "TCTL_SPAWN_FAILED")
    }

    /// Run a `users add`/`reset` command and extract the one-time setup URL.
    fn invite(&self, user: &str, req: &CommandRequest) -> Result<InviteLink, DomainError> {
        let outcome = self.runner.run(req).map_err(|e| DomainError::Backend {
            code: "TCTL_SPAWN_FAILED",
            detail: e.to_string(),
        })?;
        if !outcome.succeeded() {
            return Err(classify_failure(&outcome.stderr));
        }
        // stdout embeds the secret setup URL → scrub once it is extracted.
        let stdout = Zeroizing::new(outcome.stdout);
        parse_invite(user, &stdout)
    }
}

impl<R: CommandRunner> AdminRepository for TctlAdminRepository<R> {
    fn list_users(&self) -> Result<Vec<AdminUser>, DomainError> {
        parse_users(&self.get("users")?)
    }
    fn list_roles(&self) -> Result<Vec<AdminRole>, DomainError> {
        parse_roles(&self.get("roles")?)
    }

    fn list_tokens(&self) -> Result<Vec<ProvisionToken>, DomainError> {
        // The listing is non-secret (names/types/labels/expiry, exactly what
        // `tctl tokens ls` prints), so no scrubbing is needed here.
        let args = vec![
            "tokens".to_owned(),
            "ls".to_owned(),
            "--format=json".to_owned(),
        ];
        parse_tokens(&run_cli(
            &self.runner,
            &self.tctl,
            args,
            "TCTL_SPAWN_FAILED",
        )?)
    }

    fn remove_token(&self, token: &str) -> Result<(), DomainError> {
        // `token` is the token's name (its identifier), passed as a positional
        // argv element (no shell).
        let args = vec!["tokens".to_owned(), "rm".to_owned(), token.to_owned()];
        run_cli(&self.runner, &self.tctl, args, "TCTL_SPAWN_FAILED").map(|_| ())
    }

    fn add_user(&self, user: &str, roles: &str) -> Result<InviteLink, DomainError> {
        // `user` is a positional argv element (validated upstream); roles use the
        // `--roles=` form so a value can't be reparsed as a flag. No shell.
        let req = CommandRequest::new(
            self.tctl.clone(),
            vec![
                "users".to_owned(),
                "add".to_owned(),
                user.to_owned(),
                format!("--roles={roles}"),
            ],
        );
        self.invite(user, &req)
    }

    fn reset_user(&self, user: &str) -> Result<InviteLink, DomainError> {
        let req = CommandRequest::new(
            self.tctl.clone(),
            vec!["users".to_owned(), "reset".to_owned(), user.to_owned()],
        );
        self.invite(user, &req)
    }

    fn list_bots(&self) -> Result<Vec<Bot>, DomainError> {
        parse_bots(&self.run_json(vec![
            "bots".to_owned(),
            "ls".to_owned(),
            "--format=json".to_owned(),
        ])?)
    }

    fn list_instances(&self) -> Result<Vec<Instance>, DomainError> {
        parse_instances(&self.run_json(vec![
            "inventory".to_owned(),
            "ls".to_owned(),
            "--format=json".to_owned(),
        ])?)
    }

    fn can_admin(&self) -> bool {
        // Lightweight probe: `tctl status` succeeds only for an identity with
        // auth-server admin access, so it gates the Admin tabs without listing
        // every role. A spawn failure (tctl missing) also reads as "no admin".
        let req = CommandRequest::new(self.tctl.clone(), vec!["status".to_owned()]);
        self.runner.run(&req).is_ok_and(|o| o.succeeded())
    }

    fn select_cluster(&self, cluster: &str) -> Result<(), DomainError> {
        // `cluster` is a validated topology name. It becomes a *positional* argv
        // element, so also reject empty / leading-`-` (flag injection) / whitespace
        // / control chars, defence-in-depth against a malformed value reshaping argv.
        if cluster.is_empty()
            || cluster.starts_with('-')
            || cluster.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(DomainError::InvalidValue { field: "cluster" });
        }
        // `tsh login <cluster>` (POSITIONAL) selects a cluster under the current
        // proxy — the root or a trusted leaf — so the following `tctl` call, which
        // targets whatever cluster the profile has selected, hits the right one.
        // NOT `tsh login --proxy=<cluster>`: `--proxy` is a proxy *address*, not a
        // cluster, so passing a cluster name there left the selected cluster (and
        // thus `tctl`) pointed at the previous one. With a valid cached cert this
        // is instant and silent; without one tsh would need a password — impossible
        // here (no tty) — so a non-zero exit means "login required".
        let req = CommandRequest::new(
            self.tsh.clone(),
            vec!["login".to_owned(), cluster.to_owned()],
        );
        let outcome = self.runner.run(&req).map_err(|e| DomainError::Backend {
            code: "TSH_SPAWN_FAILED",
            detail: e.to_string(),
        })?;
        if outcome.succeeded() {
            Ok(())
        } else {
            Err(DomainError::NotAuthenticated)
        }
    }

    fn generate_token(&self, token_type: &str) -> Result<GeneratedToken, DomainError> {
        // SECURITY: stdout contains the secret token; it is parsed and returned
        // for one-time display, but never written to logs. On failure only the
        // (redacted) stderr is surfaced — never stdout.
        let req = CommandRequest::new(
            self.tctl.clone(),
            vec![
                "tokens".to_owned(),
                "add".to_owned(),
                format!("--type={token_type}"),
                "--format=json".to_owned(),
            ],
        );
        let outcome = self.runner.run(&req).map_err(|e| DomainError::Backend {
            code: "TCTL_SPAWN_FAILED",
            detail: e.to_string(),
        })?;
        if !outcome.succeeded() {
            return Err(classify_failure(&outcome.stderr));
        }
        // stdout carries the secret token verbatim. Hold it in a zeroizing
        // buffer so the JSON (token included) is scrubbed from memory as soon
        // as parsing extracts the fields — it must not linger in freed heap.
        let stdout = Zeroizing::new(outcome.stdout);
        parse_token(&stdout)
    }
}

#[derive(Debug, DeJson)]
struct TokenDto {
    token: String,
    #[nserde(default)]
    roles: Vec<String>,
    #[nserde(default)]
    expires: String,
    #[nserde(default)]
    ca_pins: Vec<String>,
}

fn parse_token(stdout: &str) -> Result<GeneratedToken, DomainError> {
    // On parse failure, surface only a generic message — the input may contain
    // the secret token, so it must not appear in the error detail.
    let dto: TokenDto = DeJson::deserialize_json(stdout).map_err(|_| DomainError::Parse {
        detail: "could not parse token JSON".to_owned(),
    })?;
    Ok(GeneratedToken {
        token: dto.token,
        roles: dto.roles,
        expires: dto.expires,
        ca_pins: dto.ca_pins,
    })
}

#[derive(Debug, DeJson)]
struct ProvisionTokenDto {
    metadata: ProvisionTokenMetaDto,
    spec: ProvisionTokenSpecDto,
}

#[derive(Debug, DeJson)]
struct ProvisionTokenMetaDto {
    /// The token's name (its identifier) — the "Token" column of `tctl tokens ls`.
    name: String,
    #[nserde(default)]
    expires: String,
    #[nserde(default)]
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, DeJson)]
struct ProvisionTokenSpecDto {
    /// The token's type(s) (`Bot`, `Node`, …) — the "Type" column.
    #[nserde(default)]
    roles: Vec<String>,
}

#[derive(Debug, DeJson)]
struct BotDto {
    metadata: BotMetaDto,
    spec: BotSpecDto,
    #[nserde(default)]
    status: BotStatusDto,
}

#[derive(Debug, DeJson)]
struct BotMetaDto {
    name: String,
    #[nserde(default)]
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Default, DeJson)]
struct BotSpecDto {
    #[nserde(default)]
    roles: Vec<String>,
    #[nserde(default)]
    max_session_ttl: TtlDto,
}

#[derive(Debug, Default, DeJson)]
struct TtlDto {
    #[nserde(default)]
    seconds: u64,
}

#[derive(Debug, Default, DeJson)]
struct BotStatusDto {
    #[nserde(default)]
    user_name: String,
}

fn parse_bots(stdout: &str) -> Result<Vec<Bot>, DomainError> {
    let dtos: Vec<BotDto> = DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
        detail: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(dtos.len());
    for d in dtos {
        out.push(Bot {
            name: ResourceName::try_from(d.metadata.name)?,
            roles: d.spec.roles,
            user: d.status.user_name,
            max_ttl_secs: d.spec.max_session_ttl.seconds,
            labels: sorted_labels(d.metadata.labels),
        });
    }
    Ok(out)
}

#[derive(Debug, DeJson)]
struct InstanceDto {
    metadata: InstanceMetaDto,
    spec: InstanceSpecDto,
}

#[derive(Debug, DeJson)]
struct InstanceMetaDto {
    name: String,
}

#[derive(Debug, Default, DeJson)]
struct InstanceSpecDto {
    #[nserde(default)]
    version: String,
    #[nserde(default)]
    services: Vec<String>,
    #[nserde(default)]
    hostname: String,
    #[nserde(default)]
    last_seen: String,
}

fn parse_instances(stdout: &str) -> Result<Vec<Instance>, DomainError> {
    let dtos: Vec<InstanceDto> =
        DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
            detail: e.to_string(),
        })?;
    Ok(dtos
        .into_iter()
        .map(|d| Instance {
            server_id: d.metadata.name,
            hostname: d.spec.hostname,
            version: d.spec.version,
            services: d.spec.services,
            last_seen: d.spec.last_seen,
        })
        .collect())
}

fn parse_invite(user: &str, stdout: &str) -> Result<InviteLink, DomainError> {
    // The setup URL is the first http(s) token in the output; it embeds the
    // one-time secret. On failure, surface only a generic message — the output
    // may contain the URL/secret and must not appear in the error detail.
    stdout
        .split_whitespace()
        .find(|w| w.starts_with("https://") || w.starts_with("http://"))
        .map(|u| InviteLink {
            user: user.to_owned(),
            url: u.to_owned(),
        })
        .ok_or(DomainError::Parse {
            detail: "could not find setup URL in output".to_owned(),
        })
}

fn parse_tokens(stdout: &str) -> Result<Vec<ProvisionToken>, DomainError> {
    let dtos: Vec<ProvisionTokenDto> =
        DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
            detail: e.to_string(),
        })?;
    Ok(dtos
        .into_iter()
        .map(|d| ProvisionToken {
            name: d.metadata.name,
            types: d.spec.roles,
            labels: sorted_labels(d.metadata.labels),
            expires: d.metadata.expires,
        })
        .collect())
}

fn parse_users(stdout: &str) -> Result<Vec<AdminUser>, DomainError> {
    let dtos: Vec<UserDto> = DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
        detail: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(dtos.len());
    for dto in dtos {
        out.push(AdminUser {
            name: ResourceName::try_from(dto.metadata.name)?,
            roles: dto.spec.roles,
            labels: sorted_labels(dto.metadata.labels),
        });
    }
    Ok(out)
}

fn parse_roles(stdout: &str) -> Result<Vec<AdminRole>, DomainError> {
    let dtos: Vec<RoleDto> = DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
        detail: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(dtos.len());
    for dto in dtos {
        out.push(AdminRole {
            name: ResourceName::try_from(dto.metadata.name)?,
            description: dto.metadata.description,
            labels: sorted_labels(dto.metadata.labels),
        });
    }
    Ok(out)
}

/// Fallback when `tctl` is absent: admin features are simply unavailable.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableAdmin;

impl AdminRepository for UnavailableAdmin {
    fn list_users(&self) -> Result<Vec<AdminUser>, DomainError> {
        Err(DomainError::BinaryNotFound)
    }
    fn list_roles(&self) -> Result<Vec<AdminRole>, DomainError> {
        Err(DomainError::BinaryNotFound)
    }
    fn generate_token(&self, _token_type: &str) -> Result<GeneratedToken, DomainError> {
        Err(DomainError::BinaryNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_users_fixture() {
        let users = parse_users(include_str!("../tests/fixtures/users.json")).unwrap();
        assert_eq!(users.len(), 2);
        assert!(!users[0].roles.is_empty());
    }

    #[test]
    fn parses_roles_fixture() {
        let roles = parse_roles(include_str!("../tests/fixtures/roles.json")).unwrap();
        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0].name.as_str(), "access");
    }

    #[test]
    fn parses_provision_tokens() {
        // Synthetic `tctl tokens ls --format=json` shape: name/type/labels/expiry.
        let json = r#"[
            {"metadata":{"name":"tbot-ci","expires":"2026-07-01T00:00:00Z",
              "labels":{"team":"ci","teleport.dev/origin":"kubernetes"}},
             "spec":{"roles":["Bot"]}},
            {"metadata":{"name":"node-join"},
             "spec":{"roles":["Kube","App"]}}
        ]"#;
        let toks = parse_tokens(json).unwrap();
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0].name, "tbot-ci");
        assert_eq!(toks[0].types, vec!["Bot"]);
        assert_eq!(
            toks[0].labels,
            vec![
                ("team".to_owned(), "ci".to_owned()),
                ("teleport.dev/origin".to_owned(), "kubernetes".to_owned()),
            ]
        );
        assert_eq!(toks[1].types, vec!["Kube", "App"]);
        assert_eq!(toks[1].expires, ""); // absent → empty (rendered "never")
    }

    #[test]
    fn parses_bots() {
        // Shape from a real `tctl bots ls --format=json`.
        let json = r#"[
            {"kind":"bot","version":"v1","metadata":{"name":"operator"},
             "spec":{"roles":["operator"],"max_session_ttl":{"seconds":108000}},
             "status":{"user_name":"bot-operator","role_name":"bot-operator"}},
            {"kind":"bot","version":"v1",
             "metadata":{"name":"ci","labels":{"teleport.dev/origin":"kubernetes"}},
             "spec":{"roles":["lab"],"max_session_ttl":{"seconds":43200}},
             "status":{"user_name":"bot-ci"}}
        ]"#;
        let bots = parse_bots(json).unwrap();
        assert_eq!(bots.len(), 2);
        assert_eq!(bots[0].name.as_str(), "operator");
        assert_eq!(bots[0].user, "bot-operator");
        assert_eq!(bots[0].max_ttl_secs, 108_000);
        assert_eq!(bots[1].roles, vec!["lab"]);
        assert_eq!(bots[1].labels.len(), 1);
    }

    #[test]
    fn parses_instances() {
        // Shape from a real `tctl inventory ls --format=json`.
        let json = r#"[
            {"kind":"instance","version":"v1",
             "metadata":{"name":"02833375-112a-46cb-a3f6-0f188a9b785b","expires":"2026-06-29T16:48:30Z"},
             "spec":{"version":"v18.7.3","services":["Node","App"],
                     "hostname":"agent-01","last_seen":"2026-06-29T16:28:30Z"}}
        ]"#;
        let inst = parse_instances(json).unwrap();
        assert_eq!(inst.len(), 1);
        assert_eq!(inst[0].hostname, "agent-01");
        assert_eq!(inst[0].version, "v18.7.3");
        assert_eq!(inst[0].services, vec!["Node", "App"]);
    }

    #[test]
    fn extracts_invite_url() {
        let out = "User \"bob\" has been created but requires a password.\n\
                   Share this URL with the user to complete setup, valid for 1h:\n\
                   https://proxy.example.com:443/web/invite/abcdef123456\n\n\
                   NOTE: make sure the proxy is reachable.\n";
        let inv = parse_invite("bob", out).unwrap();
        assert_eq!(inv.user, "bob");
        assert_eq!(
            inv.url,
            "https://proxy.example.com:443/web/invite/abcdef123456"
        );
        // No URL → generic error, never echoing the output.
        assert!(parse_invite("bob", "nope, failed").is_err());
    }

    #[test]
    fn parses_generated_token() {
        // Synthetic shape of `tctl tokens add --format=json` (fake token value).
        let json = r#"{"token":"deadbeef","roles":["Node"],
            "expires":"2026-06-29T00:02:06Z","ca_pins":["sha256:abc"]}"#;
        let t = parse_token(json).unwrap();
        assert_eq!(t.token, "deadbeef");
        assert_eq!(t.roles, vec!["Node"]);
        assert_eq!(t.ca_pins.len(), 1);
    }
}
