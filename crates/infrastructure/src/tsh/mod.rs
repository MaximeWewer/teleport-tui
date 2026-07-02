//! `tsh` adapter: runs the CLI, parses `--format=json`, maps DTOs to domain
//! entities (anti-corruption layer). A schema change in Teleport only touches
//! the DTOs/mapping here, never the domain.

// nanoserde's derived `DeJson` impls expand to `?`-style blocks clippy flags;
// suppress that pedantic noise for this DTO-heavy module only.
#![allow(clippy::question_mark, clippy::wildcard_imports)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use domain::cluster::{ClusterContext, ClusterKind, ClusterStatus, ClusterTopology};
use domain::error::DomainError;
use domain::mfa::MfaDevice;
use domain::node::SshNode;
use domain::port::{
    AppRepository, AuthGateway, ClusterRepository, DatabaseRepository, KubeRepository,
    NodeRepository, RecordingRepository, RequestRepository, SessionRepository,
};
use domain::profile::Profile;
use domain::recording::SessionRecording;
use domain::request::{AccessRequest, RequestState};
use domain::resource::{App, Database, KubeCluster};
use domain::session::ActiveSession;
use domain::value::{ClusterName, Hostname, RequestId, ResourceName};
use nanoserde::DeJson;

use crate::process::{CommandRequest, CommandRunner};
use crate::redact::redact_message;

/// Map a failed CLI invocation to a domain error, recognising auth failures.
pub(crate) fn classify_failure(stderr: &str) -> DomainError {
    let s = stderr.to_lowercase();
    if s.contains("not logged in") || s.contains("please login") || s.contains("no profile") {
        DomainError::NotAuthenticated
    } else if s.contains("expired") {
        DomainError::CertExpired
    } else {
        DomainError::Backend {
            code: "TSH_EXEC_FAILED",
            // stderr is free text that may echo a supplied secret → mask, don't
            // just strip control chars.
            detail: redact_message(stderr.trim()),
        }
    }
}

/// Run a `tsh`/`tctl` command and return its stdout, folding failures into the
/// domain vocabulary: a spawn error becomes `Backend { code: spawn_code, … }`, a
/// non-zero exit is routed through [`classify_failure`] (auth/expired/backend).
/// Shared by both adapters so the spawn→classify boilerplate lives in one place.
/// Not for secret-bearing output (token/invite) — those hold the raw outcome in
/// zeroizing storage instead.
pub(crate) fn run_cli(
    runner: &impl CommandRunner,

    bin: &Path,

    args: Vec<String>,

    spawn_code: &'static str,
) -> Result<String, DomainError> {
    let req = CommandRequest::new(bin.to_path_buf(), args);
    let outcome = runner.run(&req).map_err(|e| DomainError::Backend {
        code: spawn_code,
        detail: e.to_string(),
    })?;
    if outcome.succeeded() {
        Ok(outcome.stdout)
    } else {
        Err(classify_failure(&outcome.stderr))
    }
}

fn run_json(
    runner: &impl CommandRunner,

    tsh: &Path,

    args: Vec<String>,
) -> Result<String, DomainError> {
    run_cli(runner, tsh, args, "TSH_SPAWN_FAILED")
}

#[derive(Debug, DeJson)]
struct MetaDto {
    name: String,
    #[nserde(default)]
    labels: Option<HashMap<String, String>>,
}

pub(crate) fn sorted_labels(labels: Option<HashMap<String, String>>) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = labels.unwrap_or_default().into_iter().collect();
    v.sort();
    v
}

/// Common scoped-listing prelude: reject offline cluster, run `tsh <verb> ls
/// --format=json -c <cluster>`.
fn run_scoped_ls(
    runner: &impl CommandRunner,

    tsh: &Path,

    verb: &[&str],

    ctx: &ClusterContext,
) -> Result<String, DomainError> {
    if !ctx.is_online() {
        return Err(DomainError::ClusterOffline {
            cluster: ctx.name.to_string(),
        });
    }
    let mut args: Vec<String> = verb.iter().map(|s| (*s).to_owned()).collect();
    args.push("ls".to_owned());
    args.push("--format=json".to_owned());
    args.push("-c".to_owned());
    args.push(ctx.name.to_string());
    run_json(runner, tsh, args)
}

/// Like [`run_scoped_ls`] but WITHOUT the `-c <cluster>` flag, for `tsh`
/// subcommands that reject it: `recordings ls` and `sessions ls` are audit /
/// session commands scoped to the *current proxy*, not a named cluster (passing
/// `-c` makes tsh error `unknown short flag '-c'`, which surfaced as an empty
/// list). The offline guard on the current cluster still applies.
fn run_unscoped_ls(
    runner: &impl CommandRunner,

    tsh: &Path,

    verb: &[&str],

    ctx: &ClusterContext,
) -> Result<String, DomainError> {
    if !ctx.is_online() {
        return Err(DomainError::ClusterOffline {
            cluster: ctx.name.to_string(),
        });
    }
    let mut args: Vec<String> = verb.iter().map(|s| (*s).to_owned()).collect();
    args.push("ls".to_owned());
    args.push("--format=json".to_owned());
    run_json(runner, tsh, args)
}

mod app;
mod auth;
mod cluster;
mod database;
mod kube;
mod node;
mod recording;
mod request;
mod session;

pub use app::TshAppRepository;
pub use auth::TshAuthGateway;
pub use cluster::TshClusterRepository;
pub use database::TshDatabaseRepository;
pub use kube::TshKubeRepository;
pub use node::TshNodeRepository;
pub use recording::TshRecordingRepository;
pub use request::TshRequestRepository;
pub use session::TshSessionRepository;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_not_logged_in() {
        assert!(matches!(
            classify_failure("ERROR: Not logged in"),
            DomainError::NotAuthenticated
        ));
        assert!(matches!(
            classify_failure("certificate has expired"),
            DomainError::CertExpired
        ));
    }
}
