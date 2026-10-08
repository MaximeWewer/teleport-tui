//! `tsh` adapter: runs the CLI, parses `--format=json`, maps DTOs to domain
//! entities (anti-corruption layer). A schema change in Teleport only touches
//! the DTOs/mapping here, never the domain.

// nanoserde's derived `DeJson` impls expand to `?`-style blocks clippy flags;
// suppress that pedantic noise for this DTO-heavy module only.
#![allow(clippy::question_mark)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use domain::cluster::ClusterContext;
use domain::error::DomainError;
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
/// Not for secret-bearing output (token/invite) - those hold the raw outcome in
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

/// Seconds since the Unix epoch for an RFC 3339 timestamp
/// (`YYYY-MM-DDThh:mm:ss[.frac](Z|±hh:mm)`). Fractional seconds are ignored; a
/// missing or unreadable zone suffix reads as UTC. `None` on a malformed date.
/// Uses Howard Hinnant's `days_from_civil` so no date-library dependency is
/// pulled into this minimal-deps crate.
pub(crate) fn epoch_secs(s: &str) -> Option<i64> {
    let field = |a: usize, z: usize| s.get(a..z)?.parse::<i64>().ok();
    let (year, month, day) = (field(0, 4)?, field(5, 7)?, field(8, 10)?);
    let (hour, min, sec) = (field(11, 13)?, field(14, 16)?, field(17, 19)?);
    // days_from_civil (Howard Hinnant): civil date -> days since 1970-01-01.
    let years = year - i64::from(month <= 2);
    let era = (if years >= 0 { years } else { years - 399 }) / 400;
    let year_of_era = years - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3600 + min * 60 + sec - utc_offset_secs(s.get(19..)?))
}

/// The UTC offset of an RFC 3339 zone tail (after the seconds, fraction
/// allowed): `+02:00` is 7200, `Z` or anything unreadable is 0.
fn utc_offset_secs(tail: &str) -> i64 {
    let zone = tail.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    let sign = match zone.get(..1) {
        Some("+") => 1,
        Some("-") => -1,
        _ => return 0,
    };
    let part = |a: usize, z: usize| zone.get(a..z).and_then(|v| v.parse::<i64>().ok());
    match (part(1, 3), part(4, 6)) {
        (Some(h), Some(m)) => sign * (h * 3600 + m * 60),
        _ => 0,
    }
}

/// Owned argv from string literals: `args(&["mfa", "ls"])`.
pub(crate) fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

/// Deserialize `--format=json` output, mapping a parser error to
/// `DomainError::Parse` with the parser's message. Not for secret-bearing
/// output: a parser message may quote its input.
pub(crate) fn parse_json<T: DeJson>(stdout: &str) -> Result<T, DomainError> {
    DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
        detail: e.to_string(),
    })
}

/// Resource metadata shared by most Teleport objects (`metadata.name` +
/// optional labels). Undeclared fields are ignored by nanoserde. Private to
/// `tsh` (nanoserde's derive rejects `pub(crate)`); `tctl` keeps its own copy.
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

/// The `tsh` binary plus the runner that spawns it: the state every `tsh`
/// adapter shares.
#[derive(Debug, Clone)]
struct TshCli<R: CommandRunner> {
    runner: R,
    tsh: PathBuf,
}

impl<R: CommandRunner> TshCli<R> {
    /// Run `tsh <args>` and return stdout (see [`run_cli`]).
    fn run(&self, args: Vec<String>) -> Result<String, DomainError> {
        run_cli(&self.runner, &self.tsh, args, "TSH_SPAWN_FAILED")
    }

    /// Common listing prelude: reject an offline cluster, then run
    /// `tsh <verb> ls --format=json`, adding `-c <cluster>` when `scoped`.
    /// Cluster names come from a validated value object cross-checked against
    /// the real topology, so they are safe to pass as `-c`.
    ///
    /// Unscoped is for `tsh` subcommands that reject `-c`: `recordings ls` and
    /// `sessions ls` are audit / session commands scoped to the *current
    /// proxy*, not a named cluster (passing `-c` makes tsh error `unknown short
    /// flag '-c'`, which surfaced as an empty list). The offline guard on the
    /// current cluster still applies.
    fn ls(&self, verb: &[&str], ctx: &ClusterContext, scoped: bool) -> Result<String, DomainError> {
        if !ctx.is_online() {
            return Err(DomainError::ClusterOffline {
                cluster: ctx.name.to_string(),
            });
        }
        let mut argv = args(verb);
        argv.extend(args(&["ls", "--format=json"]));
        if scoped {
            argv.push("-c".to_owned());
            argv.push(ctx.name.to_string());
        }
        self.run(argv)
    }
}

/// Declare a `tsh` adapter: a public struct wrapping [`TshCli`] with the
/// `new(runner, tsh)` constructor the composition root calls.
macro_rules! tsh_adapter {
    ($name:ident) => {
        #[derive(Debug, Clone)]
        pub struct $name<R: $crate::process::CommandRunner> {
            cli: $crate::tsh::TshCli<R>,
        }

        impl<R: $crate::process::CommandRunner> $name<R> {
            pub const fn new(runner: R, tsh: ::std::path::PathBuf) -> Self {
                Self {
                    cli: $crate::tsh::TshCli { runner, tsh },
                }
            }
        }
    };
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
    use domain::cluster::{ClusterKind, ClusterStatus};
    use domain::value::ClusterName;
    #[test]
    fn epoch_secs_honours_the_utc_offset() {
        assert_eq!(epoch_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(epoch_secs("1970-01-01T02:00:00+02:00"), Some(0));
        assert_eq!(epoch_secs("1969-12-31T22:30:00-01:30"), Some(0));
        assert_eq!(
            epoch_secs("2026-06-29T16:30:26.000000000Z"),
            Some(1_782_750_626)
        );
        assert_eq!(epoch_secs("not a date"), None);
    }

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

    /// Records the argv of the last command and succeeds with `[]`.
    #[derive(Debug, Default)]
    struct ArgvRunner(std::sync::Mutex<Vec<String>>);
    impl CommandRunner for ArgvRunner {
        fn run(&self, req: &CommandRequest) -> std::io::Result<crate::process::CommandOutcome> {
            *self.0.lock().unwrap() = req.args.clone();
            Ok(crate::process::CommandOutcome {
                status: Some(0),
                stdout: "[]".to_owned(),
                stderr: String::new(),
            })
        }
    }

    fn ctx(status: ClusterStatus) -> ClusterContext {
        ClusterContext {
            name: ClusterName::try_from("leaf1").unwrap(),
            kind: ClusterKind::Leaf,
            status,
        }
    }

    #[test]
    fn ls_adds_cluster_flag_only_when_scoped() {
        let cli = TshCli {
            runner: ArgvRunner::default(),
            tsh: "tsh".into(),
        };
        cli.ls(&["db"], &ctx(ClusterStatus::Online), true).unwrap();
        assert_eq!(
            *cli.runner.0.lock().unwrap(),
            args(&["db", "ls", "--format=json", "-c", "leaf1"])
        );
        cli.ls(&["sessions"], &ctx(ClusterStatus::Online), false)
            .unwrap();
        assert_eq!(
            *cli.runner.0.lock().unwrap(),
            args(&["sessions", "ls", "--format=json"])
        );
        assert!(matches!(
            cli.ls(&[], &ctx(ClusterStatus::Offline), true),
            Err(DomainError::ClusterOffline { .. })
        ));
    }
}
