//! `tsh sessions ls` → active sessions to join. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`run_json`, `run_scoped_ls`,
//! `classify_failure`, `sorted_labels`, `MetaDto`) and imports come via `super::*`.

#![allow(clippy::question_mark, clippy::wildcard_imports)]
use super::*;

#[derive(Debug, Clone)]
pub struct TshSessionRepository<R: CommandRunner> {
    runner: R,
    tsh: PathBuf,
}

impl<R: CommandRunner> TshSessionRepository<R> {
    pub fn new(runner: R, tsh: PathBuf) -> Self {
        Self { runner, tsh }
    }
}

impl<R: CommandRunner> SessionRepository for TshSessionRepository<R> {
    fn list_sessions(&self, ctx: &ClusterContext) -> Result<Vec<ActiveSession>, DomainError> {
        let stdout = run_unscoped_ls(&self.runner, &self.tsh, &["sessions"], ctx)?;
        parse_sessions(&stdout)
    }
}

#[derive(Debug, DeJson)]
struct SessionTrackerDto {
    spec: SessionSpecDto,
}

#[derive(Debug, Default, DeJson)]
struct SessionSpecDto {
    #[nserde(default)]
    session_id: String,
    #[nserde(default)]
    kind: String,
    #[nserde(default)]
    target_hostname: String,
    #[nserde(default)]
    login: String,
    #[nserde(default)]
    host_user: String,
    #[nserde(default)]
    created: String,
}

fn parse_sessions(stdout: &str) -> Result<Vec<ActiveSession>, DomainError> {
    let dtos: Vec<SessionTrackerDto> =
        DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
            detail: e.to_string(),
        })?;
    Ok(dtos
        .into_iter()
        .filter(|d| !d.spec.session_id.is_empty())
        .map(|d| ActiveSession {
            id: d.spec.session_id,
            kind: d.spec.kind,
            host: d.spec.target_hostname,
            login: d.spec.login,
            started_by: d.spec.host_user,
            created: d.spec.created,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_active_sessions() {
        // Shape from a real `tsh sessions ls --format=json` (session_tracker).
        let json = r#"[
            {"kind":"session_tracker","version":"v1",
             "metadata":{"name":"cc0bb7fc"},
             "spec":{"session_id":"cc0bb7fc","kind":"ssh","state":1,
                     "target_hostname":"node-01","cluster_name":"root",
                     "login":"admin","host_user":"alice",
                     "created":"2026-06-30T05:50:30Z",
                     "host_roles":[{"name":"ssp","version":"v7"}],
                     "participants":[{"user":"alice","mode":"peer"}]}}
        ]"#;
        let sess = parse_sessions(json).unwrap();
        assert_eq!(sess.len(), 1);
        assert_eq!(sess[0].id, "cc0bb7fc");
        assert_eq!(sess[0].kind, "ssh");
        assert_eq!(sess[0].host, "node-01");
        assert_eq!(sess[0].login, "admin");
        assert_eq!(sess[0].started_by, "alice");
    }
}
