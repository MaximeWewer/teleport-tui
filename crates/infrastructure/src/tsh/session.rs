//! `tsh sessions ls` → active sessions to join. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`TshCli`, `tsh_adapter!`, `parse_json`, `sorted_labels`,
//! `MetaDto`) come from `super`.

#![allow(clippy::question_mark)]

use domain::cluster::ClusterContext;
use domain::error::DomainError;
use domain::port::SessionRepository;
use domain::session::ActiveSession;
use nanoserde::DeJson;

use super::parse_json;
use crate::process::CommandRunner;

tsh_adapter!(TshSessionRepository);

impl<R: CommandRunner> SessionRepository for TshSessionRepository<R> {
    fn list_sessions(&self, ctx: &ClusterContext) -> Result<Vec<ActiveSession>, DomainError> {
        let stdout = self.cli.ls(&["sessions"], ctx, false)?;
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
    let dtos: Vec<SessionTrackerDto> = parse_json(stdout)?;
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

    #[test]
    fn parses_sessions_fixture() {
        let sess = parse_sessions(include_str!("../../tests/fixtures/sessions.json")).unwrap();
        // The tracker without a session id can't be joined: dropped.
        assert_eq!(sess.len(), 2);
        assert_eq!(
            sess[0],
            ActiveSession {
                id: "cc0bb7fc-1111-2222-3333-444444444444".to_owned(),
                kind: "ssh".to_owned(),
                host: "node-01".to_owned(),
                login: "admin".to_owned(),
                started_by: "alice".to_owned(),
                created: "2026-06-30T05:50:30Z".to_owned(),
            }
        );
        // A kube session has no target host / login: they default to empty.
        assert_eq!(sess[1].kind, "k8s");
        assert_eq!(sess[1].host, "");
        assert_eq!(sess[1].login, "");
        assert_eq!(sess[1].started_by, "bob@example.com");
    }

    #[test]
    fn empty_list_and_malformed_output() {
        assert!(parse_sessions("[]").unwrap().is_empty());
        assert!(matches!(
            parse_sessions("not json"),
            Err(DomainError::Parse { .. })
        ));
    }
}
