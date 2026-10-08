//! `tsh recordings ls` → session recordings (audit stream). DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`TshCli`, `tsh_adapter!`, `parse_json`, `sorted_labels`,
//! `MetaDto`) come from `super`.

#![allow(clippy::question_mark)]

use domain::cluster::ClusterContext;
use domain::error::DomainError;
use domain::port::RecordingRepository;
use domain::recording::SessionRecording;
use nanoserde::DeJson;

use super::{epoch_secs, parse_json};
use crate::process::CommandRunner;

tsh_adapter!(TshRecordingRepository);

impl<R: CommandRunner> RecordingRepository for TshRecordingRepository<R> {
    fn list_recordings(&self, ctx: &ClusterContext) -> Result<Vec<SessionRecording>, DomainError> {
        let stdout = self.cli.ls(&["recordings"], ctx, false)?;
        parse_recordings(&stdout)
    }
}

#[derive(Debug, DeJson)]
struct RecordingDto {
    // Only non-secret display fields are declared; `user_traits` (which can hold
    // a JWT for some event types) is deliberately NOT declared, so nanoserde
    // ignores it and it never enters memory.
    #[nserde(default)]
    event: String,
    #[nserde(default)]
    sid: String,
    #[nserde(default)]
    session_start: String,
    /// The `session.end` event timestamp - the session's end, used with
    /// `session_start` to compute a display duration.
    #[nserde(default)]
    time: String,
    #[nserde(default)]
    user: String,
    #[nserde(default)]
    server_hostname: String,
    #[nserde(default)]
    proto: String,
}

fn parse_recordings(stdout: &str) -> Result<Vec<SessionRecording>, DomainError> {
    let dtos: Vec<RecordingDto> = parse_json(stdout)?;
    // `tsh recordings ls` returns a raw audit-event stream. Keep only the
    // `session.end` events (a completed, playable SSH/kube recording, keyed by
    // `sid`); this drops the streaming `app.session.chunk` events - which are the
    // ones that carry secret `user_traits` (a JWT) - so nothing secret is shown.
    Ok(dtos
        .into_iter()
        .filter(|d| d.event == "session.end" && !d.sid.is_empty())
        .map(|d| {
            let duration = match (epoch_secs(&d.session_start), epoch_secs(&d.time)) {
                (Some(a), Some(b)) if b >= a => fmt_duration(b - a),
                _ => String::new(),
            };
            SessionRecording {
                sid: d.sid,
                started: d.session_start,
                duration,
                user: d.user,
                server: d.server_hostname,
                proto: d.proto,
            }
        })
        .collect())
}

/// Compact human duration: `45s`, `5m29s`, `2h04m`.
fn fmt_duration(secs: i64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_recordings_keeps_completed_drops_chunks() {
        // session.end (kept) + an app.session.chunk carrying a secret jwt (dropped,
        // and its user_traits is never even declared).
        let json = r#"[
            {"event":"session.end","sid":"18c9d1ec","user":"alice","login":"admin",
             "proto":"ssh","server_hostname":"node-01",
             "session_start":"2026-06-29T16:24:57Z","time":"2026-06-29T16:30:26Z",
             "user_traits":{"hostnames":["x"]}},
            {"event":"app.session.chunk","sid":"44787843","user":"alice","proto":"https",
             "user_traits":{"jwt":["eyJhbGSECRET"]}}
        ]"#;
        let recs = parse_recordings(json).unwrap();
        assert_eq!(recs.len(), 1); // chunk (not a session.end event) dropped
        assert_eq!(recs[0].sid, "18c9d1ec");
        assert_eq!(recs[0].server, "node-01");
        assert_eq!(recs[0].proto, "ssh");
        assert_eq!(recs[0].duration, "5m29s"); // 16:24:57 → 16:30:26
        // The secret never appears anywhere in the parsed output.
        assert!(!format!("{recs:?}").contains("SECRET"));
    }
    #[test]
    fn parses_recordings_real_event_shape() {
        // A `session.end` event as tsh actually emits it: a dotted key
        // (`addr.remote`), nested objects/arrays (server_labels, user_roles,
        // user_traits, participants). nanoserde must skip all undeclared fields
        // and still populate `sid` - the id `tsh play` needs.
        let json = r#"[
            {"ei":0,"event":"session.end","uid":"0000","code":"T2004I",
             "time":"2026-06-29T16:30:26.000Z","cluster_name":"root.example",
             "user":"alice","login":"root","user_kind":1,
             "sid":"18c9d1ec-0000-4000-8000-000000000000","private_key_policy":"none",
             "addr.remote":"10.0.0.1:54282","proto":"ssh","namespace":"default",
             "server_id":"srv0","server_hostname":"node-01",
             "server_labels":{"arch":"x86_64","group":"vm","teleport_version":"v18.9.1"},
             "user_roles":["access","editor","reviewer"],
             "user_traits":{"logins":["root"],"jwt":["eyJhbGSECRET"]},
             "participants":["alice"],
             "session_start":"2026-06-29T16:24:57.000000000Z"}
        ]"#;
        let recs = parse_recordings(json).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].sid, "18c9d1ec-0000-4000-8000-000000000000");
        assert_eq!(recs[0].server, "node-01");
        assert_eq!(recs[0].user, "alice");
        assert_eq!(recs[0].proto, "ssh");
        assert_eq!(recs[0].duration, "5m29s"); // 16:24:57 → 16:30:26
        assert!(!format!("{recs:?}").contains("SECRET"));
    }
}
