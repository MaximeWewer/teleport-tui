//! `tsh recordings ls` → session recordings (audit stream). DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`run_json`, `run_scoped_ls`,
//! `classify_failure`, `sorted_labels`, `MetaDto`) and imports come via `super::*`.

#![allow(clippy::question_mark, clippy::wildcard_imports)]
use super::*;

#[derive(Debug, Clone)]
pub struct TshRecordingRepository<R: CommandRunner> {
    runner: R,
    tsh: PathBuf,
}

impl<R: CommandRunner> TshRecordingRepository<R> {
    pub fn new(runner: R, tsh: PathBuf) -> Self {
        Self { runner, tsh }
    }
}

impl<R: CommandRunner> RecordingRepository for TshRecordingRepository<R> {
    fn list_recordings(&self, ctx: &ClusterContext) -> Result<Vec<SessionRecording>, DomainError> {
        let stdout = run_unscoped_ls(&self.runner, &self.tsh, &["recordings"], ctx)?;
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
    /// The `session.end` event timestamp — the session's end, used with
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
    let dtos: Vec<RecordingDto> =
        DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
            detail: e.to_string(),
        })?;
    // `tsh recordings ls` returns a raw audit-event stream. Keep only the
    // `session.end` events (a completed, playable SSH/kube recording, keyed by
    // `sid`); this drops the streaming `app.session.chunk` events — which are the
    // ones that carry secret `user_traits` (a JWT) — so nothing secret is shown.
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

/// Seconds-since-epoch for an RFC 3339 UTC timestamp (`YYYY-MM-DDThh:mm:ss…Z`),
/// using only the leading `…ss` — fractional seconds and the zone suffix are
/// ignored (Teleport always emits `Z`). Returns `None` on a malformed prefix.
/// Uses Howard Hinnant's `days_from_civil` so no date-library dependency is
/// pulled into this minimal-deps crate.
fn epoch_secs(s: &str) -> Option<i64> {
    let field = |a: usize, z: usize| s.get(a..z)?.parse::<i64>().ok();
    let (year, month, day) = (field(0, 4)?, field(5, 7)?, field(8, 10)?);
    let (hour, min, sec) = (field(11, 13)?, field(14, 16)?, field(17, 19)?);
    // days_from_civil (Howard Hinnant): civil date → days since 1970-01-01.
    let years = year - i64::from(month <= 2);
    let era = (if years >= 0 { years } else { years - 399 }) / 400;
    let year_of_era = years - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3600 + min * 60 + sec)
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
        // and still populate `sid` — the id `tsh play` needs.
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
