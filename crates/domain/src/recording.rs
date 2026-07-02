//! Recorded sessions (`tsh recordings ls`).
//!
//! The CLI output is a stream of audit events; some event types embed secrets in
//! `user_traits` (e.g. a JWT). We keep **only non-secret display fields** and
//! never declare/read `user_traits`, so a secret cannot leak into the listing.

use crate::resource::Resource;

/// One recorded session, identified by `sid` (the id passed to `tsh play`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecording {
    pub sid: String,
    pub started: String,
    /// Human-readable playback length (e.g. `5m29s`), computed from the session's
    /// start/end timestamps; empty when they can't be parsed.
    pub duration: String,
    pub user: String,
    pub server: String,
    pub proto: String,
}

impl Resource for SessionRecording {
    fn columns() -> &'static [&'static str] {
        &["STARTED", "DURATION", "USER", "SERVER", "PROTO"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.started.clone(),
            self.duration.clone(),
            self.user.clone(),
            self.server.clone(),
            self.proto.clone(),
        ]
    }
    fn matches(&self, needle: &str) -> bool {
        self.user.to_lowercase().contains(needle)
            || self.server.to_lowercase().contains(needle)
            || self.proto.to_lowercase().contains(needle)
            || self.sid.to_lowercase().contains(needle)
    }
}
