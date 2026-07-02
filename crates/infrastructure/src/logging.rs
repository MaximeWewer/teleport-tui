//! Structured error export as JSON Lines (NDJSON), one object per line, for
//! `jq`/grep analysis. Best-effort: a logging failure never breaks the UI.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use domain::error::ReportableError;
use nanoserde::SerJson;

use crate::platform;
use crate::redact::{redact_command, redact_message};

/// One exported error line. Field names are the analysis schema.
#[derive(Debug, Clone, SerJson)]
pub struct ErrorRecord {
    pub ts_ms: u64,
    pub level: String,
    pub code: String,
    pub category: String,
    pub layer: String,
    pub msg: String,
    pub cause: Option<String>,
    pub command: Option<String>,
    pub run_id: String,
}

impl ErrorRecord {
    /// Build a redacted record from any reportable error.
    pub fn build(
        layer: &str,
        level: &str,
        err: &impl ReportableError,
        command: Option<&str>,
        run_id: &str,
    ) -> Self {
        Self {
            ts_ms: now_ms(),
            level: level.to_owned(),
            code: err.code().to_owned(),
            category: err.category().as_str().to_owned(),
            layer: layer.to_owned(),
            msg: redact_message(&err.message()),
            cause: err.cause().map(|c| redact_message(&c)),
            command: command.map(redact_command),
            run_id: run_id.to_owned(),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Appends [`ErrorRecord`]s to an NDJSON file.
#[derive(Debug, Clone)]
pub struct NdjsonLogger {
    path: PathBuf,
}

impl NdjsonLogger {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Default location under the per-OS state directory.
    #[must_use]
    pub fn at_default_path() -> Self {
        Self::new(platform::error_log_path())
    }

    /// Append one record. Returns `false` on I/O failure (never panics, never
    /// blocks the UI). Creates parent dirs best-effort.
    #[must_use]
    pub fn append(&self, record: &ErrorRecord) -> bool {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
            platform::restrict_dir(parent);
        }
        let line = format!("{}\n", record.serialize_json());
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        // The log may contain (redacted) operational detail; keep it owner-only
        // on Unix so a shared-home box doesn't expose it world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&self.path)
            .and_then(|mut f| f.write_all(line.as_bytes()))
            .is_ok()
    }

    /// Convenience: build + append in one call.
    pub fn report(
        &self,
        layer: &str,
        err: &impl ReportableError,
        command: Option<&str>,
        run_id: &str,
    ) -> bool {
        let record = ErrorRecord::build(layer, "error", err, command, run_id);
        self.append(&record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::error::DomainError;

    #[test]
    fn record_has_stable_code_and_is_redacted() {
        let err = DomainError::Backend {
            code: "TSH_EXEC_FAILED",
            detail: "boom\x1b[0m".to_owned(),
        };
        let rec = ErrorRecord::build(
            "infrastructure",
            "error",
            &err,
            Some("tsh login --token s3cr3t"),
            "run-1",
        );
        assert_eq!(rec.code, "TSH_EXEC_FAILED");
        assert_eq!(rec.category, "network");
        assert!(!rec.msg.contains('\x1b'));
        assert_eq!(rec.command.as_deref(), Some("tsh login --token ***"));
        // Serializes to a single JSON object.
        let json = rec.serialize_json();
        assert!(json.starts_with('{') && json.contains("\"code\":\"TSH_EXEC_FAILED\""));
    }
}
