//! Optional user config (`config.toml`). Deliberately a tiny hand-rolled
//! flat `key = value` parser — no TOML dependency (attack-surface constraint).
//! Unknown keys are ignored; a missing/unreadable file yields defaults.

use std::path::{Path, PathBuf};

use crate::platform;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Config {
    /// Override path to the `tsh` binary.
    pub tsh_path: Option<PathBuf>,
    /// Override path to the `tctl` binary.
    pub tctl_path: Option<PathBuf>,
    /// Auto-refresh interval in seconds (`None`/0 disables).
    pub refresh_seconds: Option<u64>,
    /// Tools offered when opening a Kubernetes cluster (auto-proxy + `--exec`).
    /// `"shell"` opens a shell with `$KUBECONFIG` set; any other value is run
    /// via `--exec-cmd` (e.g. `k9s`). Defaults to `["shell", "k9s"]`.
    pub kube_tools: Vec<String>,
    /// Pre-filled Teleport proxy address for the login form (`tsh login --proxy`).
    pub proxy: Option<String>,
    /// Pre-filled Teleport user for the login form (`tsh login --user`).
    pub user: Option<String>,
    /// Pre-filled auth connector for the login form (`local`/`passwordless`/`sso`).
    pub auth: Option<String>,
    /// Pre-filled MFA mode for the login form (`otp`/`webauthn`/`platform`/…).
    pub mfa: Option<String>,
    /// Default SSH login. When set, connecting to a node uses it directly
    /// instead of prompting (`tsh ssh <login>@host`).
    pub default_login: Option<String>,
    /// Default Kubernetes user (`tsh proxy kube --as`). When set, skips the user picker.
    pub kube_user: Option<String>,
    /// Default database user (`tsh db connect --db-user`). When set, skips the prompt.
    pub db_user: Option<String>,
}

/// Default Kubernetes launchers when none are configured.
#[must_use]
pub fn default_kube_tools() -> Vec<String> {
    vec!["shell".to_owned(), "k9s".to_owned()]
}

impl Config {
    /// Load from the per-OS config path; defaults if absent/unreadable.
    #[must_use]
    pub fn load_default() -> Self {
        Self::load(&platform::config_path())
    }

    #[must_use]
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .map(|s| Self::parse(&s))
            .unwrap_or_default()
    }

    #[must_use]
    pub fn parse(contents: &str) -> Self {
        let mut cfg = Self::default();
        for raw in contents.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = unquote(value.trim());
            match key {
                "tsh_path" if !value.is_empty() => cfg.tsh_path = Some(PathBuf::from(value)),
                "tctl_path" if !value.is_empty() => cfg.tctl_path = Some(PathBuf::from(value)),
                "refresh_seconds" => cfg.refresh_seconds = value.parse().ok().filter(|n| *n > 0),
                "kube_tools" => {
                    cfg.kube_tools = value
                        .split(',')
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "proxy" if !value.is_empty() => cfg.proxy = Some(value.to_owned()),
                "user" if !value.is_empty() => cfg.user = Some(value.to_owned()),
                "auth" if !value.is_empty() => cfg.auth = Some(value.to_owned()),
                "mfa" if !value.is_empty() => cfg.mfa = Some(value.to_owned()),
                "default_login" if !value.is_empty() => {
                    cfg.default_login = Some(value.to_owned());
                }
                "kube_user" if !value.is_empty() => cfg.kube_user = Some(value.to_owned()),
                "db_user" if !value.is_empty() => cfg.db_user = Some(value.to_owned()),
                _ => {}
            }
        }
        cfg
    }
}

impl Config {
    /// Serialize to the flat `key = "value"` file format. Only set fields are
    /// written (absent keys fall back to defaults on load).
    #[must_use]
    pub fn to_file_string(&self) -> String {
        use std::fmt::Write;
        // Values are validated upstream (no control/quote chars), so a plain
        // double-quoted form round-trips through `unquote`.
        fn kv(s: &mut String, key: &str, val: &str) {
            let _ = writeln!(s, "{key} = \"{val}\"");
        }
        let mut s = String::from("# teleport-tui configuration (edited in-app)\n");
        if let Some(p) = &self.tsh_path {
            kv(&mut s, "tsh_path", &p.display().to_string());
        }
        if let Some(p) = &self.tctl_path {
            kv(&mut s, "tctl_path", &p.display().to_string());
        }
        if let Some(n) = self.refresh_seconds {
            let _ = writeln!(s, "refresh_seconds = {n}");
        }
        if !self.kube_tools.is_empty() {
            kv(&mut s, "kube_tools", &self.kube_tools.join(", "));
        }
        if let Some(v) = &self.proxy {
            kv(&mut s, "proxy", v);
        }
        if let Some(v) = &self.user {
            kv(&mut s, "user", v);
        }
        if let Some(v) = &self.auth {
            kv(&mut s, "auth", v);
        }
        if let Some(v) = &self.mfa {
            kv(&mut s, "mfa", v);
        }
        if let Some(v) = &self.default_login {
            kv(&mut s, "default_login", v);
        }
        if let Some(v) = &self.kube_user {
            kv(&mut s, "kube_user", v);
        }
        if let Some(v) = &self.db_user {
            kv(&mut s, "db_user", v);
        }
        s
    }

    /// Persist to `path`, creating the parent directory if needed.
    ///
    /// # Errors
    /// Returns any I/O error from creating the directory or writing the file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            platform::restrict_dir(dir);
        }
        std::fs::write(path, self.to_file_string())?;
        // Owner-only on Unix: the config may hold a default login/proxy.
        platform::restrict_file(path);
        Ok(())
    }
}

fn unquote(s: &str) -> &str {
    // Strip a matching pair of surrounding single/double quotes, index-free:
    // peel the first and last char and return the middle only when both are the
    // same quote character (needs ≥2 chars, so `next`/`next_back` both yield).
    let mut chars = s.chars();
    match (chars.next(), chars.next_back()) {
        (Some(first), Some(last)) if first == last && (first == '"' || first == '\'') => {
            chars.as_str()
        }
        _ => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_keys_and_ignores_unknown_and_comments() {
        let cfg = Config::parse(
            r#"
            # comment
            tsh_path = "/opt/tsh"
            tctl_path = '/opt/tctl'
            refresh_seconds = 30
            unknown = whatever
            "#,
        );
        assert_eq!(cfg.tsh_path, Some(PathBuf::from("/opt/tsh")));
        assert_eq!(cfg.tctl_path, Some(PathBuf::from("/opt/tctl")));
        assert_eq!(cfg.refresh_seconds, Some(30));
    }

    #[test]
    fn empty_or_zero_refresh_is_none() {
        let cfg = Config::parse("refresh_seconds = 0\n");
        assert_eq!(cfg.refresh_seconds, None);
        assert_eq!(Config::parse("").tsh_path, None);
    }

    #[test]
    fn round_trips_through_serialize() {
        let cfg = Config {
            refresh_seconds: Some(20),
            kube_tools: vec!["shell".to_owned(), "k9s".to_owned()],
            proxy: Some("root.example".to_owned()),
            user: Some("maxime".to_owned()),
            auth: Some("local".to_owned()),
            mfa: Some("otp".to_owned()),
            default_login: Some("root".to_owned()),
            kube_user: Some("kube-admin".to_owned()),
            db_user: Some("readonly".to_owned()),
            ..Config::default()
        };
        assert_eq!(Config::parse(&cfg.to_file_string()), cfg);
    }

    #[test]
    fn parses_default_behaviour_keys() {
        let cfg = Config::parse(
            "default_login = \"root\"\nkube_user = \"ka\"\ndb_user = \"ro\"\nauth = \"sso\"\nmfa = \"otp\"\n",
        );
        assert_eq!(cfg.default_login.as_deref(), Some("root"));
        assert_eq!(cfg.kube_user.as_deref(), Some("ka"));
        assert_eq!(cfg.db_user.as_deref(), Some("ro"));
        assert_eq!(cfg.auth.as_deref(), Some("sso"));
        assert_eq!(cfg.mfa.as_deref(), Some("otp"));
    }

    #[test]
    fn parses_kube_tools_list() {
        let cfg = Config::parse("kube_tools = \"shell, k9s, lens\"\n");
        assert_eq!(cfg.kube_tools, vec!["shell", "k9s", "lens"]);
        // absent -> empty (caller falls back to defaults)
        assert!(Config::parse("").kube_tools.is_empty());
    }
}
