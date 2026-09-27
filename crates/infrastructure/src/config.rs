//! Optional user config (`config.toml`). Deliberately a tiny hand-rolled
//! flat `key = value` parser - no TOML dependency (attack-surface constraint).
//! Unknown keys and invalid values are ignored (defaults apply) but reported as
//! warnings; a missing file yields defaults silently, an unreadable one with a
//! warning.

use std::path::{Path, PathBuf};

use domain::auth::{AuthMethod, MfaMode};
use domain::port::PreferencesStore;
use domain::preferences::Preferences;

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
    /// Pre-filled auth method for the login form (`local`/`passwordless`/`sso`
    /// or a connector name).
    pub auth: Option<AuthMethod>,
    /// Pre-filled MFA mode for the login form (`otp`/`cross-platform`/…).
    pub mfa: Option<MfaMode>,
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
        Self::load_with_warnings(path).0
    }

    /// Like [`Config::load_default`], plus a human-readable warning for every
    /// ignored line/key/value (see [`Config::parse_with_warnings`]).
    #[must_use]
    pub fn load_default_with_warnings() -> (Self, Vec<String>) {
        Self::load_with_warnings(&platform::config_path())
    }

    /// Like [`Config::load`], plus warnings. A missing file is the normal
    /// "no config" case and is not a warning; any other read error is.
    #[must_use]
    pub fn load_with_warnings(path: &Path) -> (Self, Vec<String>) {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::parse_with_warnings(&s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Self::default(), Vec::new()),
            Err(e) => (
                Self::default(),
                vec![format!(
                    "could not read config {}: {e} (using defaults)",
                    path.display()
                )],
            ),
        }
    }

    #[must_use]
    pub fn parse(contents: &str) -> Self {
        Self::parse_with_warnings(contents).0
    }

    /// Parse, also returning a warning for each malformed line, unknown key or
    /// invalid value (all of which are otherwise ignored), so a typo doesn't
    /// silently fall back to the default.
    #[must_use]
    pub fn parse_with_warnings(contents: &str) -> (Self, Vec<String>) {
        let mut cfg = Self::default();
        let mut warnings = Vec::new();
        for (idx, raw) in contents.lines().enumerate() {
            let lineno = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                warnings.push(format!(
                    "config line {lineno} ignored: expected `key = value`"
                ));
                continue;
            };
            let key = key.trim();
            let value = unquote(value.trim());
            match key {
                "tsh_path" if !value.is_empty() => cfg.tsh_path = Some(PathBuf::from(value)),
                "tctl_path" if !value.is_empty() => cfg.tctl_path = Some(PathBuf::from(value)),
                // 0 is valid (disables auto-refresh); anything unparsable is not.
                "refresh_seconds" => match value.parse::<u64>() {
                    Ok(n) => cfg.refresh_seconds = Some(n).filter(|n| *n > 0),
                    Err(_) => warnings.push(format!(
                        "config line {lineno}: invalid refresh_seconds `{value}` (expected whole seconds), auto-refresh disabled"
                    )),
                },
                "kube_tools" => {
                    cfg.kube_tools = value
                        .split(',')
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "proxy" if !value.is_empty() => cfg.proxy = Some(value.to_owned()),
                "user" if !value.is_empty() => cfg.user = Some(value.to_owned()),
                "auth" if !value.is_empty() => match AuthMethod::try_from(value) {
                    Ok(a) => cfg.auth = Some(a),
                    Err(_) => warnings.push(format!(
                        "config line {lineno}: invalid auth `{value}` (expected local, passwordless, sso or a connector name), using the cluster default"
                    )),
                },
                "mfa" if !value.is_empty() => match MfaMode::try_from(value) {
                    Ok(m) => cfg.mfa = Some(m),
                    Err(_) => warnings.push(format!(
                        "config line {lineno}: invalid mfa `{value}` (expected one of auto, cross-platform, platform, otp, sso, browser), using the tsh default"
                    )),
                },
                "default_login" if !value.is_empty() => {
                    cfg.default_login = Some(value.to_owned());
                }
                "kube_user" if !value.is_empty() => cfg.kube_user = Some(value.to_owned()),
                "db_user" if !value.is_empty() => cfg.db_user = Some(value.to_owned()),
                // A known key with an empty value just keeps the default.
                "tsh_path" | "tctl_path" | "proxy" | "user" | "auth" | "mfa" | "default_login"
                | "kube_user" | "db_user" => {}
                _ => warnings.push(format!("config line {lineno}: unknown key `{key}` ignored")),
            }
        }
        (cfg, warnings)
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
            kv(&mut s, "auth", v.as_str());
        }
        if let Some(v) = self.mfa {
            kv(&mut s, "mfa", v.as_str());
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

impl Config {
    /// The user-editable subset (the Settings screen).
    #[must_use]
    pub fn preferences(&self) -> Preferences {
        Preferences {
            proxy: self.proxy.clone(),
            user: self.user.clone(),
            auth: self.auth.clone(),
            mfa: self.mfa,
            default_login: self.default_login.clone(),
            kube_user: self.kube_user.clone(),
            db_user: self.db_user.clone(),
            refresh_seconds: self.refresh_seconds,
            kube_tools: self.kube_tools.clone(),
        }
    }

    /// Overwrite the user-editable subset, keeping the other keys (binary paths).
    pub fn set_preferences(&mut self, prefs: &Preferences) {
        self.proxy.clone_from(&prefs.proxy);
        self.user.clone_from(&prefs.user);
        self.auth.clone_from(&prefs.auth);
        self.mfa = prefs.mfa;
        self.default_login.clone_from(&prefs.default_login);
        self.kube_user.clone_from(&prefs.kube_user);
        self.db_user.clone_from(&prefs.db_user);
        self.refresh_seconds = prefs.refresh_seconds;
        self.kube_tools.clone_from(&prefs.kube_tools);
    }
}

/// [`PreferencesStore`] backed by the `config.toml` at `path`. Each save
/// re-reads the file first, so keys the Settings screen doesn't edit (e.g.
/// `tsh_path`) survive.
#[derive(Debug, Clone)]
pub struct ConfigFileStore {
    path: PathBuf,
}

impl ConfigFileStore {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The per-OS config path.
    #[must_use]
    pub fn at_default_path() -> Self {
        Self::new(platform::config_path())
    }
}

impl PreferencesStore for ConfigFileStore {
    fn save(&self, prefs: &Preferences) -> std::io::Result<()> {
        let mut cfg = Config::load(&self.path);
        cfg.set_preferences(prefs);
        cfg.save(&self.path)
    }

    fn location(&self) -> String {
        self.path.display().to_string()
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
    fn warns_about_unknown_keys_bad_values_and_malformed_lines() {
        let (cfg, warnings) = Config::parse_with_warnings(
            "# ok\nrefersh_seconds = 30\nrefresh_seconds = soon\njust text\nproxy = \"\"\nuser = \"me\"\n",
        );
        assert_eq!(cfg.refresh_seconds, None);
        assert_eq!(cfg.user.as_deref(), Some("me"));
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        assert!(warnings[0].contains("refersh_seconds"));
        assert!(warnings[1].contains("soon"));
        assert!(warnings[2].contains("line 4"));
        // A valid file, including `refresh_seconds = 0` (disabled), is quiet.
        assert!(
            Config::parse_with_warnings("refresh_seconds = 0\n")
                .1
                .is_empty()
        );
    }

    #[test]
    fn missing_file_is_not_a_warning() {
        let (cfg, warnings) =
            Config::load_with_warnings(Path::new("/nonexistent/teleport-tui.toml"));
        assert_eq!(cfg, Config::default());
        assert!(warnings.is_empty());
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
            auth: Some(AuthMethod::Local),
            mfa: Some(MfaMode::Otp),
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
        assert_eq!(cfg.auth, Some(AuthMethod::Sso));
        assert_eq!(cfg.mfa, Some(MfaMode::Otp));
    }

    #[test]
    fn warns_about_invalid_auth_and_mfa() {
        let (cfg, warnings) = Config::parse_with_warnings("auth = \"-evil\"\nmfa = \"yubikey\"\n");
        assert_eq!(cfg.auth, None);
        assert_eq!(cfg.mfa, None);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("auth"));
        assert!(warnings[1].contains("yubikey"));
        // A named connector and the legacy `webauthn` spelling are accepted.
        let (cfg, warnings) = Config::parse_with_warnings("auth = \"okta\"\nmfa = \"webauthn\"\n");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(cfg.auth.as_ref().map(AuthMethod::as_str), Some("okta"));
        assert_eq!(cfg.mfa, Some(MfaMode::CrossPlatform));
    }

    #[test]
    fn file_store_saves_preferences_and_keeps_other_keys() {
        let dir = std::env::temp_dir().join(format!("ttui-store-{}", std::process::id()));
        let path = dir.join("config.toml");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(&path, "tsh_path = \"/opt/tsh\"\nuser = \"old\"\n").unwrap();
        let prefs = Preferences {
            user: Some("alice".to_owned()),
            mfa: Some(MfaMode::Otp),
            ..Preferences::default()
        };
        ConfigFileStore::new(path.clone()).save(&prefs).unwrap();
        let reloaded = Config::load(&path);
        assert_eq!(reloaded.tsh_path, Some(PathBuf::from("/opt/tsh")));
        assert_eq!(reloaded.preferences(), prefs);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_kube_tools_list() {
        let cfg = Config::parse("kube_tools = \"shell, k9s, lens\"\n");
        assert_eq!(cfg.kube_tools, vec!["shell", "k9s", "lens"]);
        // absent -> empty (caller falls back to defaults)
        assert!(Config::parse("").kube_tools.is_empty());
    }
}
