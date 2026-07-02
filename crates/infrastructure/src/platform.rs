//! Per-OS concerns: locating the `tsh` binary and resolving data directories.
//! Runtime resolution via env vars; `#[cfg]` only where the OS genuinely differs.

use std::path::{Path, PathBuf};

use domain::error::DomainError;

/// Binary name for the current OS.
#[must_use]
pub fn tsh_binary_name() -> &'static str {
    if cfg!(windows) { "tsh.exe" } else { "tsh" }
}

/// Admin CLI binary name for the current OS.
#[must_use]
pub fn tctl_binary_name() -> &'static str {
    if cfg!(windows) { "tctl.exe" } else { "tctl" }
}

/// Locate the `tctl` binary (same strategy as [`locate_tsh`]). Admin features
/// are optional, so callers treat a failure as "admin unavailable", not fatal.
///
/// # Errors
/// Returns [`DomainError::BinaryNotFound`] if no executable is found.
pub fn locate_tctl(override_path: Option<PathBuf>) -> Result<PathBuf, DomainError> {
    locate_named(override_path, tctl_binary_name())
}

/// Locate the `tsh` binary safely.
///
/// Order: explicit override → `PATH` → known per-OS install dirs. An absolute,
/// validated path avoids `PATH` hijacking from passing an attacker-controlled
/// relative name to the shell (we never use a shell anyway).
///
/// # Errors
/// Returns [`DomainError::BinaryNotFound`] if no executable is found.
pub fn locate_tsh(override_path: Option<PathBuf>) -> Result<PathBuf, DomainError> {
    locate_named(override_path, tsh_binary_name())
}

/// Shared binary resolution: explicit override → `PATH` → known install dirs.
fn locate_named(override_path: Option<PathBuf>, name: &str) -> Result<PathBuf, DomainError> {
    if let Some(p) = override_path {
        // A config-supplied path must be absolute: a relative override would
        // resolve against the cwd (a PATH-hijack vector). Existence is checked
        // here; executability/permissions are left to the spawn (avoids a
        // TOCTOU pre-check that the OS re-validates anyway).
        if p.is_absolute() && p.is_file() {
            return Ok(p);
        }
        return Err(DomainError::BinaryNotFound);
    }

    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    for dir in known_install_dirs() {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(DomainError::BinaryNotFound)
}

fn known_install_dirs() -> &'static [&'static str] {
    #[cfg(target_os = "macos")]
    {
        &["/opt/homebrew/bin", "/usr/local/bin"]
    }
    #[cfg(target_os = "windows")]
    {
        &[
            r"C:\Program Files\Teleport",
            r"C:\Program Files (x86)\Teleport",
        ]
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        &["/usr/local/bin", "/usr/bin"]
    }
}

/// Directory for app state (error logs). Best-effort per-OS; falls back to the
/// current directory if no home is resolvable.
#[must_use]
pub fn state_dir() -> PathBuf {
    let base = state_base().unwrap_or_else(|| PathBuf::from("."));
    base.join("teleport-tui")
}

fn state_base() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library").join("Logs"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state"))
            })
    }
}

/// Path of the NDJSON error log.
#[must_use]
pub fn error_log_path() -> PathBuf {
    state_dir().join("errors.jsonl")
}

/// Per-OS config directory base.
fn config_base() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA").map(PathBuf::from)
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    }
}

/// Best-effort tighten a directory to owner-only (0700) on Unix. No-op
/// elsewhere and on failure — purely defence-in-depth on a shared host.
pub fn restrict_dir(path: &Path) {
    restrict(path, 0o700);
}

/// Best-effort tighten a file to owner-only (0600) on Unix. No-op elsewhere.
pub fn restrict_file(path: &Path) {
    restrict(path, 0o600);
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) {}

/// Path of the optional config file.
#[must_use]
pub fn config_path() -> PathBuf {
    config_base()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("teleport-tui")
        .join("config.toml")
}
