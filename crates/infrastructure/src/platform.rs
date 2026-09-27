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

    if let Some(found) = std::env::var_os("PATH").and_then(|path| find_in_path(&path, name)) {
        return Ok(found);
    }

    for dir in known_install_dirs() {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(DomainError::BinaryNotFound)
}

/// First `dir/name` that is a file, over the absolute entries of a `PATH`-style
/// list. Relative and empty entries are skipped: they resolve against the cwd,
/// so a `./tsh` dropped in the working directory could otherwise win.
fn find_in_path(path: &std::ffi::OsStr, name: &str) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
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
/// elsewhere and on failure - purely defence-in-depth on a shared host.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_lookup_skips_relative_and_empty_entries() {
        // Tests run with the crate root as cwd, so `./Cargo.toml` exists: a
        // relative (`.`, `src/..`) or empty entry would find it.
        let rel = std::env::join_paths(["", ".", "src/.."]).unwrap();
        assert_eq!(find_in_path(&rel, "Cargo.toml"), None);

        let abs_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mixed = std::env::join_paths([PathBuf::from("."), abs_dir.clone()]).unwrap();
        assert_eq!(
            find_in_path(&mixed, "Cargo.toml"),
            Some(abs_dir.join("Cargo.toml"))
        );
    }

    /// A fresh scratch dir, unique per test and process.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ttui-platform-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn path_lookup_takes_the_first_file_in_order_and_skips_directories() {
        let root = scratch("order");
        let (a, b, c) = (root.join("a"), root.join("b"), root.join("c"));
        for d in [&a, &b, &c] {
            std::fs::create_dir_all(d).unwrap();
        }
        // In `a`, `tsh` is a directory: not a candidate.
        std::fs::create_dir_all(a.join("tsh")).unwrap();
        std::fs::write(b.join("tsh"), "").unwrap();
        std::fs::write(c.join("tsh"), "").unwrap();
        let path = std::env::join_paths([&a, &b, &c]).unwrap();
        assert_eq!(find_in_path(&path, "tsh"), Some(b.join("tsh")));
        assert_eq!(find_in_path(&path, "tctl"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn override_must_be_an_absolute_existing_file() {
        let root = scratch("override");
        let bin = root.join("tsh");
        std::fs::write(&bin, "").unwrap();
        assert_eq!(locate_named(Some(bin.clone()), "tsh").unwrap(), bin);
        // The override wins even when the name differs from the default.
        assert_eq!(locate_tctl(Some(bin.clone())).unwrap(), bin);

        let rejected = [
            root.join("missing"),
            root.clone(),                // a directory
            PathBuf::from("Cargo.toml"), // exists in the cwd, but relative
        ];
        for p in rejected {
            assert!(
                matches!(
                    locate_named(Some(p.clone()), "tsh"),
                    Err(DomainError::BinaryNotFound)
                ),
                "{p:?} must be rejected"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn binary_names_follow_the_os() {
        let exe = if cfg!(windows) { ".exe" } else { "" };
        assert_eq!(tsh_binary_name(), format!("tsh{exe}"));
        assert_eq!(tctl_binary_name(), format!("tctl{exe}"));
    }

    #[test]
    fn data_paths_end_with_the_app_dir() {
        assert!(error_log_path().ends_with("teleport-tui/errors.jsonl"));
        assert!(config_path().ends_with("teleport-tui/config.toml"));
    }

    #[cfg(unix)]
    #[test]
    fn restrict_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        let root = scratch("perms");
        let file = root.join("errors.jsonl");
        std::fs::write(&file, "").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

        restrict_file(&file);
        restrict_dir(&root);
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&root), 0o700);

        // Best-effort: a missing path is silently ignored.
        restrict_file(&root.join("missing"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
