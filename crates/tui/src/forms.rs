//! Input-form state for the modal screens (login, scp, settings, add-user, kube
//! exec) plus the small validation helpers that gate typed values before they
//! become CLI arguments.
//!
//! These are pure view-model types with no dependency on [`App`](crate::app::App):
//! each holds a field cursor and the typed strings, and exposes cursor movement
//! (`next_field`/`prev_field`), dropdown cycling (`cycle`), toggles, and the
//! focused-text accessor (`text_mut`). Pulling them out of `app` keeps the form
//! plumbing separate from the update/dispatch logic.

/// Auth connector choices for the login dropdown. `""` = let `tsh` use the
/// cluster default. `sso` triggers the browser flow (no `--auth` connector);
/// `local`/`passwordless` are passed through as `--auth=<value>`.
pub(crate) const AUTH_OPTIONS: &[&str] = &["", "local", "passwordless", "sso"];
/// MFA mode choices for the login dropdown. `""` = `tsh` default (auto).
/// `platform` uses the machine TPM; `otp` is typed in the terminal; `sso`/
/// `browser` open the browser; `webauthn` covers security keys (e.g. a Yubikey).
pub(crate) const MFA_OPTIONS: &[&str] = &["", "otp", "webauthn", "platform", "sso", "browser"];

/// Editable `tsh login` form. The password and MFA are NOT handled here — `tsh`
/// prompts for them in the handed-over terminal (so secrets never enter the TUI).
/// `auth`/`mfa` are indices into [`AUTH_OPTIONS`]/[`MFA_OPTIONS`] (dropdowns).
#[derive(Debug, Default, Clone)]
pub(crate) struct LoginForm {
    pub(crate) proxy: String,
    pub(crate) user: String,
    pub(crate) auth: usize,
    pub(crate) mfa: usize,
    pub(crate) field: usize,
}

impl LoginForm {
    const FIELDS: usize = 4;

    /// Mutable handle to the focused TEXT field (proxy/user). Returns `None` for
    /// the dropdown fields (auth/mfa), which are cycled, not typed.
    pub(crate) fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            0 => Some(&mut self.proxy),
            1 => Some(&mut self.user),
            _ => None,
        }
    }

    pub(crate) fn next_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, true);
    }

    pub(crate) fn prev_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, false);
    }

    /// Cycle the focused dropdown (auth/mfa). No-op on the text fields.
    pub(crate) fn cycle(&mut self, forward: bool) {
        let (idx, len) = match self.field {
            2 => (&mut self.auth, AUTH_OPTIONS.len()),
            3 => (&mut self.mfa, MFA_OPTIONS.len()),
            _ => return,
        };
        *idx = wrap_step(*idx, len, forward);
    }

    pub(crate) fn auth_str(&self) -> &'static str {
        AUTH_OPTIONS.get(self.auth).copied().unwrap_or("")
    }

    pub(crate) fn mfa_str(&self) -> &'static str {
        MFA_OPTIONS.get(self.mfa).copied().unwrap_or("")
    }
}

/// `tsh scp` transfer form for an SSH node. `host`/`cluster` are captured from
/// the selected node (not editable). The remote path lives on the node, the
/// local path on this machine; `download` chooses the transfer direction.
#[derive(Debug, Default, Clone)]
pub(crate) struct ScpForm {
    pub(crate) host: String,
    pub(crate) cluster: String,
    /// true = remote → local (copy from node); false = local → remote (send).
    pub(crate) download: bool,
    pub(crate) login: String,
    pub(crate) remote: String,
    pub(crate) local: String,
    pub(crate) recursive: bool,
    pub(crate) field: usize,
}

impl ScpForm {
    // Editable rows: 0 direction, 1 login, 2 remote, 3 local, 4 recursive.
    const FIELDS: usize = 5;

    /// Mutable handle to the focused TEXT field; `None` for the toggle rows
    /// (direction/recursive), which are flipped with ←/→ instead of typed.
    pub(crate) fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            1 => Some(&mut self.login),
            2 => Some(&mut self.remote),
            3 => Some(&mut self.local),
            _ => None,
        }
    }

    pub(crate) fn next_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, true);
    }

    pub(crate) fn prev_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, false);
    }

    /// Flip the focused toggle (direction/recursive). No-op on text rows.
    pub(crate) fn toggle(&mut self) {
        match self.field {
            0 => self.download = !self.download,
            4 => self.recursive = !self.recursive,
            _ => {}
        }
    }
}

/// Index of `val` in `opts`, or 0 (the `""`/default slot) when absent.
pub(crate) fn opt_index(opts: &[&str], val: &str) -> usize {
    opts.iter().position(|o| *o == val).unwrap_or(0)
}

/// Advance a wrapping cursor (form field, dropdown option) by ±1 within
/// `[0, len)`. Shared by every form so the modular arithmetic lives in one spot.
fn wrap_step(idx: usize, len: usize, forward: bool) -> usize {
    if len == 0 {
        return 0;
    }
    if forward {
        (idx + 1) % len
    } else {
        (idx + len - 1) % len
    }
}

/// Editable, persistable defaults shown on the Settings screen. Text rows are
/// typed; auth/mfa are dropdowns (indices into [`AUTH_OPTIONS`]/[`MFA_OPTIONS`]).
#[derive(Debug, Default, Clone)]
pub(crate) struct SettingsForm {
    pub(crate) ssh_login: String,
    pub(crate) kube_user: String,
    pub(crate) db_user: String,
    pub(crate) proxy: String,
    pub(crate) user: String,
    pub(crate) auth: usize,
    pub(crate) mfa: usize,
    pub(crate) refresh: String,
    pub(crate) kube_tools: String,
    pub(crate) field: usize,
}

impl SettingsForm {
    // Rows: 0 ssh, 1 kube, 2 db, 3 proxy, 4 user, 5 auth, 6 mfa, 7 refresh, 8 tools.
    const FIELDS: usize = 9;

    pub(crate) fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            0 => Some(&mut self.ssh_login),
            1 => Some(&mut self.kube_user),
            2 => Some(&mut self.db_user),
            3 => Some(&mut self.proxy),
            4 => Some(&mut self.user),
            7 => Some(&mut self.refresh),
            8 => Some(&mut self.kube_tools),
            _ => None, // 5/6 are dropdowns
        }
    }

    /// True when the focused row only accepts digits (the refresh interval).
    pub(crate) fn numeric_field(&self) -> bool {
        self.field == 7
    }

    pub(crate) fn next_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, true);
    }

    pub(crate) fn prev_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, false);
    }

    pub(crate) fn cycle(&mut self, forward: bool) {
        let (idx, len) = match self.field {
            5 => (&mut self.auth, AUTH_OPTIONS.len()),
            6 => (&mut self.mfa, MFA_OPTIONS.len()),
            _ => return,
        };
        *idx = wrap_step(*idx, len, forward);
    }

    pub(crate) fn auth_str(&self) -> &'static str {
        AUTH_OPTIONS.get(self.auth).copied().unwrap_or("")
    }

    pub(crate) fn mfa_str(&self) -> &'static str {
        MFA_OPTIONS.get(self.mfa).copied().unwrap_or("")
    }
}

/// Two-field form for `tctl users add` (username + comma-separated roles).
#[derive(Debug, Default, Clone)]
pub(crate) struct AddUserForm {
    pub(crate) username: String,
    pub(crate) roles: String,
    pub(crate) field: usize,
}

impl AddUserForm {
    const FIELDS: usize = 2;

    pub(crate) fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            0 => Some(&mut self.username),
            1 => Some(&mut self.roles),
            _ => None,
        }
    }

    pub(crate) fn next_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, true);
    }

    pub(crate) fn prev_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, false);
    }
}

/// `tsh ssh` options form for the selected SSH node: an optional login, a local
/// port-forward (`-L`) with a tunnel-only toggle (`-N`), and an optional one-off
/// command to run instead of an interactive shell. `host`/`cluster` are captured
/// from the selected node (not editable).
#[derive(Debug, Default, Clone)]
pub(crate) struct SshOptionsForm {
    pub(crate) host: String,
    pub(crate) cluster: String,
    pub(crate) login: String,
    pub(crate) forward: String,
    /// `-N`: open the forward without a remote shell/command (pure tunnel).
    pub(crate) tunnel_only: bool,
    pub(crate) command: String,
    pub(crate) field: usize,
}

impl SshOptionsForm {
    // Rows: 0 login, 1 forward, 2 tunnel-only (toggle), 3 command.
    const FIELDS: usize = 4;

    pub(crate) fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            0 => Some(&mut self.login),
            1 => Some(&mut self.forward),
            3 => Some(&mut self.command),
            _ => None, // 2 is the tunnel-only toggle
        }
    }

    pub(crate) fn next_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, true);
    }

    pub(crate) fn prev_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, false);
    }

    /// Flip the tunnel-only toggle. No-op on the text rows.
    pub(crate) fn toggle(&mut self) {
        if self.field == 2 {
            self.tunnel_only = !self.tunnel_only;
        }
    }
}

/// Form for `tsh kube exec` (Kube tab): the pod/deployment and the command to
/// run, plus optional container/namespace overrides.
#[derive(Debug, Default, Clone)]
pub(crate) struct KubeExecForm {
    pub(crate) pod: String,
    pub(crate) command: String,
    pub(crate) container: String,
    pub(crate) namespace: String,
    pub(crate) field: usize,
}

impl KubeExecForm {
    const FIELDS: usize = 4;

    pub(crate) fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            0 => Some(&mut self.pod),
            1 => Some(&mut self.command),
            2 => Some(&mut self.container),
            3 => Some(&mut self.namespace),
            _ => None,
        }
    }

    pub(crate) fn next_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, true);
    }

    pub(crate) fn prev_field(&mut self) {
        self.field = wrap_step(self.field, Self::FIELDS, false);
    }
}

/// Validate a token-type string before it becomes a `tctl` argument. Chars
/// only (allowlist); `tctl` rejects unknown types itself.
pub(crate) fn valid_token_type(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ','))
}

/// Validate a comma-separated roles string before it becomes a `tsh` argument.
pub(crate) fn valid_roles(roles: &str) -> bool {
    !roles.is_empty()
        && roles.len() <= 256
        && !roles.starts_with('-')
        && roles
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ','))
}

/// Validate a connection user/login (from the profile or typed) before it
/// becomes a CLI argument: no control/whitespace and no leading `-` (which
/// could be parsed as a flag). Kube users may contain `:./@_-`.
pub(crate) fn valid_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 256
        && !user.starts_with('-')
        && !user.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Validate a `-L` local-forward spec (`[bind:]port:host:hostport`) before it
/// becomes a CLI argument: host/port characters only, no control/whitespace and
/// no leading `-` (flag injection). Execution is argv-only (no shell).
pub(crate) fn valid_forward(spec: &str) -> bool {
    !spec.is_empty()
        && spec.len() <= 256
        && !spec.starts_with('-')
        && spec.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '-' | '_' | '[' | ']' | '*')
        })
}

/// Validate a one-off remote command before it becomes a CLI argument: no
/// control chars (terminal/log safety) and no leading `-` (so `tsh` can't reparse
/// it as a flag). Spaces are allowed — as with plain `ssh host cmd`, the command
/// is one argv element that the *remote* shell parses; our side is argv-only.
pub(crate) fn valid_command(cmd: &str) -> bool {
    !cmd.is_empty()
        && cmd.len() <= 4096
        && !cmd.starts_with('-')
        && !cmd.chars().any(char::is_control)
}

/// Validate an `scp` path before it becomes a CLI argument. Filenames may hold
/// spaces, so whitespace is allowed; control chars are rejected (they could
/// corrupt the terminal / logs) and a leading `-` is blocked (flag injection).
/// Execution is argv-only (no shell), so other metacharacters are inert.
pub(crate) fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.starts_with('-')
        && !path.chars().any(char::is_control)
}
