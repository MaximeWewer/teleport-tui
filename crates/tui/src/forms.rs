//! Input-form state for the modal screens (login, scp, settings, add-user, kube
//! exec) plus the small validation helpers that gate typed values before they
//! become CLI arguments.
//!
//! These are pure view-model types with no dependency on [`App`](crate::app::App):
//! each holds a field cursor and the typed strings, and exposes cursor movement
//! (`next_field`/`prev_field`), dropdown cycling (`cycle`), toggles, and the
//! focused-text accessor (`text_mut`). Pulling them out of `app` keeps the form
//! plumbing separate from the update/dispatch logic.

use domain::auth::{AuthMethod, MfaMode};
use domain::error::DomainError;
use domain::value::{ClusterName, Hostname};

/// Editable `tsh login` form. The password and MFA are NOT handled here - `tsh`
/// prompts for them in the handed-over terminal (so secrets never enter the TUI).
/// `auth`/`mfa` are dropdowns over [`AuthMethod::CHOICES`]/[`MfaMode::CHOICES`];
/// `None` lets `tsh` use its default.
#[derive(Debug, Default, Clone)]
pub(crate) struct LoginForm {
    pub(crate) proxy: String,
    pub(crate) user: String,
    pub(crate) auth: Option<AuthMethod>,
    pub(crate) mfa: Option<MfaMode>,
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
        match self.field {
            2 => self.auth = cycle_choice(self.auth.as_ref(), &AuthMethod::CHOICES, forward),
            3 => self.mfa = cycle_choice(self.mfa.as_ref(), &MfaMode::CHOICES, forward),
            _ => {}
        }
    }

    /// The auth dropdown's label (`""` = default).
    pub(crate) fn auth_str(&self) -> &str {
        self.auth.as_ref().map_or("", AuthMethod::as_str)
    }

    /// The MFA dropdown's label (`""` = default).
    pub(crate) fn mfa_str(&self) -> &'static str {
        self.mfa.map_or("", MfaMode::as_str)
    }
}

/// The SSH node a form acts on, captured from the selected row (not editable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeTarget {
    pub(crate) cluster: ClusterName,
    pub(crate) host: Hostname,
}

/// `tsh scp` transfer form for an SSH node. `target` is captured from the
/// selected node (`None` only for the never-shown default form). The remote path
/// lives on the node, the local path on this machine; `download` chooses the
/// transfer direction.
#[derive(Debug, Default, Clone)]
pub(crate) struct ScpForm {
    pub(crate) target: Option<NodeTarget>,
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

/// Step an optional dropdown value through `None` (the default slot) then
/// `choices`, wrapping. A current value outside `choices` (e.g. a connector name
/// from the config file) steps as if from the default slot.
fn cycle_choice<T: Clone + PartialEq>(
    current: Option<&T>,
    choices: &[T],
    forward: bool,
) -> Option<T> {
    let pos = current
        .and_then(|c| choices.iter().position(|o| o == c))
        .map_or(0, |i| i + 1);
    let next = wrap_step(pos, choices.len() + 1, forward);
    next.checked_sub(1).and_then(|i| choices.get(i).cloned())
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
/// typed; auth/mfa are dropdowns (as on [`LoginForm`]).
#[derive(Debug, Default, Clone)]
pub(crate) struct SettingsForm {
    pub(crate) ssh_login: String,
    pub(crate) kube_user: String,
    pub(crate) db_user: String,
    pub(crate) proxy: String,
    pub(crate) user: String,
    pub(crate) auth: Option<AuthMethod>,
    pub(crate) mfa: Option<MfaMode>,
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
        match self.field {
            5 => self.auth = cycle_choice(self.auth.as_ref(), &AuthMethod::CHOICES, forward),
            6 => self.mfa = cycle_choice(self.mfa.as_ref(), &MfaMode::CHOICES, forward),
            _ => {}
        }
    }

    pub(crate) fn auth_str(&self) -> &str {
        self.auth.as_ref().map_or("", AuthMethod::as_str)
    }

    pub(crate) fn mfa_str(&self) -> &'static str {
        self.mfa.map_or("", MfaMode::as_str)
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
/// command to run instead of an interactive shell. `target` is captured from the
/// selected node (not editable).
#[derive(Debug, Default, Clone)]
pub(crate) struct SshOptionsForm {
    pub(crate) target: Option<NodeTarget>,
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

/// Parse a typed form value with its domain constructor (which owns the
/// validation: charset, length, no leading `-`), reporting a failure under the
/// form's own `field` name so the message points at the row to fix.
pub(crate) fn parse_field<'a, T: TryFrom<&'a str>>(
    value: &'a str,
    field: &'static str,
) -> Result<T, DomainError> {
    T::try_from(value).map_err(|_| DomainError::InvalidValue { field })
}

/// [`parse_field`] for an optional row: blank (after trimming) is `None`.
pub(crate) fn parse_opt_field<'a, T: TryFrom<&'a str>>(
    value: &'a str,
    field: &'static str,
) -> Result<Option<T>, DomainError> {
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        parse_field(value, field).map(Some)
    }
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

/// Whether a `-L` spec binds every interface (`0.0.0.0`, `*`, `[::]` or an
/// empty bind address), which exposes the tunnel to the network rather than
/// just this machine.
pub(crate) fn forward_binds_all_interfaces(spec: &str) -> bool {
    if let Some(rest) = spec.strip_prefix('[') {
        return rest.split(']').next().is_some_and(|a| a == "::");
    }
    let parts: Vec<&str> = spec.split(':').collect();
    matches!(parts.as_slice(), [bind, _, _, _] if matches!(*bind, "0.0.0.0" | "*" | ""))
}

/// Validate a one-off remote command before it becomes a CLI argument: no
/// control chars (terminal/log safety) and no leading `-` (so `tsh` can't reparse
/// it as a flag). Spaces are allowed - as with plain `ssh host cmd`, the command
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropdown_cycles_through_default_and_choices() {
        let mut f = LoginForm {
            field: 3,
            ..LoginForm::default()
        };
        f.cycle(true);
        assert_eq!(f.mfa, Some(MfaMode::Otp));
        f.cycle(false);
        assert_eq!(f.mfa, None);
        f.cycle(false); // wraps to the last choice
        assert_eq!(f.mfa, MfaMode::CHOICES.last().copied());
        // A config-only connector is kept until cycled, then steps like default.
        f.field = 2;
        f.auth = Some(AuthMethod::try_from("okta").unwrap());
        assert_eq!(f.auth_str(), "okta");
        f.cycle(true);
        assert_eq!(f.auth, Some(AuthMethod::Local));
    }

    #[test]
    fn wrap_step_wraps_both_ways_and_tolerates_empty() {
        assert_eq!(wrap_step(0, 3, true), 1);
        assert_eq!(wrap_step(2, 3, true), 0);
        assert_eq!(wrap_step(0, 3, false), 2);
        assert_eq!(wrap_step(0, 0, true), 0);
        assert_eq!(wrap_step(5, 0, false), 0);
    }

    #[test]
    fn field_cursor_wraps_and_skips_text_on_dropdowns() {
        let mut f = SettingsForm::default();
        f.prev_field();
        assert_eq!(f.field, 8, "wraps back to the last row");
        f.next_field();
        assert_eq!(f.field, 0);
        f.field = 5;
        assert!(f.text_mut().is_none(), "auth is a dropdown");
        f.field = 7;
        assert!(f.numeric_field());
        f.text_mut().unwrap().push('9');
        assert_eq!(f.refresh, "9");
    }

    #[test]
    fn toggles_only_flip_on_their_rows() {
        let mut scp = ScpForm::default();
        scp.toggle(); // row 0: direction
        assert!(scp.download);
        scp.field = 4;
        scp.toggle();
        assert!(scp.recursive);
        scp.field = 2;
        scp.toggle(); // a text row: no-op
        assert!(scp.download && scp.recursive);

        let mut ssh = SshOptionsForm::default();
        ssh.toggle();
        assert!(!ssh.tunnel_only, "row 0 is the login text field");
        ssh.field = 2;
        ssh.toggle();
        assert!(ssh.tunnel_only);
    }

    #[test]
    fn parse_field_reports_the_form_row() {
        let ok: ClusterName = parse_field("leaf.example.com", "cluster").unwrap();
        assert_eq!(ok.as_str(), "leaf.example.com");
        let err = parse_field::<ClusterName>("-oProxyCommand=x", "cluster").unwrap_err();
        assert!(matches!(
            err,
            DomainError::InvalidValue { field: "cluster" }
        ));
    }

    #[test]
    fn parse_opt_field_treats_blank_as_none_and_trims() {
        assert_eq!(parse_opt_field::<Hostname>("  ", "host").unwrap(), None);
        assert_eq!(
            parse_opt_field::<Hostname>(" web-1 ", "host").unwrap(),
            Some(Hostname::try_from("web-1").unwrap())
        );
        assert!(matches!(
            parse_opt_field::<Hostname>("bad host", "host"),
            Err(DomainError::InvalidValue { field: "host" })
        ));
    }

    #[test]
    fn valid_forward_accepts_specs_and_rejects_injection() {
        for ok in [
            "8080:db:5432",
            "127.0.0.1:8080:db.internal:5432",
            "[::1]:8080:db:5432",
            "*:8080:db_1:5432",
        ] {
            assert!(valid_forward(ok), "{ok}");
        }
        let long = "1".repeat(257);
        for bad in [
            "",
            "-oProxyCommand=x",
            "8080:db:5432 -R 1:x:1",
            "8080:db:5432;id",
            "8080:db:5432\n",
            "8080:$(id):5432",
            long.as_str(),
        ] {
            assert!(!valid_forward(bad), "{bad:?}");
        }
    }

    #[test]
    fn valid_command_allows_spaces_but_not_flags_or_control_chars() {
        assert!(valid_command("ls -la /var/log | head"));
        assert!(!valid_command(""));
        assert!(!valid_command("--help"));
        assert!(!valid_command("echo \x1b[2J"));
        assert!(!valid_command("echo a\nrm -rf /"));
        assert!(valid_command(&"a".repeat(4096)));
        assert!(!valid_command(&"a".repeat(4097)));
    }

    #[test]
    fn valid_path_allows_spaces_but_not_flags_or_control_chars() {
        assert!(valid_path("/home/alice/My Documents/report.pdf"));
        assert!(valid_path("./relative/dir"));
        assert!(!valid_path(""));
        assert!(!valid_path("-r"));
        assert!(!valid_path("file\u{7}name"));
        assert!(!valid_path(&"a".repeat(4097)));
    }
}
