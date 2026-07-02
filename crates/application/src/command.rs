//! Pure builders for the *interactive* `tsh` argv vectors the TUI hands to the
//! terminal (login, ssh, db connect, scp, requests, logout).
//!
//! These live in the application layer, not infrastructure: they perform **no
//! I/O** — they only assemble the argv that the presentation layer expresses as
//! an interactive intent and hands to the terminal itself. Keeping them here
//! means the TUI orchestrates interactive commands through the application
//! layer rather than reaching into `infrastructure`. The *read-path* argv (the
//! commands infrastructure actually *executes* via the command runner) stays in
//! `infrastructure::tsh`/`tctl`, next to the I/O it drives.
//!
//! SECURITY: every argument is a discrete argv element — execution is argv-only,
//! never a shell. Callers pass already-validated values (domain newtypes or the
//! TUI's `valid_*` checks); these functions add no validation, only assembly.
//! Value-bearing flags use the `--flag=value` form so a value can never be
//! reparsed as a separate option.

/// `tsh login [--proxy=…] [--user=…] [--auth=…] [--mfa-mode=…]`. Empty `proxy`,
/// `user`, or `mfa` omit their flags. `auth` is only emitted for the real
/// connector flows (`local`/`passwordless`); `sso` drives the browser and takes
/// no `--auth` value, so it (and any other value) is dropped.
#[must_use]
pub fn login(proxy: &str, user: &str, auth: &str, mfa: &str) -> Vec<String> {
    let mut args = vec!["login".to_owned()];
    if !proxy.is_empty() {
        args.push(format!("--proxy={proxy}"));
    }
    if !user.is_empty() {
        args.push(format!("--user={user}"));
    }
    if auth == "local" || auth == "passwordless" {
        args.push(format!("--auth={auth}"));
    }
    if !mfa.is_empty() {
        args.push(format!("--mfa-mode={mfa}"));
    }
    args
}

/// `tsh logout`.
#[must_use]
pub fn logout() -> Vec<String> {
    vec!["logout".to_owned()]
}

/// `tsh ssh -c <cluster> <user>@<host>`.
#[must_use]
pub fn ssh(cluster: &str, user: &str, host: &str) -> Vec<String> {
    vec![
        "ssh".to_owned(),
        "-c".to_owned(),
        cluster.to_owned(),
        format!("{user}@{host}"),
    ]
}

/// `tsh ssh -c <cluster> [-L <spec>] [-N] [<user>@]<host> [<command>]`.
///
/// Extends [`ssh`] with the options form's extras: a blank `user` omits the login
/// (tsh's default); a blank `forward` omits `-L`; `-N` (tunnel only, no remote
/// shell) is emitted **only** for a pure forward — a `-L` with no `command` and
/// `tunnel_only` set. A non-empty `command` is appended as a single argv element
/// (the remote shell parses it, as with plain `ssh host cmd`).
#[must_use]
pub fn ssh_full(
    cluster: &str,
    user: &str,
    host: &str,
    forward: &str,
    tunnel_only: bool,
    command: &str,
) -> Vec<String> {
    let mut args = vec!["ssh".to_owned(), "-c".to_owned(), cluster.to_owned()];
    if !forward.is_empty() {
        args.push("-L".to_owned());
        args.push(forward.to_owned());
    }
    if tunnel_only && !forward.is_empty() && command.is_empty() {
        args.push("-N".to_owned());
    }
    args.push(if user.is_empty() {
        host.to_owned()
    } else {
        format!("{user}@{host}")
    });
    if !command.is_empty() {
        args.push(command.to_owned());
    }
    args
}

/// `tsh db connect -c <cluster> <name> [--db-user=<user>]`. An empty `db_user`
/// lets tsh pick the default user (no flag).
#[must_use]
pub fn db_connect(cluster: &str, name: &str, db_user: &str) -> Vec<String> {
    let mut args = vec![
        "db".to_owned(),
        "connect".to_owned(),
        "-c".to_owned(),
        cluster.to_owned(),
        name.to_owned(),
    ];
    if !db_user.is_empty() {
        args.push(format!("--db-user={db_user}"));
    }
    args
}

/// `tsh scp -c <cluster> [-r] <from> <to>`, where one endpoint is the remote
/// spec `[login@]host:path` and the direction decides the from/to order.
#[must_use]
pub fn scp(
    cluster: &str,
    login: &str,
    host: &str,
    remote_path: &str,
    local_path: &str,
    download: bool,
    recursive: bool,
) -> Vec<String> {
    let remote_spec = if login.is_empty() {
        format!("{host}:{remote_path}")
    } else {
        format!("{login}@{host}:{remote_path}")
    };
    let mut args = vec!["scp".to_owned(), "-c".to_owned(), cluster.to_owned()];
    if recursive {
        args.push("-r".to_owned());
    }
    let (from, to) = if download {
        (remote_spec, local_path.to_owned())
    } else {
        (local_path.to_owned(), remote_spec)
    };
    args.push(from);
    args.push(to);
    args
}

/// `tsh db login -c <cluster> [--db-user=<user>] <name>` — retrieve a database
/// certificate (no interactive shell; the cert lands in `~/.tsh`). An empty
/// `db_user` lets tsh use the database's own default user.
#[must_use]
pub fn db_login(cluster: &str, name: &str, db_user: &str) -> Vec<String> {
    let mut args = vec![
        "db".to_owned(),
        "login".to_owned(),
        "-c".to_owned(),
        cluster.to_owned(),
    ];
    if !db_user.is_empty() {
        args.push(format!("--db-user={db_user}"));
    }
    args.push(name.to_owned());
    args
}

/// `tsh db logout -c <cluster> <name>` — remove a database's stored credentials.
#[must_use]
pub fn db_logout(cluster: &str, name: &str) -> Vec<String> {
    vec![
        "db".to_owned(),
        "logout".to_owned(),
        "-c".to_owned(),
        cluster.to_owned(),
        name.to_owned(),
    ]
}

/// `tsh apps login -c <cluster> <name>` — retrieve a short-lived app certificate.
#[must_use]
pub fn app_login(cluster: &str, name: &str) -> Vec<String> {
    vec![
        "apps".to_owned(),
        "login".to_owned(),
        "-c".to_owned(),
        cluster.to_owned(),
        name.to_owned(),
    ]
}

/// `tsh apps logout -c <cluster> <name>` — remove a stored app certificate.
#[must_use]
pub fn app_logout(cluster: &str, name: &str) -> Vec<String> {
    vec![
        "apps".to_owned(),
        "logout".to_owned(),
        "-c".to_owned(),
        cluster.to_owned(),
        name.to_owned(),
    ]
}

/// `tsh kube login -c <cluster> <kube>` — make `kube` the active Kubernetes
/// context, a prerequisite for `tsh kube exec` (which has no cluster flag).
#[must_use]
pub fn kube_login(cluster: &str, kube: &str) -> Vec<String> {
    vec![
        "kube".to_owned(),
        "login".to_owned(),
        "-c".to_owned(),
        cluster.to_owned(),
        kube.to_owned(),
    ]
}

/// `tsh kube exec [-c <container>] [-n <namespace>] -- <pod> <command…>` — run a
/// command in a pod of the *current* kube context (set by [`kube_login`]). The
/// `--` ends flag parsing so a command with leading-dash args is passed through
/// verbatim. `command` is the already-tokenised argv. Empty container/namespace
/// omit their flags.
#[must_use]
pub fn kube_exec(pod: &str, command: &[String], container: &str, namespace: &str) -> Vec<String> {
    let mut args = vec!["kube".to_owned(), "exec".to_owned()];
    if !container.is_empty() {
        args.push(format!("--container={container}"));
    }
    if !namespace.is_empty() {
        args.push(format!("--namespace={namespace}"));
    }
    args.push("--".to_owned());
    args.push(pod.to_owned());
    args.extend(command.iter().cloned());
    args
}

/// `tsh request show -c <cluster> <id>`.
#[must_use]
pub fn request_show(cluster: &str, id: &str) -> Vec<String> {
    vec![
        "request".to_owned(),
        "show".to_owned(),
        "-c".to_owned(),
        cluster.to_owned(),
        id.to_owned(),
    ]
}

/// `tsh request create -c <cluster> --roles=<roles>`.
#[must_use]
pub fn request_create(cluster: &str, roles: &str) -> Vec<String> {
    vec![
        "request".to_owned(),
        "create".to_owned(),
        "-c".to_owned(),
        cluster.to_owned(),
        format!("--roles={roles}"),
    ]
}

/// `tsh mfa add` — interactively register a new MFA device (tsh prompts for the
/// name/type and drives the authenticator in the terminal).
#[must_use]
pub fn mfa_add() -> Vec<String> {
    vec!["mfa".to_owned(), "add".to_owned()]
}

/// `tsh mfa rm <name>` — remove the named MFA device.
#[must_use]
pub fn mfa_rm(name: &str) -> Vec<String> {
    vec!["mfa".to_owned(), "rm".to_owned(), name.to_owned()]
}

/// `tsh join <session-id>` — join a live session in the terminal.
#[must_use]
pub fn join(session_id: &str) -> Vec<String> {
    vec!["join".to_owned(), session_id.to_owned()]
}

/// `tsh play <session-id>` — replay a recorded session in the terminal.
#[must_use]
pub fn play(session_id: &str) -> Vec<String> {
    vec!["play".to_owned(), session_id.to_owned()]
}

/// `tsh request drop <id>` — drop a previously assumed access request, reverting
/// the elevated access it granted.
#[must_use]
pub fn request_drop(id: &str) -> Vec<String> {
    vec!["request".to_owned(), "drop".to_owned(), id.to_owned()]
}

/// `tsh request review (--approve|--deny) -c <cluster> <id>`.
#[must_use]
pub fn request_review(cluster: &str, id: &str, approve: bool) -> Vec<String> {
    let verdict = if approve { "--approve" } else { "--deny" };
    vec![
        "request".to_owned(),
        "review".to_owned(),
        verdict.to_owned(),
        "-c".to_owned(),
        cluster.to_owned(),
        id.to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_omits_empty_and_drops_sso_connector() {
        assert_eq!(login("", "", "", ""), vec!["login"]);
        assert_eq!(
            login("proxy.example.com", "alice", "local", "otp"),
            vec![
                "login",
                "--proxy=proxy.example.com",
                "--user=alice",
                "--auth=local",
                "--mfa-mode=otp",
            ]
        );
        // sso has no connector value → no --auth.
        assert_eq!(
            login("proxy.example.com", "", "sso", ""),
            vec!["login", "--proxy=proxy.example.com"]
        );
    }

    #[test]
    fn ssh_and_db_shapes() {
        assert_eq!(
            ssh("root.example.com", "admin", "node-01"),
            vec!["ssh", "-c", "root.example.com", "admin@node-01"]
        );
        assert_eq!(
            db_connect("root", "pg", ""),
            vec!["db", "connect", "-c", "root", "pg"]
        );
        assert_eq!(
            db_connect("root", "pg", "reader"),
            vec!["db", "connect", "-c", "root", "pg", "--db-user=reader"]
        );
    }

    #[test]
    fn ssh_full_forward_tunnel_and_command() {
        // Plain: same shape as `ssh`.
        assert_eq!(
            ssh_full("root", "admin", "node-01", "", false, ""),
            vec!["ssh", "-c", "root", "admin@node-01"]
        );
        // Pure tunnel: -L before host, -N added (no command).
        assert_eq!(
            ssh_full("root", "admin", "node-01", "8080:localhost:80", true, ""),
            vec![
                "ssh",
                "-c",
                "root",
                "-L",
                "8080:localhost:80",
                "-N",
                "admin@node-01"
            ]
        );
        // A command suppresses -N even if tunnel_only is set, and is appended last.
        assert_eq!(
            ssh_full(
                "root",
                "admin",
                "node-01",
                "8080:localhost:80",
                true,
                "uptime"
            ),
            vec![
                "ssh",
                "-c",
                "root",
                "-L",
                "8080:localhost:80",
                "admin@node-01",
                "uptime"
            ]
        );
        // Blank user omits the login (tsh default).
        assert_eq!(
            ssh_full("root", "", "node-01", "", false, ""),
            vec!["ssh", "-c", "root", "node-01"]
        );
    }

    #[test]
    fn scp_direction_and_recursion() {
        // Download: remote → local, recursive.
        assert_eq!(
            scp(
                "root",
                "alice",
                "node-01",
                "/etc/hosts",
                "./hosts",
                true,
                true
            ),
            vec![
                "scp",
                "-c",
                "root",
                "-r",
                "alice@node-01:/etc/hosts",
                "./hosts"
            ]
        );
        // Upload: local → remote, no login prefix, non-recursive.
        assert_eq!(
            scp("root", "", "node-01", "/tmp/x", "./x", false, false),
            vec!["scp", "-c", "root", "./x", "node-01:/tmp/x"]
        );
    }

    #[test]
    fn request_shapes() {
        assert_eq!(
            request_show("root", "abc-123"),
            vec!["request", "show", "-c", "root", "abc-123"]
        );
        assert_eq!(
            request_create("root", "dba,sre"),
            vec!["request", "create", "-c", "root", "--roles=dba,sre"]
        );
        assert_eq!(
            request_review("root", "abc-123", true),
            vec!["request", "review", "--approve", "-c", "root", "abc-123"]
        );
        assert_eq!(
            request_review("root", "abc-123", false),
            vec!["request", "review", "--deny", "-c", "root", "abc-123"]
        );
        assert_eq!(request_drop("abc-123"), vec!["request", "drop", "abc-123"]);
    }

    #[test]
    fn kube_login_and_exec_shapes() {
        assert_eq!(
            kube_login("root", "prod"),
            vec!["kube", "login", "-c", "root", "prod"]
        );
        // Bare command, no container/namespace.
        assert_eq!(
            kube_exec("api-0", &["sh".to_owned()], "", ""),
            vec!["kube", "exec", "--", "api-0", "sh"]
        );
        // Container + namespace + multi-token command with a leading-dash arg
        // (protected by the `--` separator).
        assert_eq!(
            kube_exec("api-0", &["ls".to_owned(), "-la".to_owned()], "app", "prod"),
            vec![
                "kube",
                "exec",
                "--container=app",
                "--namespace=prod",
                "--",
                "api-0",
                "ls",
                "-la"
            ]
        );
    }

    #[test]
    fn db_and_app_cert_lifecycle_shapes() {
        assert_eq!(
            db_login("root", "pg", ""),
            vec!["db", "login", "-c", "root", "pg"]
        );
        assert_eq!(
            db_login("root", "pg", "reader"),
            vec!["db", "login", "-c", "root", "--db-user=reader", "pg"]
        );
        assert_eq!(
            db_logout("root", "pg"),
            vec!["db", "logout", "-c", "root", "pg"]
        );
        assert_eq!(
            app_login("root", "grafana"),
            vec!["apps", "login", "-c", "root", "grafana"]
        );
        assert_eq!(
            app_logout("root", "grafana"),
            vec!["apps", "logout", "-c", "root", "grafana"]
        );
    }

    #[test]
    fn mfa_and_play_shapes() {
        assert_eq!(mfa_add(), vec!["mfa", "add"]);
        assert_eq!(mfa_rm("yubikey"), vec!["mfa", "rm", "yubikey"]);
        assert_eq!(play("sid-1"), vec!["play", "sid-1"]);
        assert_eq!(join("sid-1"), vec!["join", "sid-1"]);
    }
}
