//! Pure builders for the `tsh` argv vectors the TUI runs itself.
//!
//! They cover the *interactive* commands it hands the terminal to (login, ssh,
//! db connect, scp, requests, logout) and the *background* local proxies /
//! forwards it spawns (`tsh proxy app|db|kube`, `tsh ssh -L … -N`).
//!
//! These live in the application layer, not infrastructure: they perform **no
//! I/O** - they only assemble the argv; the presentation layer hands it to the
//! terminal or spawns it. Keeping them here
//! means the TUI orchestrates interactive commands through the application
//! layer rather than reaching into `infrastructure`. The *read-path* argv (the
//! commands infrastructure actually *executes* via the command runner) stays in
//! `infrastructure::tsh`/`tctl`, next to the I/O it drives.
//!
//! SECURITY: every argument is a discrete argv element - execution is argv-only,
//! never a shell. Identifiers arrive as domain newtypes (`ClusterName`,
//! `Hostname`, `Login`, `ResourceName`, ...), whose constructors already reject
//! empty and flag-like (leading `-`) values, so a positional slot can't be turned
//! into an option. The remaining `&str` values (forward spec, remote command,
//! scp paths) are checked by the TUI's form validators. These functions add no
//! validation, only assembly. Value-bearing flags use the `--flag=value` form so
//! a value can never be reparsed as a separate option.

use domain::auth::{AuthMethod, MfaMode};
use domain::value::{
    ClusterName, DeviceName, Hostname, Identifier, Login, RequestId, ResourceName, RoleList,
    SessionId,
};

/// `tsh login [--proxy=…] [--user=…] [--auth=…] [--mfa-mode=…]`. An absent
/// option omits its flag, as does [`AuthMethod::Sso`] (the default SSO flow
/// drives the browser and takes no `--auth` value).
#[must_use]
pub fn login(
    proxy: Option<&Identifier>,
    user: Option<&Identifier>,
    auth: Option<&AuthMethod>,
    mfa: Option<MfaMode>,
) -> Vec<String> {
    let mut args = vec!["login".to_owned()];
    if let Some(proxy) = proxy {
        args.push(format!("--proxy={proxy}"));
    }
    if let Some(user) = user {
        args.push(format!("--user={user}"));
    }
    if let Some(auth) = auth.and_then(AuthMethod::flag_value) {
        args.push(format!("--auth={auth}"));
    }
    if let Some(mfa) = mfa {
        args.push(format!("--mfa-mode={mfa}"));
    }
    args
}

/// `tsh logout`.
#[must_use]
pub fn logout() -> Vec<String> {
    vec!["logout".to_owned()]
}

/// `tsh ssh --cluster=<cluster> <user>@<host>`.
#[must_use]
pub fn ssh(cluster: &ClusterName, user: &Login, host: &Hostname) -> Vec<String> {
    vec![
        "ssh".to_owned(),
        format!("--cluster={cluster}"),
        format!("{user}@{host}"),
    ]
}

/// `tsh ssh --cluster=<cluster> [--forward=<spec>] [-N] [<user>@]<host> [<command>]`.
///
/// Extends [`ssh`] with the options form's extras: no `user` omits the login
/// (tsh's default); a blank `forward` omits `--forward`; `-N` (tunnel only, no remote
/// shell) is emitted **only** for a pure forward - a `--forward` with no `command` and
/// `tunnel_only` set. A non-empty `command` is appended as a single argv element
/// (the remote shell parses it, as with plain `ssh host cmd`).
#[must_use]
pub fn ssh_full(
    cluster: &ClusterName,
    user: Option<&Login>,
    host: &Hostname,
    forward: &str,
    tunnel_only: bool,
    command: &str,
) -> Vec<String> {
    let mut args = vec!["ssh".to_owned(), format!("--cluster={cluster}")];
    if !forward.is_empty() {
        args.push(format!("--forward={forward}"));
    }
    if tunnel_only && !forward.is_empty() && command.is_empty() {
        args.push("-N".to_owned());
    }
    args.push(user.map_or_else(|| host.to_string(), |u| format!("{u}@{host}")));
    if !command.is_empty() {
        args.push(command.to_owned());
    }
    args
}

/// `tsh db connect --cluster=<cluster> <name> [--db-user=<user>]`. No `db_user` lets
/// tsh pick the default user (no flag).
#[must_use]
pub fn db_connect(
    cluster: &ClusterName,
    name: &ResourceName,
    db_user: Option<&Identifier>,
) -> Vec<String> {
    let mut args = vec![
        "db".to_owned(),
        "connect".to_owned(),
        format!("--cluster={cluster}"),
        name.to_string(),
    ];
    if let Some(db_user) = db_user {
        args.push(format!("--db-user={db_user}"));
    }
    args
}

/// `tsh scp --cluster=<cluster> [-r] <from> <to>`, where one endpoint is the remote
/// spec `[login@]host:path` and the direction decides the from/to order.
#[must_use]
pub fn scp(
    cluster: &ClusterName,
    login: Option<&Login>,
    host: &Hostname,
    remote_path: &str,
    local_path: &str,
    download: bool,
    recursive: bool,
) -> Vec<String> {
    let remote_spec = login.map_or_else(
        || format!("{host}:{remote_path}"),
        |l| format!("{l}@{host}:{remote_path}"),
    );
    let mut args = vec!["scp".to_owned(), format!("--cluster={cluster}")];
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

/// `tsh db login --cluster=<cluster> [--db-user=<user>] <name>`.
///
/// Retrieves a database certificate (no interactive shell; the cert lands in
/// `~/.tsh`). No `db_user` lets tsh use the database's own default user.
#[must_use]
pub fn db_login(
    cluster: &ClusterName,
    name: &ResourceName,
    db_user: Option<&Identifier>,
) -> Vec<String> {
    let mut args = vec![
        "db".to_owned(),
        "login".to_owned(),
        format!("--cluster={cluster}"),
    ];
    if let Some(db_user) = db_user {
        args.push(format!("--db-user={db_user}"));
    }
    args.push(name.to_string());
    args
}

/// `tsh db logout --cluster=<cluster> <name>` - remove a database's stored credentials.
#[must_use]
pub fn db_logout(cluster: &ClusterName, name: &ResourceName) -> Vec<String> {
    vec![
        "db".to_owned(),
        "logout".to_owned(),
        format!("--cluster={cluster}"),
        name.to_string(),
    ]
}

/// `tsh apps login --cluster=<cluster> <name>` - retrieve a short-lived app certificate.
#[must_use]
pub fn app_login(cluster: &ClusterName, name: &ResourceName) -> Vec<String> {
    vec![
        "apps".to_owned(),
        "login".to_owned(),
        format!("--cluster={cluster}"),
        name.to_string(),
    ]
}

/// `tsh apps logout --cluster=<cluster> <name>` - remove a stored app certificate.
#[must_use]
pub fn app_logout(cluster: &ClusterName, name: &ResourceName) -> Vec<String> {
    vec![
        "apps".to_owned(),
        "logout".to_owned(),
        format!("--cluster={cluster}"),
        name.to_string(),
    ]
}

/// `tsh kube login --cluster=<cluster> <kube>` - make `kube` the active Kubernetes
/// context, a prerequisite for `tsh kube exec` (which has no cluster flag).
#[must_use]
pub fn kube_login(cluster: &ClusterName, kube: &ResourceName) -> Vec<String> {
    vec![
        "kube".to_owned(),
        "login".to_owned(),
        format!("--cluster={cluster}"),
        kube.to_string(),
    ]
}

/// `tsh kube exec [--container=…] [--namespace=…] -- <pod> <command…>`.
///
/// Runs a command in a pod of the *current* kube context (set by
/// [`kube_login`]). The `--` ends flag parsing so a command with leading-dash
/// args is passed through verbatim. `command` is the already-tokenised argv. An
/// absent container/namespace omits its flag.
#[must_use]
pub fn kube_exec(
    pod: &Identifier,
    command: &[String],
    container: Option<&Identifier>,
    namespace: Option<&Identifier>,
) -> Vec<String> {
    let mut args = vec!["kube".to_owned(), "exec".to_owned()];
    if let Some(container) = container {
        args.push(format!("--container={container}"));
    }
    if let Some(namespace) = namespace {
        args.push(format!("--namespace={namespace}"));
    }
    args.push("--".to_owned());
    args.push(pod.to_string());
    args.extend(command.iter().cloned());
    args
}

/// `tsh request show --cluster=<cluster> <id>`.
#[must_use]
pub fn request_show(cluster: &ClusterName, id: &RequestId) -> Vec<String> {
    vec![
        "request".to_owned(),
        "show".to_owned(),
        format!("--cluster={cluster}"),
        id.to_string(),
    ]
}

/// `tsh request create --cluster=<cluster> --roles=<roles>`.
#[must_use]
pub fn request_create(cluster: &ClusterName, roles: &RoleList) -> Vec<String> {
    vec![
        "request".to_owned(),
        "create".to_owned(),
        format!("--cluster={cluster}"),
        format!("--roles={roles}"),
    ]
}

/// `tsh mfa add` - interactively register a new MFA device (tsh prompts for the
/// name/type and drives the authenticator in the terminal).
#[must_use]
pub fn mfa_add() -> Vec<String> {
    vec!["mfa".to_owned(), "add".to_owned()]
}

/// `tsh mfa rm <name>` - remove the named MFA device.
#[must_use]
pub fn mfa_rm(name: &DeviceName) -> Vec<String> {
    vec!["mfa".to_owned(), "rm".to_owned(), name.to_string()]
}

/// `tsh join <session-id>` - join a live session in the terminal.
#[must_use]
pub fn join(session_id: &SessionId) -> Vec<String> {
    vec!["join".to_owned(), session_id.to_string()]
}

/// `tsh play <session-id>` - replay a recorded session in the terminal.
#[must_use]
pub fn play(session_id: &SessionId) -> Vec<String> {
    vec!["play".to_owned(), session_id.to_string()]
}

/// `tsh request drop <id>` - drop a previously assumed access request, reverting
/// the elevated access it granted.
#[must_use]
pub fn request_drop(id: &RequestId) -> Vec<String> {
    vec!["request".to_owned(), "drop".to_owned(), id.to_string()]
}

/// `tsh request review (--approve|--deny) --cluster=<cluster> <id>`.
#[must_use]
pub fn request_review(cluster: &ClusterName, id: &RequestId, approve: bool) -> Vec<String> {
    let verdict = if approve { "--approve" } else { "--deny" };
    vec![
        "request".to_owned(),
        "review".to_owned(),
        verdict.to_owned(),
        format!("--cluster={cluster}"),
        id.to_string(),
    ]
}

/// `tsh proxy app <name> --cluster=<cluster> --port=<port>` - a background local
/// proxy for an app behind an L7 load balancer.
#[must_use]
pub fn proxy_app(cluster: &ClusterName, name: &ResourceName, port: u16) -> Vec<String> {
    vec![
        "proxy".to_owned(),
        "app".to_owned(),
        name.to_string(),
        format!("--cluster={cluster}"),
        format!("--port={port}"),
    ]
}

/// `tsh proxy db <name> --cluster=<cluster> --tunnel --port=<port>` - a background
/// authenticated tunnel a GUI client connects to without extra credentials.
#[must_use]
pub fn proxy_db(cluster: &ClusterName, name: &ResourceName, port: u16) -> Vec<String> {
    vec![
        "proxy".to_owned(),
        "db".to_owned(),
        name.to_string(),
        format!("--cluster={cluster}"),
        "--tunnel".to_owned(),
        format!("--port={port}"),
    ]
}

/// `tsh proxy kube <kube> --cluster=<cluster> --port=<port> [--as=<user>]` - a
/// background kube proxy that prints the `KUBECONFIG` to use. No `user` keeps
/// the role's default impersonation.
#[must_use]
pub fn proxy_kube(
    cluster: &ClusterName,
    kube: &ResourceName,
    user: Option<&Identifier>,
    port: u16,
) -> Vec<String> {
    let mut args = vec![
        "proxy".to_owned(),
        "kube".to_owned(),
        kube.to_string(),
        format!("--cluster={cluster}"),
        format!("--port={port}"),
    ];
    if let Some(user) = user {
        args.push(format!("--as={user}"));
    }
    args
}

/// A background SSH local port-forward with no remote shell: [`ssh_full`] with
/// `-L <spec> -N` and no command.
#[must_use]
pub fn ssh_forward(
    cluster: &ClusterName,
    user: Option<&Login>,
    host: &Hostname,
    spec: &str,
) -> Vec<String> {
    ssh_full(cluster, user, host, spec, true, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> ClusterName {
        ClusterName::try_from(s).unwrap()
    }
    fn h(s: &str) -> Hostname {
        Hostname::try_from(s).unwrap()
    }
    fn l(s: &str) -> Login {
        Login::try_from(s).unwrap()
    }
    fn r(s: &str) -> ResourceName {
        ResourceName::try_from(s).unwrap()
    }
    fn i(s: &str) -> Identifier {
        Identifier::try_from(s).unwrap()
    }
    fn id(s: &str) -> RequestId {
        RequestId::try_from(s).unwrap()
    }
    fn sid(s: &str) -> SessionId {
        SessionId::try_from(s).unwrap()
    }

    #[test]
    fn login_omits_empty_and_drops_sso_connector() {
        assert_eq!(login(None, None, None, None), vec!["login"]);
        assert_eq!(
            login(
                Some(&i("proxy.example.com")),
                Some(&i("alice")),
                Some(&AuthMethod::Local),
                Some(MfaMode::Otp)
            ),
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
            login(
                Some(&i("proxy.example.com")),
                None,
                Some(&AuthMethod::Sso),
                None
            ),
            vec!["login", "--proxy=proxy.example.com"]
        );
        // A named connector is passed through; MFA uses tsh's own spelling.
        assert_eq!(
            login(
                None,
                None,
                Some(&AuthMethod::try_from("okta").unwrap()),
                Some(MfaMode::CrossPlatform)
            ),
            vec!["login", "--auth=okta", "--mfa-mode=cross-platform"]
        );
    }

    #[test]
    fn ssh_and_db_shapes() {
        assert_eq!(
            ssh(&c("root.example.com"), &l("admin"), &h("node-01")),
            vec!["ssh", "--cluster=root.example.com", "admin@node-01"]
        );
        assert_eq!(
            db_connect(&c("root"), &r("pg"), None),
            vec!["db", "connect", "--cluster=root", "pg"]
        );
        assert_eq!(
            db_connect(&c("root"), &r("pg"), Some(&i("reader"))),
            vec!["db", "connect", "--cluster=root", "pg", "--db-user=reader"]
        );
    }

    #[test]
    fn ssh_full_forward_tunnel_and_command() {
        let (root, admin, node) = (c("root"), l("admin"), h("node-01"));
        // Plain: same shape as `ssh`.
        assert_eq!(
            ssh_full(&root, Some(&admin), &node, "", false, ""),
            vec!["ssh", "--cluster=root", "admin@node-01"]
        );
        // Pure tunnel: -L before host, -N added (no command).
        assert_eq!(
            ssh_full(&root, Some(&admin), &node, "8080:localhost:80", true, ""),
            vec![
                "ssh",
                "--cluster=root",
                "--forward=8080:localhost:80",
                "-N",
                "admin@node-01"
            ]
        );
        // A command suppresses -N even if tunnel_only is set, and is appended last.
        assert_eq!(
            ssh_full(
                &root,
                Some(&admin),
                &node,
                "8080:localhost:80",
                true,
                "uptime"
            ),
            vec![
                "ssh",
                "--cluster=root",
                "--forward=8080:localhost:80",
                "admin@node-01",
                "uptime"
            ]
        );
        // No user omits the login (tsh default).
        assert_eq!(
            ssh_full(&root, None, &node, "", false, ""),
            vec!["ssh", "--cluster=root", "node-01"]
        );
    }

    #[test]
    fn scp_direction_and_recursion() {
        // Download: remote → local, recursive.
        assert_eq!(
            scp(
                &c("root"),
                Some(&l("alice")),
                &h("node-01"),
                "/etc/hosts",
                "./hosts",
                true,
                true
            ),
            vec![
                "scp",
                "--cluster=root",
                "-r",
                "alice@node-01:/etc/hosts",
                "./hosts"
            ]
        );
        // Upload: local → remote, no login prefix, non-recursive.
        assert_eq!(
            scp(
                &c("root"),
                None,
                &h("node-01"),
                "/tmp/x",
                "./x",
                false,
                false
            ),
            vec!["scp", "--cluster=root", "./x", "node-01:/tmp/x"]
        );
    }

    #[test]
    fn request_shapes() {
        let root = c("root");
        assert_eq!(
            request_show(&root, &id("abc-123")),
            vec!["request", "show", "--cluster=root", "abc-123"]
        );
        assert_eq!(
            request_create(&root, &RoleList::try_from("dba,sre").unwrap()),
            vec!["request", "create", "--cluster=root", "--roles=dba,sre"]
        );
        assert_eq!(
            request_review(&root, &id("abc-123"), true),
            vec![
                "request",
                "review",
                "--approve",
                "--cluster=root",
                "abc-123"
            ]
        );
        assert_eq!(
            request_review(&root, &id("abc-123"), false),
            vec!["request", "review", "--deny", "--cluster=root", "abc-123"]
        );
        assert_eq!(
            request_drop(&id("abc-123")),
            vec!["request", "drop", "abc-123"]
        );
    }

    #[test]
    fn kube_login_and_exec_shapes() {
        assert_eq!(
            kube_login(&c("root"), &r("prod")),
            vec!["kube", "login", "--cluster=root", "prod"]
        );
        // Bare command, no container/namespace.
        assert_eq!(
            kube_exec(&i("api-0"), &["sh".to_owned()], None, None),
            vec!["kube", "exec", "--", "api-0", "sh"]
        );
        // Container + namespace + multi-token command with a leading-dash arg
        // (protected by the `--` separator).
        assert_eq!(
            kube_exec(
                &i("api-0"),
                &["ls".to_owned(), "-la".to_owned()],
                Some(&i("app")),
                Some(&i("prod"))
            ),
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
        let root = c("root");
        assert_eq!(
            db_login(&root, &r("pg"), None),
            vec!["db", "login", "--cluster=root", "pg"]
        );
        assert_eq!(
            db_login(&root, &r("pg"), Some(&i("reader"))),
            vec!["db", "login", "--cluster=root", "--db-user=reader", "pg"]
        );
        assert_eq!(
            db_logout(&root, &r("pg")),
            vec!["db", "logout", "--cluster=root", "pg"]
        );
        assert_eq!(
            app_login(&root, &r("grafana")),
            vec!["apps", "login", "--cluster=root", "grafana"]
        );
        assert_eq!(
            app_logout(&root, &r("grafana")),
            vec!["apps", "logout", "--cluster=root", "grafana"]
        );
    }

    #[test]
    fn mfa_and_play_shapes() {
        assert_eq!(mfa_add(), vec!["mfa", "add"]);
        assert_eq!(
            mfa_rm(&DeviceName::try_from("my yubikey").unwrap()),
            vec!["mfa", "rm", "my yubikey"]
        );
        assert_eq!(play(&sid("sid-1")), vec!["play", "sid-1"]);
        assert_eq!(join(&sid("sid-1")), vec!["join", "sid-1"]);
    }

    #[test]
    fn background_proxy_shapes() {
        let root = c("root");
        assert_eq!(
            proxy_app(&root, &r("grafana"), 8080),
            vec!["proxy", "app", "grafana", "--cluster=root", "--port=8080"]
        );
        assert_eq!(
            proxy_db(&root, &r("pg"), 5432),
            vec![
                "proxy",
                "db",
                "pg",
                "--cluster=root",
                "--tunnel",
                "--port=5432"
            ]
        );
        assert_eq!(
            proxy_kube(&root, &r("prod"), None, 9000),
            vec!["proxy", "kube", "prod", "--cluster=root", "--port=9000"]
        );
        assert_eq!(
            proxy_kube(&root, &r("prod"), Some(&i("system:admin")), 9000),
            vec![
                "proxy",
                "kube",
                "prod",
                "--cluster=root",
                "--port=9000",
                "--as=system:admin"
            ]
        );
        assert_eq!(
            ssh_forward(&root, None, &h("node-01"), "8080:localhost:80"),
            vec![
                "ssh",
                "--cluster=root",
                "--forward=8080:localhost:80",
                "-N",
                "node-01"
            ]
        );
    }
}
