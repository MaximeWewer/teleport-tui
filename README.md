# teleport-tui

**One keyboard-driven dashboard over all your Teleport resources.** Browse, search and
connect to SSH nodes, Kubernetes clusters, databases and apps — across every cluster —
without leaving the terminal or remembering a single `tsh` flag.

`teleport-tui` is a fast Rust + [ratatui](https://github.com/ratatui/ratatui) front-end
for the Teleport client CLIs (`tsh`, `tctl`). It doesn't reimplement Teleport: it drives
the official binaries, turns their JSON output into live searchable tables, and hands the
terminal straight to `tsh` for the interactive parts (SSH sessions, MFA prompts,
`db connect`). You get the convenience of a UI with the exact behaviour, auth and RBAC of
the real client.

> Runs whatever `tsh`/`tctl` you already have installed and respects your existing login.
> `tctl` is optional — admin features simply appear when it's available.

## Why

Driving Teleport from the shell means long commands, per-cluster `-c` flags, copy-pasted
node names, and re-typing `db connect --db-user=…` every day. `teleport-tui` collapses
that into: open, arrow to the thing, press `Enter`.

## What it does

- **Everything in one place** — SSH nodes, Kubernetes, Databases, Apps, Access requests,
  session Recordings, and admin (Users, Roles, Tokens, Bots, Inventory) as searchable
  tables. Hit `/` to filter; `Enter` on an admin row shows every field in a popup.
- **Connect in one keystroke** — `Enter` opens an SSH session, `kube login`, `db connect`
  or `apps login`. Several logins available? It offers a picker. No flags to memorise.
- **All your clusters at once** — a switcher (`c`) jumps between root/leaf, or pick
  **All clusters** to see any tab aggregated across every online cluster in one view.
- **Port-forwards that don't block you** — the SSH options popup (`o`) builds a `-L`
  tunnel; a `-N` tunnel runs **in the background** and lands in a forwards list you manage
  with `F` (stop any of them anytime). Or fire a one-off command on a node and read its
  output before returning.
- **The rest of the toolbox** — `scp` transfers (`s`), `kube exec` into a pod (`e`), a
  background `proxy db` tunnel for your GUI database client (`P`), certificate login/logout
  (`l`/`u`), replay a session recording (`Enter`), list/join live sessions (`S`), and
  manage MFA devices (`M`).
- **Admin without the man page** — create/reset users, generate/remove join tokens; the
  token and invite URL are shown once and never written to disk or logs.
- **Adapts to you** — probes your `tsh`/`tctl` and hides tabs/actions the binary can't run
  or your role can't access. Mouse-wheel scrolling, a live status bar (user, logins, cert
  expiry), and defaults you can edit and persist (`p`).

## Secure by design

It's a front-end for a security product, so it behaves like one:

- Subprocesses are **argv vectors, never a shell** — no command injection. Every typed
  value (hostnames, logins, forward specs, commands…) is validated before it becomes an
  argument.
- Secrets are never logged: tokens and invite URLs are held zeroized and shown once;
  interactive secrets (passwords, MFA) go straight to `tsh`. Cluster output is stripped of
  control/ANSI sequences before it's displayed or logged.
- `#![forbid(unsafe_code)]`, no `unwrap`/`panic` in the codebase, subprocess timeouts, and
  a strict clippy gate enforced in CI on Linux, macOS and Windows.

## Install & run

**Runs on Linux, macOS and Windows** — config, state and binary paths are resolved
per-OS, and CI builds and tests on all three.

```bash
cargo run --release
# or build the binary:
cargo build --release && ./target/release/teleport-tui
```

Needs Rust 1.95+ (pinned via `rust-toolchain.toml`) and `tsh` on your `PATH`.

## Keybindings

Actions are context-sensitive (tab + selection) and gated by capabilities/rights; press
`?` in-app for the live keymap of what's reachable on your install.

| Key | Action |
|-----|--------|
| `Tab` / `Shift-Tab`, `1`–`0` | switch tab (Recordings via `Tab` cycling) |
| `↑/↓` `j/k`, mouse wheel | move selection |
| `/` | incremental search |
| `Enter` | open (SSH/kube/db/app/request), admin row → detail popup, recording → replay |
| `c` | switch cluster (root/leaf) or **All clusters** aggregate |
| `r` | refresh current tab |
| `o` | SSH: options — `-L` forward, `-N` background tunnel, or a one-off command |
| `F` | list / stop active background SSH forwards |
| `s` | SSH: scp file/folder transfer |
| `e` | Kube: exec a command in a pod |
| `P` | Db: local proxy tunnel for a GUI client |
| `l` / `u` | Db/Apps: certificate login / logout |
| `S` / `M` | active sessions (list/join) / MFA devices (list/add/remove) |
| `a` / `d` / `D` / `n` | Requests: approve / deny / drop / new |
| `g` / `d` | Tokens: generate / remove join token |
| `n` / `R` | Users: new / reset selected |
| `L` / `O` | login / logout |
| `p` | settings |
| `?` | help |
| `q` / `Esc` | quit (or close the open popup) |

## Configuration

Everything works out of the box. For defaults, drop a `config.toml` in your per-OS config
dir — or just edit and save it from the Settings screen (`p`):

- **Linux** — `$XDG_CONFIG_HOME/teleport-tui/config.toml` (default `~/.config/…`)
- **macOS** — `~/Library/Application Support/teleport-tui/config.toml`
- **Windows** — `%APPDATA%\teleport-tui\config.toml`

```toml
# Override binary locations (otherwise resolved from PATH / known install dirs)
tsh_path  = "/usr/local/bin/tsh"
tctl_path = "/usr/local/bin/tctl"

# Auto-refresh the active tab every N seconds (omit or 0 to disable)
refresh_seconds = 30

# Default connection users (blank = let tsh/tctl choose)
default_login = "root"      # SSH login
kube_user     = "dev"       # tsh kube --as
db_user       = "readonly"  # tsh db connect --db-user

# Kubernetes launchers offered when opening a kube cluster (comma-separated).
# "shell" opens your $SHELL with $KUBECONFIG set; any other value runs that tool.
kube_tools = "shell,k9s"

# Login-form defaults
proxy = "root.example.com"
user  = "alice"
auth  = "local"   # "" | local | passwordless | sso
mfa   = "otp"     # "" | otp | webauthn | platform | sso | browser
```

## Logs

Structured errors are appended as JSON Lines to the per-OS state dir, so you can grep a
bad run:

- **Linux** — `$XDG_STATE_HOME/teleport-tui/errors.jsonl` (default `~/.local/state/…`)
- **macOS** — `~/Library/Logs/teleport-tui/errors.jsonl`
- **Windows** — `%LOCALAPPDATA%\teleport-tui\errors.jsonl`

```bash
jq 'select(.code=="CERT_EXPIRED")' ~/.local/state/teleport-tui/errors.jsonl
```

## Under the hood

Rust + ratatui, laid out as a hexagonal/DDD Cargo workspace (`domain` / `application` /
`infrastructure` / `tui`) so the core has zero knowledge of ratatui, `tsh` or JSON — which
keeps it testable and the CLI adapters swappable. Contributions welcome; the CI quality
gate runs on Linux/macOS/Windows:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check        # supply chain: advisories, licenses, sources
cargo machete           # no unused dependencies
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
```
