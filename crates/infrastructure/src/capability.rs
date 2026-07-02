//! `tsh` capability probe: parses `tsh help` once to learn which top-level
//! commands the installed binary supports. Runtime detection — an old `tsh`
//! exposes fewer commands than a recent one, regardless of the host OS.

use std::path::PathBuf;

use domain::capability::Capabilities;
use domain::port::CapabilityProbe;

use crate::process::{CommandRequest, CommandRunner};

#[derive(Debug, Clone)]
pub struct TshCapabilityProbe<R: CommandRunner> {
    runner: R,
    tsh: PathBuf,
}

impl<R: CommandRunner> TshCapabilityProbe<R> {
    pub fn new(runner: R, tsh: PathBuf) -> Self {
        Self { runner, tsh }
    }
}

impl<R: CommandRunner> CapabilityProbe for TshCapabilityProbe<R> {
    fn probe(&self) -> Capabilities {
        let req = CommandRequest::new(self.tsh.clone(), vec!["help".to_owned()]);
        // Any failure → permissive: never hide features because detection broke.
        let Ok(outcome) = self.runner.run(&req) else {
            return Capabilities::unknown();
        };
        // `tsh help` prints usage to stdout; some shells route it to stderr.
        let text = if outcome.stdout.trim().is_empty() {
            &outcome.stderr
        } else {
            &outcome.stdout
        };
        parse_commands(text)
    }
}

/// Extract top-level command names from `tsh help` output.
///
/// Kingpin-style help lists each command on a lightly-indented line (1–3 spaces)
/// with the command name first; descriptions are indented further. We take the
/// first token of those command lines. An empty result → permissive fallback.
fn parse_commands(help: &str) -> Capabilities {
    let mut cmds = Vec::new();
    for line in help.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if !(1..=3).contains(&indent) {
            continue; // 0 = headers/usage, ≥4 = wrapped descriptions
        }
        let Some(token) = trimmed.split_whitespace().next() else {
            continue;
        };
        // Command names are lowercase ascii words (optionally hyphenated).
        if !token.is_empty() && token.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
            cmds.push(token.to_owned());
        }
    }
    if cmds.is_empty() {
        Capabilities::unknown()
    } else {
        Capabilities::probed(cmds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELP: &str = "\
usage: tsh [<flags>] <command> [<args> ...]

Gravitational Teleport client tool.

Commands:
  help [<command>...]
    Show help.

  ssh [<flags>] <[user@]host> [<command>...]
    Run shell or execute a command on a remote SSH node.

  ls [<flags>] [<labels>]
    List remote SSH nodes.

  kube login [<flags>] <kube-cluster>
    Login to a kubernetes cluster.

  scp [<flags>] <from, to>...
    Transfer files to a remote SSH node.
";

    #[test]
    fn parses_top_level_commands() {
        let caps = parse_commands(HELP);
        assert!(caps.is_probed());
        assert!(caps.supports("ssh"));
        assert!(caps.supports("ls"));
        assert!(caps.supports("kube")); // first token of "kube login"
        assert!(caps.supports("scp"));
        // A command the help never lists is absent.
        assert!(!caps.supports("vnet"));
    }

    #[test]
    fn empty_or_garbage_is_permissive() {
        assert!(!parse_commands("").is_probed());
        assert!(parse_commands("no commands here at all\n").supports("kube"));
    }
}
