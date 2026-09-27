//! `tsh clusters` → root/leaf topology. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`TshCli`, `tsh_adapter!`, `parse_json`, `sorted_labels`,
//! `MetaDto`) come from `super`.

#![allow(clippy::question_mark)]

use domain::cluster::{ClusterContext, ClusterKind, ClusterStatus, ClusterTopology};
use domain::error::DomainError;
use domain::port::ClusterRepository;
use domain::value::ClusterName;
use nanoserde::DeJson;

use super::{args, parse_json};
use crate::process::CommandRunner;

#[derive(Debug, DeJson)]
struct ClusterDto {
    cluster_name: String,
    status: String,
    cluster_type: String,
    selected: bool,
}

tsh_adapter!(TshClusterRepository);

impl<R: CommandRunner> ClusterRepository for TshClusterRepository<R> {
    fn list_clusters(&self) -> Result<ClusterTopology, DomainError> {
        let stdout = self.cli.run(args(&["clusters", "--format=json"]))?;
        let dtos: Vec<ClusterDto> = parse_json(&stdout)?;

        let mut selected: Option<ClusterName> = None;
        let mut contexts = Vec::with_capacity(dtos.len());
        for dto in dtos {
            // Skip (don't fail on) a row whose name we refuse: one odd entry must
            // not blank the whole list.
            let Ok(name) = ClusterName::try_from(dto.cluster_name) else {
                continue;
            };
            let kind = parse_kind(&dto.cluster_type)?;
            let status = parse_status(&dto.status);
            if dto.selected {
                selected = Some(name.clone());
            }
            contexts.push(ClusterContext { name, kind, status });
        }
        ClusterTopology::new(contexts, selected.as_ref())
    }
}

fn parse_kind(s: &str) -> Result<ClusterKind, DomainError> {
    match s {
        "root" => Ok(ClusterKind::Root),
        "leaf" => Ok(ClusterKind::Leaf),
        other => Err(DomainError::Parse {
            detail: format!("unknown cluster_type `{other}`"),
        }),
    }
}

const fn parse_status(s: &str) -> ClusterStatus {
    if s.eq_ignore_ascii_case("online") {
        ClusterStatus::Online
    } else {
        ClusterStatus::Offline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{CommandOutcome, CommandRequest};
    use std::io;
    use std::path::PathBuf;

    #[derive(Debug)]
    struct FakeRunner {
        stdout: String,
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, _req: &CommandRequest) -> io::Result<CommandOutcome> {
            Ok(CommandOutcome {
                status: Some(0),
                stdout: self.stdout.clone(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn parses_clusters_fixture_root_and_leaves() {
        let runner = FakeRunner {
            stdout: include_str!("../../tests/fixtures/clusters.json").to_owned(),
        };
        let repo = TshClusterRepository::new(runner, PathBuf::from("tsh"));
        let topo = repo.list_clusters().unwrap();
        assert_eq!(topo.all().count(), 5);
        assert_eq!(topo.root().name.as_str(), "root.example.com");
        assert_eq!(topo.selected().name.as_str(), "root.example.com");
        assert_eq!(topo.leaves().count(), 4);
    }

    #[test]
    fn skips_clusters_with_invalid_names() {
        let runner = FakeRunner {
            stdout: r#"[
                {"cluster_name":"root.example.com","status":"online","cluster_type":"root","selected":true},
                {"cluster_name":"leaf;rm -rf","status":"online","cluster_type":"leaf","selected":false},
                {"cluster_name":"leaf1","status":"offline","cluster_type":"leaf","selected":false}
            ]"#
            .to_owned(),
        };
        let repo = TshClusterRepository::new(runner, PathBuf::from("tsh"));
        let topo = repo.list_clusters().unwrap();
        assert_eq!(topo.all().count(), 2);
        assert_eq!(topo.leaves().next().unwrap().name.as_str(), "leaf1");
    }
}
