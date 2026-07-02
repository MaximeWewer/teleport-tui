//! `tsh clusters` → root/leaf topology. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`run_json`, `run_scoped_ls`,
//! `classify_failure`, `sorted_labels`, `MetaDto`) and imports come via `super::*`.

#![allow(clippy::question_mark, clippy::wildcard_imports)]
use super::*;

#[derive(Debug, DeJson)]
struct ClusterDto {
    cluster_name: String,
    status: String,
    cluster_type: String,
    selected: bool,
}

#[derive(Debug, Clone)]
pub struct TshClusterRepository<R: CommandRunner> {
    runner: R,
    tsh: PathBuf,
}

impl<R: CommandRunner> TshClusterRepository<R> {
    pub fn new(runner: R, tsh: PathBuf) -> Self {
        Self { runner, tsh }
    }
}

impl<R: CommandRunner> ClusterRepository for TshClusterRepository<R> {
    fn list_clusters(&self) -> Result<ClusterTopology, DomainError> {
        let stdout = run_json(
            &self.runner,
            &self.tsh,
            vec!["clusters".into(), "--format=json".into()],
        )?;
        let dtos: Vec<ClusterDto> =
            DeJson::deserialize_json(&stdout).map_err(|e| DomainError::Parse {
                detail: e.to_string(),
            })?;

        let mut selected: Option<ClusterName> = None;
        let mut contexts = Vec::with_capacity(dtos.len());
        for dto in dtos {
            let name = ClusterName::try_from(dto.cluster_name)?;
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

fn parse_status(s: &str) -> ClusterStatus {
    if s.eq_ignore_ascii_case("online") {
        ClusterStatus::Online
    } else {
        ClusterStatus::Offline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::CommandOutcome;
    use std::io;

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
        assert_eq!(topo.all().len(), 5);
        assert_eq!(topo.root().name.as_str(), "root.example.com");
        assert_eq!(topo.selected().name.as_str(), "root.example.com");
        assert_eq!(topo.leaves().count(), 4);
    }
}
