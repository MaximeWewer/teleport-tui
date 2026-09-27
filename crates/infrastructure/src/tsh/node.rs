//! `tsh ls` → SSH nodes. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`run_json`, `run_scoped_ls`,
//! `classify_failure`, `sorted_labels`, `MetaDto`) and imports come via `super::*`.

#![allow(clippy::question_mark, clippy::wildcard_imports)]
use super::*;

#[derive(Debug, DeJson)]
struct NodeDto {
    metadata: NodeMetaDto,
    spec: NodeSpecDto,
}

#[derive(Debug, DeJson)]
struct NodeMetaDto {
    name: String,
    #[nserde(default)]
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, DeJson)]
struct NodeSpecDto {
    hostname: String,
    #[nserde(default)]
    addr: String,
}

#[derive(Debug, Clone)]
pub struct TshNodeRepository<R: CommandRunner> {
    runner: R,
    tsh: PathBuf,
}

impl<R: CommandRunner> TshNodeRepository<R> {
    pub fn new(runner: R, tsh: PathBuf) -> Self {
        Self { runner, tsh }
    }
}

impl<R: CommandRunner> NodeRepository for TshNodeRepository<R> {
    fn list_nodes(&self, ctx: &ClusterContext) -> Result<Vec<SshNode>, DomainError> {
        if !ctx.is_online() {
            return Err(DomainError::ClusterOffline {
                cluster: ctx.name.to_string(),
            });
        }
        // Cluster name comes from a validated value object cross-checked against
        // the real topology, so it is safe to pass as `-c`.
        let stdout = run_json(
            &self.runner,
            &self.tsh,
            vec![
                "ls".into(),
                "--format=json".into(),
                "-c".into(),
                ctx.name.to_string(),
            ],
        )?;
        parse_nodes(&stdout)
    }
}

fn parse_nodes(stdout: &str) -> Result<Vec<SshNode>, DomainError> {
    let dtos: Vec<NodeDto> = DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
        detail: e.to_string(),
    })?;
    let mut nodes = Vec::with_capacity(dtos.len());
    for dto in dtos {
        // One row with a hostname we refuse (e.g. a leading `-`) is skipped, not
        // fatal: it must not blank the whole list.
        let Ok(hostname) = Hostname::try_from(dto.spec.hostname) else {
            continue;
        };
        let mut labels: Vec<(String, String)> = dto
            .metadata
            .labels
            .unwrap_or_default()
            .into_iter()
            .collect();
        labels.sort();
        nodes.push(SshNode {
            id: dto.metadata.name,
            hostname,
            address: dto.spec.addr,
            labels,
        });
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_nodes_fixture() {
        let stdout = include_str!("../../tests/fixtures/nodes.json");
        let nodes = parse_nodes(stdout).unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(!nodes[0].hostname.as_str().is_empty());
        assert!(nodes[0].matches("linux") || nodes[1].matches("linux"));
    }

    #[test]
    fn skips_nodes_with_invalid_hostnames() {
        let nodes = parse_nodes(
            r#"[{"metadata":{"name":"a"},"spec":{"hostname":"-x"}},
                {"metadata":{"name":"b"},"spec":{"hostname":"_x"}},
                {"metadata":{"name":"c"},"spec":{"hostname":"web-01"}}]"#,
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].hostname.as_str(), "web-01");
    }
}
