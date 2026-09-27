//! `tsh ls` → SSH nodes. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`TshCli`, `tsh_adapter!`, `parse_json`, `sorted_labels`,
//! `MetaDto`) come from `super`.

#![allow(clippy::question_mark)]

use domain::cluster::ClusterContext;
use domain::error::DomainError;
use domain::node::SshNode;
use domain::port::NodeRepository;
use domain::value::Hostname;
use nanoserde::DeJson;

use super::{MetaDto, parse_json, sorted_labels};
use crate::process::CommandRunner;

#[derive(Debug, DeJson)]
struct NodeDto {
    metadata: MetaDto,
    spec: NodeSpecDto,
}

#[derive(Debug, DeJson)]
struct NodeSpecDto {
    hostname: String,
    #[nserde(default)]
    addr: String,
}

tsh_adapter!(TshNodeRepository);

impl<R: CommandRunner> NodeRepository for TshNodeRepository<R> {
    fn list_nodes(&self, ctx: &ClusterContext) -> Result<Vec<SshNode>, DomainError> {
        // `tsh ls` has no noun: the verb is empty.
        let stdout = self.cli.ls(&[], ctx, true)?;
        parse_nodes(&stdout)
    }
}

fn parse_nodes(stdout: &str) -> Result<Vec<SshNode>, DomainError> {
    let dtos: Vec<NodeDto> = parse_json(stdout)?;
    let mut nodes = Vec::with_capacity(dtos.len());
    for dto in dtos {
        // One row with a hostname we refuse (e.g. a leading `-`) is skipped, not
        // fatal: it must not blank the whole list.
        let Ok(hostname) = Hostname::try_from(dto.spec.hostname) else {
            continue;
        };
        nodes.push(SshNode {
            id: dto.metadata.name,
            hostname,
            address: dto.spec.addr,
            labels: sorted_labels(dto.metadata.labels),
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
