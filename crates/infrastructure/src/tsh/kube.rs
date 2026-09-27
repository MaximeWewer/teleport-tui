//! `tsh kube ls` → Kubernetes clusters. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`TshCli`, `tsh_adapter!`, `parse_json`, `sorted_labels`,
//! `MetaDto`) come from `super`.

#![allow(clippy::question_mark)]

use std::collections::HashMap;

use domain::cluster::ClusterContext;
use domain::error::DomainError;
use domain::port::KubeRepository;
use domain::resource::KubeCluster;
use domain::value::ResourceName;
use nanoserde::DeJson;

use super::{parse_json, sorted_labels};
use crate::process::CommandRunner;

#[derive(Debug, DeJson)]
struct KubeDto {
    kube_cluster_name: String,
    #[nserde(default)]
    labels: Option<HashMap<String, String>>,
}

tsh_adapter!(TshKubeRepository);

impl<R: CommandRunner> KubeRepository for TshKubeRepository<R> {
    fn list_kube(&self, ctx: &ClusterContext) -> Result<Vec<KubeCluster>, DomainError> {
        let stdout = self.cli.ls(&["kube"], ctx, true)?;
        parse_kube(&stdout)
    }
}

fn parse_kube(stdout: &str) -> Result<Vec<KubeCluster>, DomainError> {
    let dtos: Vec<KubeDto> = parse_json(stdout)?;
    let mut out = Vec::with_capacity(dtos.len());
    for dto in dtos {
        // Skip (don't fail on) a row whose name we refuse: one odd entry must
        // not blank the whole list.
        let Ok(name) = ResourceName::try_from(dto.kube_cluster_name) else {
            continue;
        };
        out.push(KubeCluster {
            name,
            labels: sorted_labels(dto.labels),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_kube_fixture() {
        let kube = parse_kube(include_str!("../../tests/fixtures/kube.json")).unwrap();
        assert_eq!(kube.len(), 1);
        assert_eq!(kube[0].name.as_str(), "kube-cluster-demo");
    }

    #[test]
    fn skips_kube_clusters_with_invalid_names() {
        let kube =
            parse_kube(r#"[{"kube_cluster_name":"-x"},{"kube_cluster_name":"prod"}]"#).unwrap();
        assert_eq!(kube.len(), 1);
        assert_eq!(kube[0].name.as_str(), "prod");
    }
}
