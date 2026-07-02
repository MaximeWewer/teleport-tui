//! `tsh kube ls` → Kubernetes clusters. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`run_json`, `run_scoped_ls`,
//! `classify_failure`, `sorted_labels`, `MetaDto`) and imports come via `super::*`.

#![allow(clippy::question_mark, clippy::wildcard_imports)]
use super::*;

#[derive(Debug, DeJson)]
struct KubeDto {
    kube_cluster_name: String,
    #[nserde(default)]
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct TshKubeRepository<R: CommandRunner> {
    runner: R,
    tsh: PathBuf,
}

impl<R: CommandRunner> TshKubeRepository<R> {
    pub fn new(runner: R, tsh: PathBuf) -> Self {
        Self { runner, tsh }
    }
}

impl<R: CommandRunner> KubeRepository for TshKubeRepository<R> {
    fn list_kube(&self, ctx: &ClusterContext) -> Result<Vec<KubeCluster>, DomainError> {
        let stdout = run_scoped_ls(&self.runner, &self.tsh, &["kube"], ctx)?;
        parse_kube(&stdout)
    }
}

fn parse_kube(stdout: &str) -> Result<Vec<KubeCluster>, DomainError> {
    let dtos: Vec<KubeDto> = DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
        detail: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(dtos.len());
    for dto in dtos {
        out.push(KubeCluster {
            name: ResourceName::try_from(dto.kube_cluster_name)?,
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
}
