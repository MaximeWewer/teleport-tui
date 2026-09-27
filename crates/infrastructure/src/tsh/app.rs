//! `tsh apps ls` → applications. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`run_json`, `run_scoped_ls`,
//! `classify_failure`, `sorted_labels`, `MetaDto`) and imports come via `super::*`.

#![allow(clippy::question_mark, clippy::wildcard_imports)]
use super::*;

#[derive(Debug, DeJson)]
struct AppDto {
    metadata: MetaDto,
    spec: AppSpecDto,
}

#[derive(Debug, DeJson)]
struct AppSpecDto {
    #[nserde(default)]
    uri: String,
    #[nserde(default)]
    public_addr: String,
}

#[derive(Debug, Clone)]
pub struct TshAppRepository<R: CommandRunner> {
    runner: R,
    tsh: PathBuf,
}

impl<R: CommandRunner> TshAppRepository<R> {
    pub fn new(runner: R, tsh: PathBuf) -> Self {
        Self { runner, tsh }
    }
}

impl<R: CommandRunner> AppRepository for TshAppRepository<R> {
    fn list_apps(&self, ctx: &ClusterContext) -> Result<Vec<App>, DomainError> {
        let stdout = run_scoped_ls(&self.runner, &self.tsh, &["apps"], ctx)?;
        parse_apps(&stdout)
    }
}

fn parse_apps(stdout: &str) -> Result<Vec<App>, DomainError> {
    let dtos: Vec<AppDto> = DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
        detail: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(dtos.len());
    for dto in dtos {
        // Skip (don't fail on) a row whose name we refuse: one odd entry must
        // not blank the whole list.
        let Ok(name) = ResourceName::try_from(dto.metadata.name) else {
            continue;
        };
        out.push(App {
            name,
            uri: dto.spec.uri,
            public_addr: dto.spec.public_addr,
            labels: sorted_labels(dto.metadata.labels),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_apps_fixture() {
        let apps = parse_apps(include_str!("../../tests/fixtures/apps.json")).unwrap();
        assert_eq!(apps.len(), 2);
        assert!(!apps[0].public_addr.is_empty());
    }

    #[test]
    fn skips_apps_with_invalid_names() {
        let apps = parse_apps(
            r#"[{"metadata":{"name":"-x"},"spec":{}},{"metadata":{"name":"grafana"},"spec":{}}]"#,
        )
        .unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name.as_str(), "grafana");
    }
}
