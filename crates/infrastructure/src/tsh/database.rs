//! `tsh db ls` → databases. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`run_json`, `run_scoped_ls`,
//! `classify_failure`, `sorted_labels`, `MetaDto`) and imports come via `super::*`.

#![allow(clippy::question_mark, clippy::wildcard_imports)]
use super::*;

#[derive(Debug, DeJson)]
struct DbDto {
    metadata: MetaDto,
    spec: DbSpecDto,
}

#[derive(Debug, DeJson)]
struct DbSpecDto {
    #[nserde(default)]
    protocol: String,
    #[nserde(default)]
    uri: String,
}

#[derive(Debug, Clone)]
pub struct TshDatabaseRepository<R: CommandRunner> {
    runner: R,
    tsh: PathBuf,
}

impl<R: CommandRunner> TshDatabaseRepository<R> {
    pub fn new(runner: R, tsh: PathBuf) -> Self {
        Self { runner, tsh }
    }
}

impl<R: CommandRunner> DatabaseRepository for TshDatabaseRepository<R> {
    fn list_databases(&self, ctx: &ClusterContext) -> Result<Vec<Database>, DomainError> {
        let stdout = run_scoped_ls(&self.runner, &self.tsh, &["db"], ctx)?;
        parse_databases(&stdout)
    }
}

fn parse_databases(stdout: &str) -> Result<Vec<Database>, DomainError> {
    let dtos: Vec<DbDto> = DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
        detail: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(dtos.len());
    for dto in dtos {
        out.push(Database {
            name: ResourceName::try_from(dto.metadata.name)?,
            protocol: dto.spec.protocol,
            uri: dto.spec.uri,
            labels: sorted_labels(dto.metadata.labels),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_databases_fixture() {
        let dbs = parse_databases(include_str!("../../tests/fixtures/databases.json")).unwrap();
        assert_eq!(dbs.len(), 2);
        assert_eq!(dbs[0].protocol, "postgres");
        assert!(dbs[1].labels.is_empty());
    }
}
