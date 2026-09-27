//! `tsh db ls` → databases. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`TshCli`, `tsh_adapter!`, `parse_json`, `sorted_labels`,
//! `MetaDto`) come from `super`.

#![allow(clippy::question_mark)]

use domain::cluster::ClusterContext;
use domain::error::DomainError;
use domain::port::DatabaseRepository;
use domain::resource::Database;
use domain::value::ResourceName;
use nanoserde::DeJson;

use super::{MetaDto, parse_json, sorted_labels};
use crate::process::CommandRunner;

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

tsh_adapter!(TshDatabaseRepository);

impl<R: CommandRunner> DatabaseRepository for TshDatabaseRepository<R> {
    fn list_databases(&self, ctx: &ClusterContext) -> Result<Vec<Database>, DomainError> {
        let stdout = self.cli.ls(&["db"], ctx, true)?;
        parse_databases(&stdout)
    }
}

fn parse_databases(stdout: &str) -> Result<Vec<Database>, DomainError> {
    let dtos: Vec<DbDto> = parse_json(stdout)?;
    let mut out = Vec::with_capacity(dtos.len());
    for dto in dtos {
        // Skip (don't fail on) a row whose name we refuse: one odd entry must
        // not blank the whole list.
        let Ok(name) = ResourceName::try_from(dto.metadata.name) else {
            continue;
        };
        out.push(Database {
            name,
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

    #[test]
    fn skips_databases_with_invalid_names() {
        let dbs = parse_databases(
            r#"[{"metadata":{"name":"-x"},"spec":{}},{"metadata":{"name":"pg"},"spec":{}}]"#,
        )
        .unwrap();
        assert_eq!(dbs.len(), 1);
        assert_eq!(dbs[0].name.as_str(), "pg");
    }
}
