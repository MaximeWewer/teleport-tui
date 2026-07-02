//! `tsh request ls` → access requests. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`run_json`, `run_scoped_ls`,
//! `classify_failure`, `sorted_labels`, `MetaDto`) and imports come via `super::*`.

#![allow(clippy::question_mark, clippy::wildcard_imports)]
use super::*;

#[derive(Debug, DeJson)]
struct RequestDto {
    metadata: ReqMetaDto,
    spec: RequestSpecDto,
}

#[derive(Debug, DeJson)]
struct ReqMetaDto {
    name: String,
}

#[derive(Debug, DeJson)]
struct RequestSpecDto {
    #[nserde(default)]
    user: String,
    #[nserde(default)]
    roles: Vec<String>,
    // Teleport marshals the request state as an integer enum in the V3 spec.
    #[nserde(default)]
    state: i64,
    #[nserde(default)]
    request_reason: String,
    #[nserde(default)]
    created: String,
}

#[derive(Debug, Clone)]
pub struct TshRequestRepository<R: CommandRunner> {
    runner: R,
    tsh: PathBuf,
}

impl<R: CommandRunner> TshRequestRepository<R> {
    pub fn new(runner: R, tsh: PathBuf) -> Self {
        Self { runner, tsh }
    }
}

impl<R: CommandRunner> RequestRepository for TshRequestRepository<R> {
    fn list_requests(&self, ctx: &ClusterContext) -> Result<Vec<AccessRequest>, DomainError> {
        let stdout = run_scoped_ls(&self.runner, &self.tsh, &["request"], ctx)?;
        parse_requests(&stdout)
    }
}

fn parse_requests(stdout: &str) -> Result<Vec<AccessRequest>, DomainError> {
    let dtos: Vec<RequestDto> =
        DeJson::deserialize_json(stdout).map_err(|e| DomainError::Parse {
            detail: e.to_string(),
        })?;
    let mut out = Vec::with_capacity(dtos.len());
    for dto in dtos {
        out.push(AccessRequest {
            id: RequestId::try_from(dto.metadata.name)?,
            user: dto.spec.user,
            roles: dto.spec.roles,
            state: RequestState::from_code(dto.spec.state),
            reason: dto.spec.request_reason,
            created: dto.spec.created,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_requests_fixture() {
        let reqs = parse_requests(include_str!("../../tests/fixtures/requests.json")).unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].state, RequestState::Pending);
        assert!(reqs[0].state.is_pending());
        assert_eq!(reqs[0].roles.len(), 2);
        assert_eq!(reqs[1].state, RequestState::Approved);
    }
}
