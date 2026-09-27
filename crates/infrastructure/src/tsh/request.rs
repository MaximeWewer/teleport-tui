//! `tsh request ls` → access requests. DTOs + repository adapter + parsers.
//!
//! Child of `tsh`: shared helpers (`TshCli`, `tsh_adapter!`, `parse_json`,
//! `classify_failure`, `sorted_labels`, `MetaDto`) and imports come via `super::*`.

#![allow(clippy::question_mark, clippy::wildcard_imports)]
use super::*;

#[derive(Debug, DeJson)]
struct RequestDto {
    metadata: MetaDto,
    spec: RequestSpecDto,
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

tsh_adapter!(TshRequestRepository);

impl<R: CommandRunner> RequestRepository for TshRequestRepository<R> {
    fn list_requests(&self, ctx: &ClusterContext) -> Result<Vec<AccessRequest>, DomainError> {
        let stdout = self.cli.ls(&["request"], ctx, true)?;
        parse_requests(&stdout)
    }
}

fn parse_requests(stdout: &str) -> Result<Vec<AccessRequest>, DomainError> {
    let dtos: Vec<RequestDto> = parse_json(stdout)?;
    let mut out = Vec::with_capacity(dtos.len());
    for dto in dtos {
        // Skip (don't fail on) a row whose id we refuse: one odd entry must not
        // blank the whole list.
        let Ok(id) = RequestId::try_from(dto.metadata.name) else {
            continue;
        };
        out.push(AccessRequest {
            id,
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

    #[test]
    fn skips_requests_with_invalid_ids() {
        let reqs = parse_requests(
            r#"[{"metadata":{"name":"-x"},"spec":{}},{"metadata":{"name":"abc-123"},"spec":{}}]"#,
        )
        .unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].id.as_str(), "abc-123");
    }
}
