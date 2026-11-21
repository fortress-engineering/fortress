//! Versioned, factual coverage of an exact integration route.

use serde::Serialize;

/// Scope of a declared host interface. These facts supply no permission.
#[derive(Serialize)]
pub struct HostCapability {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    host: &'static str,
    host_version: &'static str,
    os: &'static str,
    arch: &'static str,
    query_protocols: &'static [u16],
    request_schema: &'static str,
    intercepted_operations: &'static [&'static str],
    unmapped_routes: &'static [&'static str],
    candidate_preview: bool,
    grant_channel: &'static str,
    decision_mapping: &'static str,
    timeout_behavior: &'static str,
    subagent_behavior: &'static str,
    provider_protection: &'static str,
}

const OTHER_ROUTES: &[&str] = &[
    "agent shell and executable commands",
    "direct filesystem and editor writes",
    "other local or remote processes",
    "provider branch and release writes",
];

/// Describes the locally installed agent transport and its configured capabilities.
#[must_use]
pub fn mcp(candidate_preview: bool) -> HostCapability {
    HostCapability {
        schema: "urn:fortress:derived:v1:host-capability",
        schema_version: 1,
        host: "FORTRESS_MCP_STDIO",
        host_version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        query_protocols: &[1, 2, 3, 4, 5],
        request_schema: "MCP tools with native QueryRequest and optional CandidateRequest",
        intercepted_operations: &[],
        unmapped_routes: OTHER_ROUTES,
        candidate_preview,
        grant_channel: "NONE",
        decision_mapping: "Native query results and proposed evaluations only",
        timeout_behavior: "Cooperative cancellation and bounded single-connection backpressure",
        subagent_behavior: "The same read-only tools for any client connected to this endpoint",
        provider_protection: "UNVERIFIED",
    }
}

pub(crate) fn mediator() -> HostCapability {
    HostCapability {
        schema: "urn:fortress:derived:v1:host-capability",
        schema_version: 1,
        host: "FORTRESS_LOCAL_MEDIATOR",
        host_version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        query_protocols: &[],
        request_schema: "urn:fortress:derived:v2:migration-plan",
        intercepted_operations: &[
            "CREATE_FILE",
            "REPLACE_FILE",
            "MOVE_PATH",
            "DELETE_OWNED_FILE",
        ],
        unmapped_routes: OTHER_ROUTES,
        candidate_preview: false,
        grant_channel: "Trusted in-process invocation and GrantValidator ports",
        decision_mapping: "Original-policy decision and independent application preconditions",
        timeout_behavior: "Revocation, expiration and cancellation checked before transactional writes",
        subagent_behavior: "No public agent method can enter the trusted mediator",
        provider_protection: "UNVERIFIED",
    }
}
