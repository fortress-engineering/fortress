//! Transport-neutral, versioned inspection DTOs and strict parameter decoding.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Supported read-only protocol edition.
pub const QUERY_PROTOCOL_VERSION: u16 = 1;
/// Maximum request frame bytes, excluding the newline delimiter.
pub const MAX_REQUEST_BYTES: usize = 65_536;
/// Maximum serialized response bytes.
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
/// Maximum records in one response page.
pub const MAX_PAGE_SIZE: usize = 200;

/// A request correlated by a caller-selected active request identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRequest {
    /// Exact supported protocol version; adjacent versions are never inferred.
    pub protocol_version: u16,
    /// Nonempty, bounded correlation identity.
    pub request_id: String,
    /// Method registry name.
    pub method: String,
    /// Exact loaded result identity, or null to discover it using status.
    pub state_ref: Option<String>,
    /// Exact loaded evaluation context, when supplied by the caller.
    pub context_ref: Option<String>,
    /// Method-specific parameters, decoded strictly before dispatch.
    pub parameters: Value,
}

impl QueryRequest {
    /// Decodes a bounded frame, rejecting duplicate keys and inexact numbers.
    ///
    /// # Errors
    /// Returns a structured malformed-input or resource error.
    pub fn from_json_str(source: &str) -> Result<Self, QueryError> {
        if source.len() > MAX_REQUEST_BYTES {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "request frame exceeds byte limit",
            ));
        }
        let request: Self = crate::wire::parse_public_json(source)
            .map_err(|error| QueryError::new("INVALID_REQUEST", error.to_string()))?;
        if request.request_id.is_empty()
            || request.request_id.len() > 128
            || request.request_id.chars().any(char::is_control)
        {
            return Err(QueryError::new(
                "INVALID_REQUEST",
                "request_id must contain 1..128 non-control bytes",
            ));
        }
        Ok(request)
    }

    /// Decodes the exact registered method parameters for a thin adapter.
    ///
    /// # Errors
    /// Rejects unknown methods, extra parameters and malformed typed values.
    pub fn operation_for_adapter(&self) -> Result<QueryOperation, QueryError> {
        serde_json::from_value(
            serde_json::json!({"method": self.method,"parameters":self.parameters}),
        )
        .map_err(|error| {
            QueryError::new(
                if METHODS.contains(&self.method.as_str()) {
                    "INVALID_PARAMETERS"
                } else {
                    "UNKNOWN_METHOD"
                },
                error.to_string(),
            )
        })
    }

    pub(super) fn operation(&self) -> Result<QueryOperation, QueryError> {
        self.operation_for_adapter()
    }
}

/// Closed supported method registry, shared by all adapters.
pub const METHODS: &[&str] = &[
    "author", "cancel", "doctor", "explain", "progress", "protocol", "query", "status",
];

/// Typed method parameters independent of stdio or any editor protocol.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "method", content = "parameters", rename_all = "snake_case")]
pub enum QueryOperation {
    /// Describe the protocol and operational limits.
    Protocol(EmptyParameters),
    /// Separate selected result truth, freshness and availability.
    Status(EmptyParameters),
    /// Inspect prepared read-only environment diagnostics.
    Doctor(EmptyParameters),
    /// Query canonical indexed relationships.
    Query(SelectParameters),
    /// Explain a finding, claim, obligation or defeater.
    Explain(ExplainParameters),
    /// Preview a supported policy proposal using readable selectors.
    Author(AuthorParameters),
    /// Cancel an active request through the adapter's registry.
    Cancel(ControlParameters),
    /// Inspect an active request through the adapter's registry.
    Progress(ControlParameters),
}

/// Parameterless operation; extra fields are errors.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyParameters {}

/// Bounded continuation tied to the exact loaded input and query.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PageParameters {
    /// Maximum requested records, between one and the published maximum.
    #[serde(default = "default_page_size")]
    pub limit: usize,
    /// Opaque continuation returned by the preceding page.
    #[serde(default)]
    pub cursor: Option<String>,
}

const fn default_page_size() -> usize {
    50
}

impl Default for PageParameters {
    fn default() -> Self {
        Self {
            limit: default_page_size(),
            cursor: None,
        }
    }
}

/// Query selection, preserving dependency direction.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectParameters {
    /// Modules, policy, dependents, routes, relationships or references.
    pub kind: QueryKind,
    /// Canonical ID, qualified name, or unique readable Module name.
    #[serde(default)]
    pub selector: Option<String>,
    /// Optional capability or provider selector for routes.
    #[serde(default)]
    pub target: Option<String>,
    /// Explicit bounded page, defaulting to fifty rows.
    #[serde(default)]
    pub page: PageParameters,
}

/// Closed supported query categories.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryKind {
    /// Declared canonical Module inventory.
    Modules,
    /// Authored policy with upstream effective-policy claims.
    Policy,
    /// Consumers requiring the selected provider, never reversed edges.
    Dependents,
    /// Consumer-to-provider capability edges with permission classification.
    Routes,
    /// Governed directed relationships.
    Relationships,
    /// Existing CCG/reference projection facts.
    References,
}

/// Explanation selection with bounded evidence continuation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplainParameters {
    /// Stable finding, claim, obligation or defeater identity.
    pub selector: String,
    /// Explicit bounded page.
    #[serde(default)]
    pub page: PageParameters,
}

/// Readable semantic policy authoring; the result remains a proposal.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorParameters {
    /// Module ID or unique readable selector.
    pub module: String,
    /// Registered effect or capability name; omitted to obtain schema guidance.
    #[serde(default)]
    pub target: Option<String>,
    /// Explicit authored disposition for a preview.
    #[serde(default)]
    pub disposition: Option<PolicyDisposition>,
}

/// Supported authored dispositions, separate from evaluated truth.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDisposition {
    /// Proposed permission; never an accepted authority write.
    Allow,
    /// Proposed negative claim.
    Deny,
}

/// Adapter lifecycle request referencing one active request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlParameters {
    /// Correlation identity to inspect or cancel.
    pub request_id: String,
}

/// Stable, transport-neutral error with explicit ambiguity candidates.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryError {
    /// Closed documented error code.
    pub code: String,
    /// Human-readable reason without a favorable fallback.
    pub message: String,
    /// Canonical candidates for explicit caller clarification.
    pub candidates: Vec<String>,
}

impl QueryError {
    /// Constructs a failure without candidates.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            candidates: Vec::new(),
        }
    }
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for QueryError {}

/// One exact response; result and error are mutually exclusive.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryResponse {
    /// Registered response schema identity.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Exact protocol edition of this response.
    pub protocol_version: u16,
    /// Correlation identity; absent only for an undecodable frame.
    pub request_id: Option<String>,
    /// Immutable query input identity, including availability and selected evidence.
    pub state_ref: String,
    /// Actual immutable source observed at loading, never a live watcher claim.
    pub actual_source_ref: String,
    /// Subject of selected evidence, when a result was supplied.
    pub selected_source_ref: Option<String>,
    /// Source bytes, independently from context equivalence, approval and authenticity.
    pub source_freshness: SourceFreshness,

    /// Selected evidence context, without claiming current context equivalence.
    pub context_ref: Option<String>,
    /// Prepared result, present only on success.
    pub result: Option<QueryPayload>,
    /// Structured failure, present only on failure.
    pub error: Option<QueryError>,
    /// Cross-cutting operational and trust limitations.
    pub limitations: Vec<String>,
    /// Explicit completion, cancellation or failure state.
    pub operational_state: String,
}

/// Closed result family with owner-produced data preserved in indexed rows.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QueryPayload {
    /// Independent truth and freshness dimensions.
    Status(Value),
    /// Prepared read-only diagnosis.
    Doctor(Value),
    /// Complete bounded continuation, without implicit truncation.
    Page(QueryPage),
    /// Human explanation and paged actual evidence.
    Explanation(ExplanationPage),
    /// Schema guidance and canonical proposed bytes.
    Authoring(Value),
    /// Protocol or lifecycle metadata.
    Protocol(Value),
}

/// A lossless indexed projection row, never a new evaluation result.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRecord {
    /// Producer-owned identity or deterministic graph-local row identity.
    pub id: String,
    /// Record authority category.
    pub kind: String,
    /// Evaluated or authored scope identity.
    pub scope_ref: String,
    /// Exact owned record projection.
    pub value: Value,
}

/// A deterministic, bounded slice of all selected records.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryPage {
    /// Total matching rows, independent of page size.
    pub total: usize,
    /// Zero-based offset for this exact result set.
    pub offset: usize,
    /// Complete rows in canonical order.
    pub records: Vec<QueryRecord>,
    /// Continuation, present exactly when rows remain.
    pub next_cursor: Option<String>,
}

/// An explanation whose supporting records use the same paging contract.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplanationPage {
    /// Original requested identity.
    pub selector: String,
    /// Governing statement, rationale, scope, uncertainty and remediation.
    pub description: Value,
    /// All actual supporting and countervailing records.
    pub evidence: QueryPage,
}

impl QueryResponse {
    /// Emits deterministic JCS bytes subject to the response byte limit.
    ///
    /// # Errors
    /// Rejects serialization failures and oversized answers.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, QueryError> {
        let bytes = crate::declaration::canonical(self)
            .map_err(|error| QueryError::new("INVALID_RESULT", error.to_string()))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "response exceeds byte limit; use a smaller page",
            ));
        }
        Ok(bytes)
    }

    /// Renders every machine field as readable labelled prose, without recomputation.
    #[must_use]
    pub fn to_human(&self) -> String {
        fn render(value: &Value, indent: usize, output: &mut String) {
            use std::fmt::Write as _;
            match value {
                Value::Object(fields) => {
                    for (key, value) in fields {
                        let _ =
                            writeln!(output, "{}{}:", " ".repeat(indent), key.replace('_', " "));
                        render(value, indent + 2, output);
                    }
                }
                Value::Array(values) if !values.is_empty() => {
                    for value in values {
                        render(value, indent + 2, output);
                    }
                }
                _ => {
                    let _ = writeln!(
                        output,
                        "{}{}",
                        " ".repeat(indent),
                        value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_owned)
                    );
                }
            }
        }
        let mut output = String::new();
        if let Ok(value) = serde_json::to_value(self) {
            render(&value, 0, &mut output);
        }
        output
    }
}

/// Source-byte relationship between selected evidence and the loaded source.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceFreshness {
    /// Exact bytes match; current host context and approval remain separate.
    Fresh,
    /// Selected evidence describes another immutable source.
    Stale,
    /// No source-bound result is selected.
    Missing,
}
