//! Public, analyzer-independent portable evidence records and JCS identities.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// One bounded portable artifact; wire and public semantic identities are distinct.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortableArtifact {
    /// Registered role or explicit portable role, never a machine-local path.
    pub id: String,
    /// Safe bundle-relative content-addressed member.
    pub member: String,
    /// Exact original bytes, preserving historical digest semantics.
    pub wire_digest: String,
    /// SHA-256 of RFC 8785 canonical public JSON.
    pub jcs_digest: Option<String>,
    /// JSON receives a public JCS identity; original external report bytes do
    /// not become JSON merely because the bundle manifest uses JSON.
    pub media_type: String,
    /// Exact original byte count.
    pub byte_count: usize,
    /// Explicit public schema identity from the artifact.
    pub schema: String,
    /// The verifier must admit this member, not an optional presentation.
    pub required: bool,
}

/// Versioned immutable portable evidence inventory, separate from CONTROL publication.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    /// Public schema identity.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Exact supported edition.
    pub schema_version: u16,
    /// Explicit source, context and governing authority references.
    pub binding: crate::declaration::DeclarationBinding,
    /// Original selected immutable generation, when available.
    pub generation_ref: Option<String>,
    /// Public canonical declaration identity.
    pub declaration_digest: String,
    /// Public canonical profile assessment identity.
    pub assessment_digest: String,
    /// Exact selected profile composition.
    pub profile_digest: String,
    /// INCLUDED, `NOT_APPLICABLE_APPLICATION`, or UNAVAILABLE; application
    /// reporting never fabricates an implementation certification decision.
    pub certification_result_availability: String,
    /// Complete required inventory, in role order.
    pub artifacts: Vec<PortableArtifact>,
    /// Required authority container roles, resolved through the artifact inventory.
    pub authority_assets: Vec<String>,
    /// Every required original Evidence DAG node, including defeaters.
    pub required_nodes: Vec<String>,
    /// Every required application leaf identity and exact payload identity.
    pub required_payloads: BTreeMap<String, String>,
    /// Omitted reproducible semantic projections, never silently assumed present.
    pub optional_projection_refs: Vec<crate::declaration::DeclarationArtifact>,
    /// Complete omitted original product identities. Their bytes are needed
    /// to recompute those products; retained-record integrity does not do so.
    pub materialization_dependencies: Vec<crate::declaration::DeclarationArtifact>,
    /// Unresolved original inputs; nonempty prevents complete verification.
    pub unavailable: Vec<String>,
    /// Explicit limitations of this representation.
    pub projection_losses: Vec<String>,
}

/// Stable machine-readable failure at the portable boundary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortableError {
    /// Closed operational category, not a semantic verdict.
    pub code: String,
    /// Bounded explanatory detail.
    pub message: String,
}

impl std::fmt::Display for PortableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for PortableError {}

/// Creates an explicit portable error.
#[must_use]
pub fn failure(code: &str, message: impl Into<String>) -> PortableError {
    PortableError {
        code: code.into(),
        message: message.into(),
    }
}

/// Exact byte digest, never producer authentication.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// RFC 8785 bytes with the established exact public integer boundary.
/// # Errors
/// Rejects unsafe numbers, invalid Unicode or serialization failures.
pub fn canonical(value: &Value) -> Result<Vec<u8>, PortableError> {
    let text = serde_json::to_string(value).map_err(|e| failure("INVALID_JSON", e.to_string()))?;
    crate::wire::canonicalize_public_json(&text).map_err(|e| failure("INVALID_JSON", e.to_string()))
}

/// Strict bounded JSON admission; preserves original bytes outside this function.
/// # Errors
/// Rejects malformed records, duplicate keys, unsafe numbers and excessive size.
pub fn parse(bytes: &[u8]) -> Result<Value, PortableError> {
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(failure("RESOURCE_LIMIT", "artifact exceeds 32 MiB"));
    }
    let text = std::str::from_utf8(bytes).map_err(|e| failure("INVALID_JSON", e.to_string()))?;
    crate::wire::parse_public_json(text).map_err(|e| failure("INVALID_JSON", e.to_string()))
}
