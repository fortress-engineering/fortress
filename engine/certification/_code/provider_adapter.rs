//! Versioned description and wire exchange for an explicitly registered evidence collector.

use serde::{Deserialize, Serialize};

use crate::control_layout::ExtensionInputRole;
use crate::declaration::DeclarationBinding;
use crate::wire::{JsonAdmissionLimits, admit_json, parse_public_json};

use super::{ProviderFormat, ProviderRunManifest, ensure, hash, is_digest};

const ROLE: ExtensionInputRole = ExtensionInputRole::EvidenceAdapter;
const WIRE_SCHEMA: &str = "urn:fortress:schema:v1:evidence-adapter-exchange";
const VERSION: u16 = 1;

/// One evidence collector description pinned by an explicit caller selection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAdapter {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    provider: String,
    provider_version: String,
    protocol_version: u16,
    format: ProviderFormat,
    capability: Capability,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Capability {
    TestReports,
    AnalysisReports,
}

/// One bounded action in the collector exchange.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdapterOperation {
    /// Fetch exact protocol and provider capabilities.
    Hello,
    /// Collect evidence for the exact independently selected scope.
    Collect,
    /// Withdraw the request before dispatching its collection.
    Cancel,
}

/// Exact operation and evidence scope supplied by the trusted host.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdapterRequest {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    /// Host-assigned request identity.
    pub request_id: String,
    /// Discovery, collection, or cancellation control.
    pub operation: AdapterOperation,
    /// Exact subject, context, and authority for collection or cancellation.
    pub binding: Option<DeclarationBinding>,
    /// Exact invocation scope for collection or cancellation.
    pub invocation_scope: Option<String>,
}

/// A bounded collector reply. Its assertions remain unverified observations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterResult {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    request_id: String,
    provider: String,
    provider_version: String,
    protocol_version: u16,
    format: ProviderFormat,
    capability: Capability,
    outcome: Outcome,
    /// Original XML or SARIF UTF-8 text before normalization.
    pub raw_utf8: Option<String>,
    /// Original reported scope and execution metadata.
    pub manifest: Option<ProviderRunManifest>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Outcome {
    Capabilities,
    Reported,
    Cancelled,
    Unavailable,
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
}

fn read<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
    token_bytes: usize,
) -> Result<T, String> {
    admit_json(
        bytes,
        JsonAdmissionLimits {
            bytes: limit,
            depth: 20,
            nodes: 32_768,
            token_bytes,
        },
    )
    .map_err(|error| error.to_string())?;
    parse_public_json(std::str::from_utf8(bytes).map_err(|e| e.to_string())?)
        .map_err(|error| error.to_string())
}

impl EvidenceAdapter {
    /// Decodes a versioned description with an explicit exact raw-byte pin.
    ///
    /// # Errors
    ///
    /// Rejects incompatible capabilities/versions, invalid identities, or differing content.
    pub fn from_pinned_bytes(bytes: &[u8], expected: &str) -> Result<Self, String> {
        if bytes.len() > ROLE.definition_bytes() {
            return Err("RESOURCE_LIMIT: evidence adapter description".into());
        }
        if hash(bytes) != expected {
            return Err("EVIDENCE_ADAPTER_DIGEST_MISMATCH".into());
        }
        let result: Self = read(bytes, ROLE.definition_bytes(), 512)?;
        if result.schema != ROLE.schema()
            || result.schema_version != VERSION
            || result.protocol_version != VERSION
        {
            return Err("UNSUPPORTED_EVIDENCE_ADAPTER_VERSION".into());
        }
        if !token(&result.provider) || !token(&result.provider_version) {
            return Err("INVALID_EVIDENCE_ADAPTER_IDENTITY".into());
        }
        if !matches!(
            (result.format, result.capability),
            (ProviderFormat::JunitXml, Capability::TestReports)
                | (ProviderFormat::Sarif210, Capability::AnalysisReports)
        ) {
            return Err("UNSUPPORTED_EVIDENCE_ADAPTER_CAPABILITY".into());
        }
        Ok(result)
    }

    /// Checks the claimed provider and content format without admitting the evidence.
    ///
    /// # Errors
    ///
    /// Returns an error if the described adapter contradicts the companion manifest.
    pub fn validate_manifest(
        &self,
        format: ProviderFormat,
        manifest: &ProviderRunManifest,
    ) -> Result<(), String> {
        ensure(
            self.format == format
                && self.provider == manifest.provider
                && self.provider_version == manifest.provider_version,
            "EVIDENCE_ADAPTER_MANIFEST_MISMATCH",
        )
        .map_err(|error| error.to_string())?;
        manifest.validate().map_err(|error| error.to_string())
    }

    /// Returns the original payload format for the existing normalizer.
    #[must_use]
    pub const fn format(&self) -> ProviderFormat {
        self.format
    }

    /// Describes the exact capabilities a negotiated reply must match.
    #[must_use]
    pub fn capabilities(&self) -> serde_json::Value {
        serde_json::json!({
            "provider": self.provider, "provider_version": self.provider_version,
            "protocol_version": self.protocol_version, "format": self.format,
            "capability": self.capability,
        })
    }

    /// Checks a collected reply and the exact independently requested evidence scope.
    ///
    /// # Errors
    ///
    /// Rejects mismatched requests, outcomes, formats, scope, or payload identities.
    pub fn validate_reply(
        &self,
        request: &ProviderAdapterRequest,
        bytes: &[u8],
    ) -> Result<AdapterResult, String> {
        let reply: AdapterResult = read(bytes, 1024 * 1024, 768 * 1024)?;
        if reply.schema != WIRE_SCHEMA
            || reply.schema_version != VERSION
            || reply.protocol_version != VERSION
        {
            return Err("UNSUPPORTED_EVIDENCE_ADAPTER_VERSION".into());
        }
        if reply.request_id != request.request_id
            || reply.format != self.format
            || reply.capability != self.capability
            || reply.provider != self.provider
            || reply.provider_version != self.provider_version
        {
            return Err("EVIDENCE_ADAPTER_REPLY_MISMATCH".into());
        }
        match (&reply.outcome, &reply.raw_utf8, &reply.manifest) {
            (Outcome::Reported, Some(raw), Some(manifest))
                if request.operation == AdapterOperation::Collect =>
            {
                self.validate_manifest(reply.format, manifest)?;
                if request.binding.as_ref() != Some(&manifest.binding)
                    || request.invocation_scope.as_ref() != Some(&manifest.invocation_scope)
                    || hash(raw.as_bytes()) != manifest.payload_digest
                {
                    return Err("EVIDENCE_ADAPTER_BINDING_MISMATCH".into());
                }
            }
            (Outcome::Capabilities, None, None) if request.operation == AdapterOperation::Hello => {
            }
            (Outcome::Cancelled, None, None) if request.operation == AdapterOperation::Cancel => {}
            (Outcome::Unavailable, None, None)
                if request.operation == AdapterOperation::Collect => {}
            _ => return Err("INVALID_EVIDENCE_ADAPTER_RESULT".into()),
        }
        Ok(reply)
    }
}

impl ProviderAdapterRequest {
    /// Decodes a host request before a provider can execute.
    ///
    /// # Errors
    ///
    /// Rejects unbound collection, bad identifiers, or an unknown protocol version.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let request: Self = read(bytes, 64 * 1024, 512)?;
        if request.schema != WIRE_SCHEMA || request.schema_version != VERSION {
            return Err("UNSUPPORTED_EVIDENCE_ADAPTER_VERSION".into());
        }
        if !token(&request.request_id) {
            return Err("INVALID_EVIDENCE_ADAPTER_REQUEST_ID".into());
        }
        match (
            request.operation,
            &request.binding,
            &request.invocation_scope,
        ) {
            (AdapterOperation::Hello, None, None) => {}
            (AdapterOperation::Collect | AdapterOperation::Cancel, Some(binding), Some(scope))
                if token(scope)
                    && [
                        &binding.subject_ref,
                        &binding.context_ref,
                        &binding.authority_ref,
                    ]
                    .into_iter()
                    .all(|hash| is_digest(hash)) => {}
            _ => return Err("INVALID_EVIDENCE_ADAPTER_REQUEST_SCOPE".into()),
        }
        Ok(request)
    }
}
