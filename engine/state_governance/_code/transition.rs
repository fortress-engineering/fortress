//! Pure four-axis comparison of explicitly bound immutable repository states.
#[path = "claims.rs"]
mod claims;
#[path = "comparison.rs"]
mod comparison;
#[path = "identity.rs"]
mod identity;
#[path = "model.rs"]
mod model;
#[path = "projection.rs"]
pub mod projection;
#[path = "retirement.rs"]
mod retirement;
#[path = "validation.rs"]
mod validation;
pub use comparison::{compare_merge, compare_states, compare_states_cancellable};
pub use model::*;
pub use retirement::{
    assess_original_findings, assess_retirements, current_governance_anchors, finding_anchors,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Largest admitted input/output document; operational safety, not a speed threshold.
pub const MAX_TRANSITION_BYTES: usize = 32 * 1024 * 1024;
/// Maximum total records retained for a comparison.
pub const MAX_TRANSITION_RECORDS: usize = 50_000;
/// Typed malformed-input, integrity, cancellation or resource failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionError {
    /// Stable machine-readable refusal code.
    pub code: String,
    /// Human-readable failure without a favorable fallback.
    pub message: String,
}
impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for TransitionError {}
pub(crate) fn fail(code: &str, message: impl Into<String>) -> TransitionError {
    TransitionError {
        code: code.into(),
        message: message.into(),
    }
}
pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, TransitionError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_TRANSITION_BYTES)
                .ok_or_else(|| std::io::Error::other("comparison byte limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter(0), value).map_err(|_| {
        fail(
            "RESOURCE_LIMIT",
            "comparison serialization exceeds admission",
        )
    })?;
    let bytes =
        crate::declaration::canonical(value).map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
    if bytes.len() > MAX_TRANSITION_BYTES {
        return Err(fail(
            "RESOURCE_LIMIT",
            "comparison document exceeds byte admission",
        ));
    }
    Ok(bytes)
}
pub(crate) fn digest<T: Serialize>(value: &T) -> Result<String, TransitionError> {
    Ok(format!("sha256:{:x}", Sha256::digest(canonical(value)?)))
}
impl ComparisonState {
    /// Creates an input with unavailable historical assets; no bytes are reconstructed.
    #[must_use]
    pub fn unavailable(origin_ref: Option<String>) -> Self {
        Self {
            schema: "urn:fortress:derived:v2:comparison-state".into(),
            schema_version: 2,
            source_ref: None,
            view: None,
            retained_application: None,
            assets: None,
            origin_ref,
            limitations: vec![
                "Historical source or necessary authority assets are unavailable.".into(),
            ],
        }
    }
    /// Returns the role-partitioned implementation identity, excluding governing inputs.
    /// # Errors
    /// Refuses invalid inputs; incomplete inventories return no identity.
    pub fn subject_identity(&self) -> Result<Option<String>, TransitionError> {
        self.validate()?;
        self.assets
            .as_ref()
            .map(identity::subject)
            .transpose()
            .map(Option::flatten)
    }
    /// Returns the complete intent/authority/governance identity for controlled cells.
    /// This is separate from the original aggregate declaration binding.
    /// # Errors
    /// Refuses invalid input; missing governing assets return no identity.
    pub fn governing_identity(&self) -> Result<Option<String>, TransitionError> {
        self.validate()?;
        let context = self
            .retained_application
            .as_ref()
            .or_else(|| self.view.as_ref().and_then(|v| v.application.as_ref()))
            .map(|a| a.declaration.binding.context_ref.as_str());
        self.assets
            .as_ref()
            .map(|a| identity::governing(a, context))
            .transpose()
            .map(Option::flatten)
    }
    /// Reads strict bounded public input and validates its exact internal bindings.
    /// # Errors
    /// Rejects duplicate keys, malformed versions, tampering and resource exhaustion.
    pub fn from_json_str(source: &str) -> Result<Self, TransitionError> {
        if source.len() > MAX_TRANSITION_BYTES {
            return Err(fail(
                "RESOURCE_LIMIT",
                "comparison input exceeds byte admission",
            ));
        }
        let value: Self = crate::wire::parse_public_json(source)
            .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
        value.validate()?;
        Ok(value)
    }
    /// Returns canonical input identity without incidental input ordering.
    /// # Errors
    /// Refuses invalid records or resource exhaustion.
    pub fn digest(&self) -> Result<String, TransitionError> {
        self.validate()?;
        digest(&self.normalized())
    }
    /// Returns validated, deterministically ordered JCS bytes.
    /// # Errors
    /// Refuses malformed input or resource exhaustion.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TransitionError> {
        self.validate()?;
        canonical(&self.normalized())
    }
    /// Checks source, authority, vocabulary and asset bindings without evaluating semantics.
    /// # Errors
    /// Returns a typed integrity, input or resource refusal.
    pub fn validate(&self) -> Result<(), TransitionError> {
        validation::validate_state(self)
    }
    pub(crate) fn normalized(&self) -> Self {
        let mut value = self.clone();
        value.limitations.sort();
        value.limitations.dedup();
        if let Some(after) = &mut value.assets {
            after.normalize();
        }
        value
    }
}
impl StateAssets {
    pub(crate) fn normalize(&mut self) {
        self.inputs
            .sort_by(|prior, next| (&prior.id, &prior.path).cmp(&(&next.id, &next.path)));
        self.entities.sort_by(|prior, next| {
            (&prior.kind, &prior.id, &prior.path).cmp(&(&next.kind, &next.id, &next.path))
        });
        self.policies.sort_by(|prior, next| prior.id.cmp(&next.id));
    }
}
impl TransitionAnalysis {
    /// Canonical versioned result bytes, including every unresolved dependency.
    /// # Errors
    /// Refuses unsupported result versions and resource exhaustion.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TransitionError> {
        if self.schema != "urn:fortress:derived:v1:transition-analysis"
            || self.schema_version != 1
            || self.semantic_version != "1.0.0"
        {
            return Err(fail("UNSUPPORTED_VERSION", "unsupported transition result"));
        }
        validation::validate_result(self)?;
        canonical(self)
    }
    /// Content address for an optional derived, non-authoritative durable record.
    /// # Errors
    /// Refuses unsupported versions or resource exhaustion.
    pub fn digest(&self) -> Result<String, TransitionError> {
        self.to_canonical_bytes()
            .map(|before| format!("sha256:{:x}", Sha256::digest(before)))
    }
    /// Parses a result only when its expected content address matches.
    /// # Errors
    /// Refuses malformed, tampered, oversized or unsupported records.
    pub fn from_json_str(source: &str, expected: &str) -> Result<Self, TransitionError> {
        if source.len() > MAX_TRANSITION_BYTES {
            return Err(fail(
                "RESOURCE_LIMIT",
                "transition result exceeds byte admission",
            ));
        }
        let value: Self = crate::wire::parse_public_json(source)
            .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
        if value.digest()? != expected {
            return Err(fail("INTEGRITY_ERROR", "transition result digest differs"));
        }
        Ok(value)
    }
}
