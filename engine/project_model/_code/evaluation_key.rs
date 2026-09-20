//! Exact authority and context bindings for an evaluated repository state.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Standard and project authority selected for one evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorityBinding {
    standard_digest: String,
    edition: String,
    selected_profile_digests: Vec<String>,
    project_authority_digest: String,
    ownership_digest: String,
    effective_policy_digest: Option<String>,
    finding_governance_digest: Option<String>,
}

impl AuthorityBinding {
    /// Binds exact authority identities without claiming their integrity or authenticity.
    #[must_use]
    pub fn new(
        standard_digest: impl Into<String>,
        edition: impl Into<String>,
        selected_profile_digests: impl IntoIterator<Item = String>,
        project_authority_digest: impl Into<String>,
        ownership_digest: impl Into<String>,
        effective_policy_digest: Option<String>,
        finding_governance_digest: Option<String>,
    ) -> Self {
        let mut selected_profile_digests = selected_profile_digests.into_iter().collect::<Vec<_>>();
        selected_profile_digests.sort();
        selected_profile_digests.dedup();
        Self {
            standard_digest: standard_digest.into(),
            edition: edition.into(),
            selected_profile_digests,
            project_authority_digest: project_authority_digest.into(),
            ownership_digest: ownership_digest.into(),
            effective_policy_digest,
            finding_governance_digest,
        }
    }

    /// Returns canonical authority binding bytes, excluding machine location and time.
    ///
    /// # Panics
    /// Panics only if the fixed in-memory binding representation cannot be serialized.
    #[must_use]
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("authority binding serializes");
        format!("sha256:{:x}", Sha256::digest(bytes))
    }
}

/// Exact source, semantic context and authority selection for one evaluation.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvaluationKey {
    source_manifest_digest: String,
    program_context_digest: String,
    authority_binding_digest: String,
}

impl EvaluationKey {
    /// Joins already established component identities without re-reading source.
    #[must_use]
    pub fn new(
        source_manifest_digest: impl Into<String>,
        program_context_digest: impl Into<String>,
        authority_binding_digest: impl Into<String>,
    ) -> Self {
        Self {
            source_manifest_digest: source_manifest_digest.into(),
            program_context_digest: program_context_digest.into(),
            authority_binding_digest: authority_binding_digest.into(),
        }
    }

    /// Returns the stable evaluation identity.
    ///
    /// # Panics
    /// Panics only if the fixed in-memory key representation cannot be serialized.
    #[must_use]
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("evaluation key serializes");
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    /// Returns the exact semantic context component.
    #[must_use]
    pub fn program_context_digest(&self) -> &str {
        &self.program_context_digest
    }
}
