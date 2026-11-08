//! Neutral immutable application endpoints shared by composition and comparison.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Neutral application endpoint state; validity and profile approval are distinct.
#[derive(Clone, Copy, Debug, serde::Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StateViewStatus {
    /// No authored project authority exists.
    Ungoverned,
    /// Authored authority is present but cannot be interpreted safely.
    Invalid,
    /// A valid application has required uncertainty or incomplete support.
    Partial,
    /// A valid application has a supported required contradiction.
    Negative,
    /// All requirements of this exact application profile are satisfied.
    Complete,
}

/// Neutral view suitable for later comparisons, including unapproved endpoints.
#[derive(Clone, Debug, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateView {
    /// Original offline replay observation, present only in neutral endpoint v3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portable_evidence_graph: Option<crate::certification::EvidenceGraph>,
    /// Versioned neutral endpoint schema identity.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Neutral endpoint contract version.
    pub schema_version: u16,
    /// Exact observed source identity, never a successful-certificate lookup.
    pub source_ref: String,
    /// Explicit authority/reporting endpoint state.
    pub status: StateViewStatus,
    /// Authority failure details without inventing conformance evidence.
    pub detail: Option<String>,
    /// Truthful application artifacts when governed analysis is structurally usable.
    pub application: Option<crate::application::ApplicationAssessment>,
}

impl StateView {
    fn validate_application_inputs(
        &self,
        application: &crate::application::ApplicationAssessment,
    ) -> Result<(), crate::declaration::DeclarationError> {
        if self.schema_version == 1 {
            if application.assessment.schema_version() != 1
                || application.evidence_inputs.is_some()
                || !application.provider_requirements.is_empty()
            {
                return crate::declaration::invalid(
                    "historical StateView cannot reinterpret current evidence",
                );
            }
        } else {
            let inputs = application.evidence_inputs.as_ref().ok_or_else(|| {
                crate::declaration::DeclarationError::Invalid(
                    "current StateView omitted evidence inputs".into(),
                )
            })?;
            let input_digest = inputs
                .digest()
                .map_err(|e| crate::declaration::DeclarationError::Invalid(e.to_string()))?;
            if application.assessment.schema_version() != 2
                || inputs.binding != application.declaration.binding
                || application.assessment.evidence_input_digest.as_ref() != Some(&input_digest)
            {
                return crate::declaration::invalid("StateView selected evidence inputs differ");
            }
            crate::declaration::strictly_increasing(
                application
                    .provider_requirements
                    .iter()
                    .map(|r| &r.requirement_id),
            )?;
            for report in &application.provider_requirements {
                if !inputs.selected.iter().any(|s| {
                    s.envelope_digest == report.envelope_digest
                        && s.inventory_digest == report.inventory_digest
                }) || !application
                    .obligations
                    .iter()
                    .any(|o| o.id == format!("external-verification:{}", report.requirement_id))
                {
                    return crate::declaration::invalid(
                        "provider selection provenance differs from complete inputs",
                    );
                }
            }
        }
        Ok(())
    }

    /// Reads neutral endpoints, including unapproved and ungoverned snapshots.
    /// Integrity and internal consistency do not authenticate the producer.
    ///
    /// # Errors
    /// Rejects malformed wire data or inconsistent cross-artifact bindings.
    pub fn from_json_str(source: &str) -> Result<Self, crate::declaration::DeclarationError> {
        let value: Self = crate::wire::parse_public_json(source)
            .map_err(|e| crate::declaration::DeclarationError::Invalid(e.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    /// Returns RFC 8785 canonical bytes; no local availability enters this view.
    ///
    /// # Errors
    /// Returns a public serialization error.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, crate::declaration::DeclarationError> {
        self.validate()?;
        crate::declaration::canonical(self)
    }

    /// Checks neutral state and exact internal links; replay requires trusted authority.
    ///
    /// # Errors
    /// Rejects inconsistent states, manifests or source/declaration bindings.
    pub fn validate(&self) -> Result<(), crate::declaration::DeclarationError> {
        if !matches!(
            (self.schema.as_str(), self.schema_version),
            ("urn:fortress:derived:v1:state-view", 1)
                | ("urn:fortress:derived:v2:state-view", 2)
                | ("urn:fortress:derived:v3:state-view", 3)
        ) || !crate::declaration::is_digest(&self.source_ref)
        {
            return crate::declaration::invalid("unsupported neutral endpoint");
        }
        if self.schema_version < 3 && self.portable_evidence_graph.is_some() {
            return crate::declaration::invalid(
                "historical endpoint cannot acquire portable evidence",
            );
        }
        if let Some(graph) = &self.portable_evidence_graph {
            graph
                .validate()
                .map_err(|e| crate::declaration::DeclarationError::Invalid(e.to_string()))?;
            if graph.subject() != self.source_ref || self.application.is_none() {
                return crate::declaration::invalid("portable graph belongs to another endpoint");
            }
        }
        if let Some(application) = &self.application {
            application.declaration.validate()?;
            application.assessment.validate()?;
            self.validate_application_inputs(application)?;
            crate::declaration::strictly_increasing(
                application.evidence.iter().map(|leaf| &leaf.id),
            )?;
            let known = application
                .evidence
                .iter()
                .map(|leaf| leaf.id.clone())
                .collect::<BTreeSet<_>>();
            for obligation in &application.obligations {
                if let Some(graph) = &obligation.proof {
                    graph.validate(&known).map_err(|e| {
                        crate::declaration::DeclarationError::Invalid(e.to_string())
                    })?;
                }
            }
            let status = match application.assessment.decision {
                crate::assessment::AssessmentDecision::Satisfied => StateViewStatus::Complete,
                crate::assessment::AssessmentDecision::NotSatisfied => StateViewStatus::Negative,
                crate::assessment::AssessmentDecision::NotEvaluable => StateViewStatus::Partial,
                crate::assessment::AssessmentDecision::Invalid => StateViewStatus::Invalid,
            };
            if self.source_ref != application.declaration.binding.subject_ref
                || self.status != status
                || application.project.is_empty()
                || application.assessment.binding != application.declaration.binding
                || application.assessment.declaration_digest != application.declaration.digest()?
                || application.assessment.obligation_manifest_digest
                    != format!(
                        "sha256:{:x}",
                        Sha256::digest(crate::declaration::canonical(&application.obligations)?)
                    )
                || application.obligations.iter().map(|o| &o.id).ne(application
                    .assessment
                    .obligations
                    .iter()
                    .map(|o| &o.id))
            {
                return crate::declaration::invalid("state-view subject differs from declaration");
            }
        } else if !matches!(
            self.status,
            StateViewStatus::Ungoverned | StateViewStatus::Invalid
        ) {
            return crate::declaration::invalid("governed endpoint omitted its application");
        }
        Ok(())
    }
}
