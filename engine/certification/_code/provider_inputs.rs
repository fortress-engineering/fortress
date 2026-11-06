//! Complete authored requirement bindings and separately selected provider inputs.

use crate::declaration::{DeclarationBinding, canonical, is_digest};
use crate::provider::{
    EvidenceEnvelope, MAX_PROVIDER_RECORDS, NormalizedBudget, PreparedProvider,
    ProviderAcceptancePolicy, ProviderError, ProviderRequirementBinding, ProviderResolution,
    ensure, hash,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Authored selectors for existing native verification Requirements; never a
/// second Requirement store and never host execution or authentication authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationBindings {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    /// Strict Requirement identity order.
    pub requirements: Vec<ProviderRequirementBinding>,
}
impl VerificationBindings {
    /// Constructs exact authored mappings; absent mappings remain obligations.
    ///
    /// # Errors
    /// Rejects duplicate, unordered or malformed selectors.
    pub fn compose(requirements: Vec<ProviderRequirementBinding>) -> Result<Self, ProviderError> {
        let result = Self {
            schema: "urn:fortress:authored:v1:provider-bindings".into(),
            schema_version: 1,
            requirements,
        };
        result.validate()?;
        Ok(result)
    }
    /// Parses bounded authored mappings without running project code.
    ///
    /// # Errors
    /// Rejects malformed or ambiguous public data.
    pub fn from_json_str(source: &str) -> Result<Self, ProviderError> {
        crate::provider::preflight_json(source.as_bytes())?;
        let value: Self = crate::wire::parse_public_json(source)
            .map_err(|e| ProviderError::Invalid(e.to_string()))?;
        value.validate()?;
        Ok(value)
    }
    /// Checks wire identity, resource bounds and strict uniqueness.
    ///
    /// # Errors
    /// Rejects malformed or ambiguous authoring.
    pub fn validate(&self) -> Result<(), ProviderError> {
        ensure(
            self.schema == "urn:fortress:authored:v1:provider-bindings" && self.schema_version == 1,
            "unsupported provider bindings",
        )?;
        ensure(
            self.requirements.len() <= MAX_PROVIDER_RECORDS,
            "provider binding count",
        )?;
        let mut budget = NormalizedBudget::default();
        let mut selector_count = 0_usize;
        let mut prior: Option<&str> = None;
        for binding in &self.requirements {
            selector_count = selector_count
                .checked_add(binding.selectors.len())
                .ok_or(ProviderError::ResourceLimit("authored selectors"))?;
            if selector_count > crate::provider::MAX_PROVIDER_SELECTORS {
                return Err(ProviderError::ResourceLimit("authored selectors"));
            }
            binding.validate()?;
            ensure(
                prior.is_none_or(|p| p < binding.requirement_id.as_str()),
                "duplicate/unordered requirement binding",
            )?;
            budget.charge(256)?;
            budget.text(&binding.requirement_id)?;
            budget.text(&binding.provider)?;
            budget.text(&binding.invocation_scope)?;
            for selector in &binding.selectors {
                budget.charge(128)?;
                budget.text(&selector.qualified_name)?;
                if let Some(v) = &selector.package {
                    budget.text(v)?;
                }
                if let Some(v) = &selector.target {
                    budget.text(v)?;
                }
            }
            prior = Some(&binding.requirement_id);
        }
        Ok(())
    }
}

/// Explicit content selection, independent of its current local availability.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInputIdentity {
    /// Canonical entire envelope digest, also the closed import directory name.
    pub envelope_digest: String,
    /// Exact original payload identity.
    pub payload_digest: String,
    /// Complete claimed observed inventory identity, if one exists.
    pub inventory_digest: Option<String>,
}

/// Exact selected provider context, deliberately outside recursive source input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceInputSet {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    /// Exact application source, `ProgramContext` and authored authority.
    pub binding: DeclarationBinding,
    /// Complete selected input identities, including unavailable members.
    pub selected: Vec<ProviderInputIdentity>,
}
impl EvidenceInputSet {
    /// Reads an explicit selection; missing imports remain separate availability.
    ///
    /// # Errors
    /// Rejects malformed, duplicate or unsupported identities.
    pub fn from_json_str(source: &str) -> Result<Self, ProviderError> {
        crate::provider::preflight_json(source.as_bytes())?;
        let value: Self = crate::wire::parse_public_json(source)
            .map_err(|e| ProviderError::Invalid(e.to_string()))?;
        value.validate()?;
        Ok(value)
    }
    /// Constructs an exact selection without inferring latest-green reports.
    ///
    /// # Errors
    /// Rejects malformed or duplicate content identities.
    pub fn compose(
        binding: DeclarationBinding,
        selected: Vec<ProviderInputIdentity>,
    ) -> Result<Self, ProviderError> {
        let value = Self {
            schema: "urn:fortress:derived:v1:evidence-input-set".into(),
            schema_version: 1,
            binding,
            selected,
        };
        value.validate()?;
        Ok(value)
    }
    /// Validates identity and bounded canonical ordering.
    ///
    /// # Errors
    /// Refuses malformed public identities.
    pub fn validate(&self) -> Result<(), ProviderError> {
        ensure(
            self.schema == "urn:fortress:derived:v1:evidence-input-set" && self.schema_version == 1,
            "unsupported evidence input set",
        )?;
        ensure(
            is_digest(&self.binding.subject_ref)
                && is_digest(&self.binding.context_ref)
                && is_digest(&self.binding.authority_ref),
            "invalid evidence input binding",
        )?;
        ensure(self.selected.len() <= 1024, "selected provider input limit")?;
        let mut prior: Option<&str> = None;
        for input in &self.selected {
            ensure(
                is_digest(&input.envelope_digest)
                    && is_digest(&input.payload_digest)
                    && input.inventory_digest.as_deref().is_none_or(is_digest),
                "invalid selected provider identity",
            )?;
            ensure(
                prior.is_none_or(|p| p < input.envelope_digest.as_str()),
                "duplicate/unordered selected provider",
            )?;
            prior = Some(&input.envelope_digest);
        }
        Ok(())
    }
    /// Stable identity excludes availability so cache deletion cannot change authority.
    ///
    /// # Errors
    /// Refuses malformed identities or serialization failures.
    pub fn digest(&self) -> Result<String, ProviderError> {
        self.validate()?;
        Ok(hash(
            &canonical(&(
                "provider-evidence-input-set-v1",
                &self.binding,
                &self.selected,
            ))
            .map_err(|e| ProviderError::Invalid(e.to_string()))?,
        ))
    }
}

/// Prepared exact inputs and complete required obligations for application composition.
pub struct ApplicationProviderEvidence {
    /// Exact selected identities, unchanged when bytes become unavailable.
    pub input_set: EvidenceInputSet,
    /// Every native Requirement, including missing binding/report support.
    pub obligations: Vec<crate::assessment::ProfileObligation>,
    /// Validated selected provider facts and their private host admission.
    pub resolutions: Vec<ProviderResolution>,
}

/// Retained selection provenance. Reading it grants no acceptance capability.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequirementReport {
    /// Real authored Requirement identity.
    pub requirement_id: String,
    /// Exact normalized metadata and payload binding.
    pub envelope_digest: String,
    /// Inventory used for unique native selection.
    pub inventory_digest: Option<String>,
    /// Exact native names or existing governed Test IDs, without invented IDs.
    pub members: Vec<crate::provider::InventoryKey>,
    /// Admission-aware verification outcome, separate from software truth.
    pub decision: crate::assessment::AssessmentDecision,
    /// Exact missing, incompatible or failing premises.
    pub blockers: Vec<crate::provider::ProviderBlocker>,
}
impl From<&ProviderResolution> for ProviderRequirementReport {
    fn from(value: &ProviderResolution) -> Self {
        Self {
            requirement_id: value.requirement_id.clone(),
            envelope_digest: value.envelope_digest.clone(),
            inventory_digest: value.inventory_digest.clone(),
            members: value.members.clone(),
            decision: value.decision,
            blockers: value.blockers.clone(),
        }
    }
}
impl ApplicationProviderEvidence {
    /// Resolves only known real Requirements and explicitly selected inputs.
    /// Completeness originates in the CCG, never a favorable provider subset.
    ///
    /// # Errors
    /// Rejects foreign authoring, substituted bytes and resource excess.
    pub fn prepare(
        input_set: EvidenceInputSet,
        required: &BTreeSet<String>,
        bindings: &VerificationBindings,
        available: &BTreeMap<String, EvidenceEnvelope>,
        policy: &mut ProviderAcceptancePolicy,
    ) -> Result<Self, ProviderError> {
        use crate::assessment::{ObligationPredicate, ProfileObligation};
        input_set.validate()?;
        bindings.validate()?;
        ensure(
            required.len() <= MAX_PROVIDER_RECORDS,
            "required external obligation limit",
        )?;
        ensure(
            bindings
                .requirements
                .iter()
                .all(|b| required.contains(&b.requirement_id)),
            "binding names no authored external Requirement",
        )?;
        let mut prepared = Vec::new();
        let mut input_budget = NormalizedBudget::default();
        for selected in &input_set.selected {
            if let Some(envelope) = available.get(&selected.envelope_digest) {
                envelope.validate_into(&mut input_budget)?;
                ensure(
                    envelope.digest()? == selected.envelope_digest
                        && envelope.payload_digest == selected.payload_digest,
                    "selected provider bytes differ",
                )?;
                let inventory = if envelope.run_manifest.is_some() {
                    Some(envelope.inventory_digest()?)
                } else {
                    None
                };
                ensure(
                    inventory == selected.inventory_digest,
                    "selected provider inventory differs",
                )?;
                prepared.push((
                    envelope,
                    PreparedProvider::new(envelope, &input_set.binding, policy)?,
                ));
            }
        }
        ensure(
            available
                .keys()
                .all(|key| input_set.selected.iter().any(|s| &s.envelope_digest == key)),
            "unselected provider supplied",
        )?;
        let mut budget = NormalizedBudget::default();
        let mut obligations = Vec::new();
        let mut resolutions = Vec::new();
        for requirement in required {
            budget.charge(256)?;
            budget.text(requirement)?;
            let authored = bindings
                .requirements
                .binary_search_by(|b| b.requirement_id.cmp(requirement))
                .ok()
                .map(|i| &bindings.requirements[i]);
            let mut proof = None;
            if let Some(authored) = authored {
                let matches = prepared
                    .iter()
                    .filter(|(e, _)| {
                        e.run_manifest.as_ref().is_some_and(|m| {
                            m.provider == authored.provider
                                && m.invocation_scope == authored.invocation_scope
                        })
                    })
                    .collect::<Vec<_>>();
                if matches.len() == 1 {
                    let resolution = matches[0].1.resolve_with_budget(authored, &mut budget)?;
                    proof.clone_from(&resolution.proof);
                    resolutions.push(resolution);
                }
            }
            obligations.push(ProfileObligation {
                id: format!("external-verification:{requirement}"),
                scope_ref: requirement.clone(),
                predicate: ObligationPredicate::SuccessfulExecution,
                evidence_class: crate::certification::EvidenceClass::ExecutedTest,
                authenticated_producer_required: authored
                    .is_some_and(|b| b.authenticated_producer_required),
                proof,
            });
        }
        Ok(Self {
            input_set,
            obligations,
            resolutions,
        })
    }
}
