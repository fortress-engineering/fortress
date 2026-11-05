//! Truthful, multidimensional application declarations, separate from approval.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// First declaration schema identity; historical certification is unchanged.
pub const DECLARATION_SCHEMA: &str = "urn:fortress:derived:v1:conformance-declaration";

/// Exact source, context and authority required by an application assessment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarationBinding {
    /// Exact source subject digest.
    pub subject_ref: String,
    /// Exact `ProgramContext` digest, not just its family name.
    pub context_ref: String,
    /// Complete scoped authority composition digest.
    pub authority_ref: String,
}

/// An associated identity/version/digest reference at its authored Module scope.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedProfileReference {
    /// Module override owner; absent for project scope.
    pub module: Option<String>,
    /// Exact immutable Standard profile identity.
    pub id: String,
    /// Exact immutable profile version.
    pub version: String,
    /// Digest associated with this identity and version.
    pub digest: String,
}

/// Independently compiled reporting requirements for one selected dimension.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredDimension {
    /// Stable selected semantic dimension.
    pub id: String,
    /// All expected upstream claim identities, including authorizations.
    pub claim_refs: Vec<String>,
}

/// Authority-owned reporting manifest, never inferred from successful outcomes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionManifest {
    /// Exact associated profile references and override placement.
    pub profiles: Vec<ScopedProfileReference>,
    /// All selected dimensions and their complete claim universes.
    pub dimensions: Vec<RequiredDimension>,
}

/// Raw claim truth, without residue or enforcement rewriting.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeclarationTruth {
    /// A sufficient upstream witness establishes a contradiction.
    SupportedViolation,
    /// The scoped negative proposition has sufficient upstream support.
    NoSupportedViolation,
    /// Relevant authority or coverage is incomplete.
    NotEvaluable,
    /// The scope has no applicable evaluative proposition.
    NotApplicable,
    /// Authored permission only; never an absence proof.
    Authorization,
}

/// Type of proposition; registered rule checks and Module policies are distinct.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeclarationClaimKind {
    /// A proposition about an exact registered rule execution.
    RuleCheck,
    /// An authored Module semantic-policy proposition.
    SemanticPolicy,
}

/// One owned projection of an upstream result, retaining its actual identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarationClaim {
    /// Prevents transferring a rule-check result into a Module policy proof.
    pub kind: DeclarationClaimKind,
    /// Upstream stable claim instance or rule-result identity.
    pub id: String,
    /// Exact Module/rule/claim scope, not a display-name heuristic.
    pub scope_ref: String,
    /// Upstream raw truth.
    pub truth: DeclarationTruth,
    /// Relevant immutable evidence leaves.
    pub proof_refs: Vec<String>,
    /// Raw normalized finding identities, including accepted residue.
    pub findings: Vec<String>,
    /// Relevant uncertainty or defeating conditions.
    pub defeater_refs: Vec<String>,
    /// Explicit upstream reasons; unknowns never become violations.
    pub reason_codes: Vec<String>,
    /// Explicit conditional premises to be admitted by the assessor's caller.
    pub assumptions: Vec<String>,
    /// Exact upstream semantic binding; absent for registered rule checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_claim: Option<SemanticClaimDetail>,
    /// Original rule outcome and applicability; absent for Module policy claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_result: Option<RuleClaimDetail>,
}

/// Exact upstream rule reporting; it never asserts a Module policy proposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleClaimDetail {
    /// Original registered check state.
    pub outcome: crate::application::ApplicationRuleOutcome,
    /// Original applicability result.
    pub applicable: bool,
    /// Original explicit applicability reason, when supplied.
    pub applicability_reason: Option<String>,
    /// Original evaluator detail, including unsupported semantics.
    pub detail: String,
}

/// Lossless claim identity, coverage, provenance and proof-shape projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticClaimDetail {
    /// Exact upstream proof citations, including aggregate identities.
    pub upstream_proof_refs: Vec<String>,
    /// Exact source and policy-bound upstream instance identity.
    pub instance_id: String,
    /// Disposition-independent upstream slot identity.
    pub slot_id: String,
    /// Authored Module owner.
    pub module_id: String,
    /// Exact selector; never inferred from observed entry points.
    pub scope_selector: String,
    /// Context family and exact instance context remain distinct.
    pub context_family: String,
    /// Exact policy identity.
    pub policy_digest: String,
    /// Exact instance `ProgramContext`.
    pub context_digest: String,
    /// Complete claim universe identity.
    pub governed_universe_digest: String,
    /// Upstream evaluator identity, without authenticity inflation.
    pub producer_identity: String,
    /// Capability or effect namespace.
    pub target_kind: String,
    /// Authored capability or effect.
    pub target: String,
    /// ALLOW or DENY authority.
    pub disposition: String,
    /// Number of governed source files.
    pub governed_source_files: u64,
    /// Number of source files producing semantic facts.
    pub analysed_source_files: u64,
    /// Independently preserved production-capable observations.
    pub production_observations: Vec<String>,
    /// Independently preserved exclusively test-only observations.
    pub test_observations: Vec<String>,
    /// Observations with unresolved entry provenance.
    pub unknown_observations: Vec<String>,
    /// Upstream complete witness alternatives, without changing their algebra.
    pub proof_graph: Option<crate::proof::ProofGraph>,
    /// Upstream enforcement eligibility, separate from raw truth.
    pub blocking_eligibility: Option<String>,
}

/// Complete report for a selected dimension.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarationDimension {
    /// Stable selected dimension identity.
    pub id: String,
    /// Complete canonical upstream claim references.
    pub claim_refs: Vec<String>,
    /// Deterministic raw aggregation; not profile satisfaction.
    pub truth: DeclarationTruth,
}

/// Residue and enforcement facts reported without changing raw conformance.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarationResidue {
    /// Finding identities accepted by baseline authority.
    pub accepted_baseline: Vec<String>,
    /// Finding identities covered by current exception authority.
    pub accepted_exceptions: Vec<String>,
    /// Current findings eligible for progressive enforcement.
    pub blocking_findings: Vec<String>,
}

/// Canonical artifact requirement, independent of local cache availability.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarationArtifact {
    /// Registered logical artifact identity.
    pub id: String,
    /// Exact required canonical content digest.
    pub content_digest: String,
    /// Exact public byte count.
    pub byte_count: u64,
}

/// Valid reporting is independent from any favorable application result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceDeclaration {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    /// Exact immutable subject/context/authority binding.
    pub binding: DeclarationBinding,
    /// Complete selected dimensions and independently compiled claims.
    pub required_dimension_manifest: DimensionManifest,
    /// Explicit record for every selected dimension.
    pub dimensions: Vec<DeclarationDimension>,
    /// Complete raw claim and rule-result projections.
    pub claims: Vec<DeclarationClaim>,
    /// Required immutable artifact identities, never CURRENT/MISSING flags.
    pub proof_manifest: Vec<DeclarationArtifact>,
    /// Baseline/exception and enforcement facts, separate from truth.
    pub residue_summary: DeclarationResidue,
    /// Exact producer identity and semantic version.
    pub producer: String,
    /// Explicit unauthenticated-local provenance; never a signing claim.
    pub authenticity: String,
}

impl ConformanceDeclaration {
    /// Composes complete typed upstream outcomes without demanding approval.
    ///
    /// # Errors
    /// Returns an error for incomplete, duplicate or conflicting authority/results.
    pub fn compose(
        binding: DeclarationBinding,
        manifest: DimensionManifest,
        mut claims: Vec<DeclarationClaim>,
        mut artifacts: Vec<DeclarationArtifact>,
        residue: DeclarationResidue,
    ) -> Result<Self, DeclarationError> {
        claims.sort_by(|a, b| a.id.cmp(&b.id));
        artifacts.sort();
        let by_id = claims
            .iter()
            .map(|c| (c.id.as_str(), c))
            .collect::<BTreeMap<_, _>>();
        let mut dimensions = Vec::new();
        for required in &manifest.dimensions {
            let states = required
                .claim_refs
                .iter()
                .map(|id| {
                    by_id
                        .get(id.as_str())
                        .map(|claim| claim.truth)
                        .ok_or_else(|| DeclarationError::Invalid("required claim omitted".into()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            dimensions.push(DeclarationDimension {
                id: required.id.clone(),
                claim_refs: required.claim_refs.clone(),
                truth: aggregate_truth(&states),
            });
        }
        let value = Self {
            schema: DECLARATION_SCHEMA.into(),
            schema_version: 1,
            binding,
            required_dimension_manifest: manifest,
            dimensions,
            claims,
            proof_manifest: artifacts,
            residue_summary: residue,
            producer: "fortress-application-declaration@1.0.0".into(),
            authenticity: "UNVERIFIED".into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Parses strict v1 reporting, without trusting its self-declared manifest.
    ///
    /// # Errors
    /// Rejects malformed public JSON and incomplete or conflicting records.
    pub fn from_json_str(source: &str) -> Result<Self, DeclarationError> {
        let value: Self = crate::wire::parse_public_json(source)
            .map_err(|e| DeclarationError::Invalid(e.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    /// Returns exact RFC 8785 bytes after validating all owned records.
    ///
    /// # Errors
    /// Rejects invalid state or serialization failures.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DeclarationError> {
        self.validate()?;
        canonical(self)
    }

    /// Identifies the exact emitted declaration bytes.
    ///
    /// # Errors
    /// Rejects invalid state or serialization failures.
    pub fn digest(&self) -> Result<String, DeclarationError> {
        Ok(format!(
            "sha256:{:x}",
            Sha256::digest(self.to_canonical_bytes()?)
        ))
    }

    /// Checks internal validity; assessment also checks trusted expected authority.
    ///
    /// # Errors
    /// Rejects omission, duplicates, incompatible versions, or inconsistent truth.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), DeclarationError> {
        if self.schema != DECLARATION_SCHEMA
            || self.schema_version != 1
            || self.producer != "fortress-application-declaration@1.0.0"
            || self.authenticity != "UNVERIFIED"
        {
            return invalid("unsupported declaration header");
        }
        for value in [
            &self.binding.subject_ref,
            &self.binding.context_ref,
            &self.binding.authority_ref,
        ] {
            if !is_digest(value) {
                return invalid("invalid evaluation binding");
            }
        }
        let manifest = &self.required_dimension_manifest;
        strictly_increasing(
            manifest
                .profiles
                .iter()
                .map(|p| (&p.module, &p.id, &p.version)),
        )?;
        for p in &manifest.profiles {
            if p.id.is_empty()
                || p.version.is_empty()
                || !is_digest(&p.digest)
                || p.module.as_ref().is_some_and(String::is_empty)
            {
                return invalid("invalid scoped profile reference");
            }
        }
        strictly_increasing(manifest.dimensions.iter().map(|d| &d.id))?;
        strictly_increasing(self.dimensions.iter().map(|d| &d.id))?;
        strictly_increasing(self.claims.iter().map(|c| &c.id))?;
        if manifest.dimensions.is_empty() || manifest.dimensions.len() != self.dimensions.len() {
            return invalid("required dimension omitted");
        }
        let claims = self
            .claims
            .iter()
            .map(|c| (c.id.as_str(), c))
            .collect::<BTreeMap<_, _>>();
        let mut referenced = BTreeSet::new();
        for (required, actual) in manifest.dimensions.iter().zip(&self.dimensions) {
            if required.id.is_empty()
                || required.id != actual.id
                || required.claim_refs != actual.claim_refs
            {
                return invalid("dimension manifest mismatch");
            }
            canonical_strings(&required.claim_refs)?;
            let mut states = Vec::new();
            for reference in &required.claim_refs {
                let claim = claims
                    .get(reference.as_str())
                    .ok_or_else(|| DeclarationError::Invalid("dangling claim".into()))?;
                referenced.insert(reference.as_str());
                states.push(claim.truth);
            }
            if actual.truth != aggregate_truth(&states) {
                return invalid("dimension truth mismatch");
            }
        }
        if referenced.len() != claims.len() {
            return invalid("claim outside selected manifest");
        }
        for claim in &self.claims {
            if match claim.kind {
                DeclarationClaimKind::RuleCheck => {
                    claim.rule_result.is_none() || claim.semantic_claim.is_some()
                }
                DeclarationClaimKind::SemanticPolicy => {
                    claim.semantic_claim.is_none() || claim.rule_result.is_some()
                }
            } {
                return invalid("raw claim projection omitted its typed upstream result");
            }
            if claim.id.is_empty() || claim.scope_ref.is_empty() {
                return invalid("empty claim identity");
            }
            for values in [
                &claim.proof_refs,
                &claim.findings,
                &claim.defeater_refs,
                &claim.reason_codes,
                &claim.assumptions,
            ] {
                canonical_strings(values)?;
            }
            if let Some(rule) = &claim.rule_result
                && (claim.kind != DeclarationClaimKind::RuleCheck
                    || claim.semantic_claim.is_some()
                    || claim.truth
                        != match rule.outcome {
                            crate::application::ApplicationRuleOutcome::Passed => {
                                DeclarationTruth::NoSupportedViolation
                            }
                            crate::application::ApplicationRuleOutcome::Failed => {
                                DeclarationTruth::SupportedViolation
                            }
                            crate::application::ApplicationRuleOutcome::Unsupported => {
                                DeclarationTruth::NotEvaluable
                            }
                            crate::application::ApplicationRuleOutcome::NotApplicable => {
                                DeclarationTruth::NotApplicable
                            }
                        })
            {
                return invalid("inconsistent upstream rule result");
            }
            if let Some(detail) = &claim.semantic_claim {
                if detail.instance_id.is_empty()
                    || claim.scope_ref != detail.instance_id
                    || detail.slot_id.is_empty()
                    || detail.module_id.is_empty()
                    || detail.scope_selector.is_empty()
                    || detail.context_family.is_empty()
                    || detail.target.is_empty()
                    || detail.producer_identity.is_empty()
                    || !["CAPABILITY", "EFFECT"].contains(&detail.target_kind.as_str())
                    || !["ALLOW", "DENY"].contains(&detail.disposition.as_str())
                    || (detail.disposition == "ALLOW")
                        != (claim.truth == DeclarationTruth::Authorization)
                    || detail.blocking_eligibility.as_deref().is_some_and(|value| {
                        !["BLOCK_SUPPORTED", "ADVISORY_ONLY", "NOT_EVALUABLE"].contains(&value)
                    })
                    || detail.analysed_source_files > detail.governed_source_files
                    || detail.governed_source_files > crate::wire::MAX_EXACT_PUBLIC_INTEGER
                    || detail.context_digest != self.binding.context_ref
                    || (claim.truth == DeclarationTruth::NoSupportedViolation
                        && detail.analysed_source_files == 0)
                {
                    return invalid("inconsistent semantic claim projection");
                }
                for identity in [
                    &detail.policy_digest,
                    &detail.context_digest,
                    &detail.governed_universe_digest,
                ] {
                    if !is_digest(identity) {
                        return invalid("invalid semantic claim binding");
                    }
                }
                for values in [
                    &detail.upstream_proof_refs,
                    &detail.production_observations,
                    &detail.test_observations,
                    &detail.unknown_observations,
                ] {
                    canonical_strings(values)?;
                }
                if detail
                    .upstream_proof_refs
                    .iter()
                    .any(|id| !claim.proof_refs.contains(id))
                {
                    return invalid("upstream proof citation omitted");
                }
                if let Some(graph) = &detail.proof_graph {
                    graph
                        .validate(&claim.proof_refs.iter().cloned().collect())
                        .map_err(|e| DeclarationError::Invalid(e.to_string()))?;
                }
            }
        }
        strictly_increasing(self.proof_manifest.iter().map(|a| &a.id))?;
        for a in &self.proof_manifest {
            if a.id.is_empty()
                || !is_digest(&a.content_digest)
                || a.byte_count == 0
                || a.byte_count > crate::wire::MAX_EXACT_PUBLIC_INTEGER
            {
                return invalid("invalid artifact requirement");
            }
        }
        for values in [
            &self.residue_summary.accepted_baseline,
            &self.residue_summary.accepted_exceptions,
            &self.residue_summary.blocking_findings,
        ] {
            canonical_strings(values)?;
            if values
                .iter()
                .any(|id| !self.claims.iter().any(|c| c.findings.contains(id)))
            {
                return invalid("residue refers to an unreported raw finding");
            }
        }
        Ok(())
    }
}

pub(crate) fn aggregate_truth(states: &[DeclarationTruth]) -> DeclarationTruth {
    for state in [
        DeclarationTruth::SupportedViolation,
        DeclarationTruth::NotEvaluable,
        DeclarationTruth::NoSupportedViolation,
    ] {
        if states.contains(&state) {
            return state;
        }
    }
    DeclarationTruth::NotApplicable
}

pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, DeclarationError> {
    let json =
        serde_json::to_string(value).map_err(|e| DeclarationError::Invalid(e.to_string()))?;
    crate::wire::canonicalize_public_json(&json)
        .map_err(|e| DeclarationError::Invalid(e.to_string()))
}

pub(crate) fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub(crate) fn canonical_strings(values: &[String]) -> Result<(), DeclarationError> {
    if values.iter().any(String::is_empty) {
        return invalid("empty canonical identity");
    }
    strictly_increasing(values.iter())
}

pub(crate) fn strictly_increasing<T: Ord>(
    values: impl IntoIterator<Item = T>,
) -> Result<(), DeclarationError> {
    let mut previous = None;
    for value in values {
        if previous.as_ref().is_some_and(|p| p >= &value) {
            return invalid("noncanonical or duplicate set");
        }
        previous = Some(value);
    }
    Ok(())
}

pub(crate) fn invalid<T>(reason: &str) -> Result<T, DeclarationError> {
    Err(DeclarationError::Invalid(reason.into()))
}

/// Invalid application reporting, distinct from a valid negative assessment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeclarationError {
    /// A typed/wire/authority invariant failed.
    Invalid(String),
}

impl Display for DeclarationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid application declaration: {reason}"),
        }
    }
}
impl Error for DeclarationError {}

/// Operational availability, with no authority to rewrite snapshot truth.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaterializationAvailability {
    /// Exact locally available bytes match the immutable requirement.
    Current,
    /// Required identities remain known, but local replay bytes are absent.
    Missing,
    /// Bytes belong to a different source subject and cannot establish availability.
    Stale,
    /// Available bytes disagree with the bound requirement.
    Invalid,
}

/// One run's local availability, intentionally outside declaration canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerificationSessionReport {
    /// Exact immutable declaration assessed by this run.
    pub declaration_digest: String,
    /// Availability of every required artifact, keyed by its registered identity.
    pub materializations: BTreeMap<String, MaterializationAvailability>,
}

impl VerificationSessionReport {
    /// Checks supplied materializations without inferring truth from cache presence.
    ///
    /// # Errors
    /// Rejects an invalid declaration or canonical serialization failure.
    pub fn inspect(
        declaration: &ConformanceDeclaration,
        local: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, DeclarationError> {
        Self::inspect_subject(declaration, &declaration.binding.subject_ref, local)
    }

    /// Checks availability in an explicitly identified cache subject.
    ///
    /// # Errors
    /// Rejects invalid declaration or cache subject identities.
    pub fn inspect_subject(
        declaration: &ConformanceDeclaration,
        cache_subject: &str,
        local: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, DeclarationError> {
        if !is_digest(cache_subject) {
            return invalid("invalid materialization subject");
        }
        let declaration_digest = declaration.digest()?;
        let materializations = declaration
            .proof_manifest
            .iter()
            .map(|required| {
                let state = match local.get(&required.id) {
                    Some(_) if cache_subject != declaration.binding.subject_ref => {
                        MaterializationAvailability::Stale
                    }
                    None => MaterializationAvailability::Missing,
                    Some(bytes)
                        if bytes.len() as u64 == required.byte_count
                            && format!("sha256:{:x}", Sha256::digest(bytes))
                                == required.content_digest =>
                    {
                        MaterializationAvailability::Current
                    }
                    Some(_) => MaterializationAvailability::Invalid,
                };
                (required.id.clone(), state)
            })
            .collect();
        Ok(Self {
            declaration_digest,
            materializations,
        })
    }
}
