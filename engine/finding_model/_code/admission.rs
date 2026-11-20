//! Neutral evidence and reviewed residue records. A serialized review is a citation.
use super::{FindingAnchor, FindingGovernanceError, lifecycle_bytes, lifecycle_digest};
use super::{RetirementEvidenceV2, RetirementOutcome};
use super::{lifecycle::lifecycle_error, validate_digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Authored document edition containing separately scoped admission records.
pub const FINDING_GOVERNANCE_SCHEMA_V3: &str = "urn:fortress:schema:v3:finding-governance";
/// Bounded per-proposal fan-out for individually selected findings.
pub const MAX_ADMISSION_FINDINGS: usize = 1_024;
/// Versioned, read-only admission comparison projection.
pub const ADMISSION_ASSESSMENT_SCHEMA: &str = "urn:fortress:derived:v1:governance-admission";
/// Versioned finding-specific review-input format.
pub const ADMISSION_REVIEW_SCHEMA: &str = "urn:fortress:proposal:v1:governance-admission-review";

/// Supported interpretations of a target finding's origin.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionClassification {
    /// Physically pinned implementation under a newly applicable supported requirement.
    NewlyGoverned,
    /// The original state already reported this exact violation.
    ExistingViolation,
    /// An implementation change has comparable evidence under unchanged governing meaning.
    ImplementationRegression,
    /// Implementation and governing authority both changed; no automatic admission.
    MixedChange,
    /// Coverage, scope, context, evaluator or evidence cannot support attribution.
    NotComparable,
    /// Complete original source, governing meaning or observations were unavailable.
    OriginalHistoryUnavailable,
    /// Stable occurrence mapping is missing or ambiguous.
    IdentityAmbiguous,
    /// Original retirement or prior use of this exact finding identity excludes readmission.
    PreviouslyGoverned,
}

/// One exact comparable claim's binding. These references are evidence, not approval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionEndpoint {
    /// Complete immutable comparison state.
    pub state_ref: String,
    /// Exact evaluated source.
    pub source_ref: String,
    /// Selected context.
    pub context_ref: String,
    /// Complete role-partitioned governing identity.
    pub authority_ref: String,
}

/// One supported finding and the reason it does or does not qualify.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionFinding {
    /// Existing stable finding identity.
    pub finding_id: String,
    /// Existing registered rule.
    pub rule_id: String,
    /// Classification of the prospect, independent of enforcement.
    pub classification: AdmissionClassification,
    /// Exact introduced requirement/scope meaning, when causality is supported.
    pub introduced_scope_ref: Option<String>,
    /// Scope slot independent of temporary selection, used to detect reactivation.
    pub scope_slot_ref: Option<String>,
    /// Existing owner-produced matching anchor for eligible occurrences.
    pub anchor: Option<FindingAnchor>,
    /// Exact selected upstream witness references, without a new sufficiency assertion.
    #[serde(deserialize_with = "strict_set")]
    pub evidence_refs: BTreeSet<String>,
    /// Exact upstream defeaters, including limits that coexist with supported positive proof.
    #[serde(deserialize_with = "strict_set")]
    pub defeater_refs: BTreeSet<String>,
    /// Original facts or limiting condition supporting this disposition.
    pub reason: String,
}

/// Explicit endpoints and a bounded, canonical, non-authoritative proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionAssessment {
    /// Assessment format.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Supported wire edition.
    pub schema_version: u16,
    /// Content digest of the canonical record with this field initially empty.
    pub assessment_ref: String,
    /// Original immutable binding when usable.
    pub original: Option<AdmissionEndpoint>,
    /// Target immutable binding before authorizing finding treatment.
    pub target: Option<AdmissionEndpoint>,
    /// Exact existing four-axis comparison evidence.
    pub transition_ref: String,
    /// Role-partitioned implementation pinned independently of governance.
    pub subject_ref: Option<String>,
    /// Retained comparison endpoint identities inspected for prior authority.
    #[serde(deserialize_with = "strict_set")]
    pub history_refs: BTreeSet<String>,
    /// Target findings, ordered by canonical identity.
    pub findings: Vec<AdmissionFinding>,
}

impl AdmissionAssessment {
    /// Returns the exact reviewed-input identity.
    /// # Errors
    /// Refuses unsupported, malformed, unordered and oversized proposals.
    pub fn digest(&self) -> Result<String, FindingGovernanceError> {
        let computed = self.compute_digest()?;
        if self.assessment_ref != computed {
            return Err(lifecycle_error(
                "INTEGRITY_ERROR",
                "admission assessment digest differs",
            ));
        }
        Ok(computed)
    }

    pub(crate) fn bind_identity(&mut self) -> Result<(), FindingGovernanceError> {
        self.assessment_ref = self.compute_digest()?;
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, FindingGovernanceError> {
        if self.schema != ADMISSION_ASSESSMENT_SCHEMA || self.schema_version != 1 {
            return Err(lifecycle_error(
                "UNSUPPORTED_VERSION",
                "unknown admission assessment",
            ));
        }
        if self.findings.len() > MAX_ADMISSION_FINDINGS || self.history_refs.len() > 64 {
            return Err(lifecycle_error(
                "RESOURCE_LIMIT",
                "admission population exceeds limit",
            ));
        }
        if self
            .findings
            .windows(2)
            .any(|pair| pair[0].finding_id >= pair[1].finding_id)
        {
            return Err(lifecycle_error(
                "IDENTITY_AMBIGUOUS",
                "unordered or repeated finding",
            ));
        }
        validate_digest(&self.transition_ref)?;
        for value in self.subject_ref.iter().chain(&self.history_refs) {
            validate_digest(value)?;
        }
        for endpoint in self.original.iter().chain(&self.target) {
            endpoint.validate()?;
        }
        for finding in &self.findings {
            validate_digest(&finding.finding_id)?;
            validate_text(&finding.reason)?;
            super::RuleId::parse(&finding.rule_id).map_err(|_| {
                lifecycle_error("INVALID_INPUT", "invalid registered rule identity")
            })?;
            let eligible = finding.classification == AdmissionClassification::NewlyGoverned;
            if eligible != finding.anchor.is_some()
                || eligible != finding.introduced_scope_ref.is_some()
                || eligible != finding.scope_slot_ref.is_some()
                || eligible && finding.evidence_refs.is_empty()
            {
                return Err(lifecycle_error(
                    "INVALID_BINDING",
                    "finding eligibility and proof disagree",
                ));
            }
            for scope in finding
                .introduced_scope_ref
                .iter()
                .chain(&finding.scope_slot_ref)
            {
                validate_digest(scope)?;
            }
            for evidence in finding.evidence_refs.iter().chain(&finding.defeater_refs) {
                validate_text(evidence)?;
            }
            if let Some(anchor) = &finding.anchor {
                anchor.validate()?;
                if self.original.is_none()
                    || self.subject_ref.is_none()
                    || self.target.as_ref().is_none_or(|binding| {
                        binding.state_ref != anchor.from_state
                            || binding.source_ref != anchor.subject_ref
                    })
                    || anchor.finding_id != finding.finding_id
                    || anchor.rule_id != finding.rule_id
                {
                    return Err(lifecycle_error(
                        "INVALID_BINDING",
                        "finding anchor targets another assessment",
                    ));
                }
            }
        }
        let mut unsigned = self.clone();
        unsigned.assessment_ref.clear();
        lifecycle_digest(&unsigned)
    }

    /// Decodes a bounded comparison artifact; provenance remains unverified.
    /// # Errors
    /// Refuses malformed, duplicate, unsupported or inconsistent records.
    pub fn from_json_str(source: &str) -> Result<Self, FindingGovernanceError> {
        if source.len() > super::MAX_GOVERNANCE_BYTES {
            return Err(lifecycle_error(
                "RESOURCE_LIMIT",
                "admission assessment exceeds byte limit",
            ));
        }
        let assessment = crate::wire::parse_public_json::<Self>(source)
            .map_err(|error| lifecycle_error("INVALID_INPUT", &error.to_string()))?;
        assessment.digest()?;
        Ok(assessment)
    }
}

impl AdmissionEndpoint {
    fn validate(&self) -> Result<(), FindingGovernanceError> {
        for value in [
            &self.state_ref,
            &self.source_ref,
            &self.context_ref,
            &self.authority_ref,
        ] {
            validate_digest(value)?;
        }
        Ok(())
    }
}

fn strict_set<'de, D: serde::Deserializer<'de>>(value: D) -> Result<BTreeSet<String>, D::Error> {
    let values = Vec::<String>::deserialize(value)?;
    let count = values.len();
    let unique = values.into_iter().collect::<BTreeSet<_>>();
    if unique.len() != count {
        return Err(serde::de::Error::custom(
            "duplicate admission evidence identity",
        ));
    }
    Ok(unique)
}

/// Per-finding review intent. Accepting residue still requires external authorization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionDisposition {
    /// Acknowledge a supported preexisting violation.
    AcceptExisting,
    /// Require a separate implementation remediation.
    Remediate,
    /// Reject the requested treatment.
    Reject,
    /// Defer the decision.
    Defer,
    /// Necessary evidence remains unresolved.
    Unresolved,
}

/// Review input whose exact record becomes part of the authorized postimage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReview {
    /// Explicit review-input schema.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Supported wire edition.
    pub schema_version: u16,
    /// Exact assessment digest, including original and target.
    pub assessment_ref: String,
    /// Explicit selected decisions, without implied acceptance for omitted findings.
    pub decisions: Vec<AdmissionReviewItem>,
    /// Caller-supplied review expiry, evaluated only with an explicit trusted time.
    pub expires_at: Option<u64>,
}

/// Explicit decision for one named occurrence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReviewItem {
    /// Exact finding identity.
    pub finding_id: String,
    /// Requested treatment.
    pub disposition: AdmissionDisposition,
    /// Human justification; never a grant.
    pub rationale: String,
    /// External grant citation; an unsigned citation never verifies itself.
    pub grant_ref: Option<String>,
}

/// Retained exact origin of reviewed newly governed residue, separate from the baseline.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRecord {
    /// Exact canonical record identity computed with this field empty.
    pub record_ref: String,
    /// Exact comparison whose per-finding treatment was explicitly reviewed.
    pub assessment_ref: String,
    /// Exact reviewed decision, including expiry and all dispositions.
    pub review_ref: String,
    /// Original comparison binding.
    pub original: AdmissionEndpoint,
    /// Target before treatment was added to finding governance.
    pub target: AdmissionEndpoint,
    /// Pinned role-partitioned implementation identity.
    pub subject_ref: String,
    /// Exact new requirement meaning.
    pub introduced_scope_ref: String,
    /// Stable slot for reactivation detection.
    pub scope_slot_ref: String,
    /// Stable identity, original meaning and original proof binding.
    pub lifecycle_anchor: FindingAnchor,
    /// Original per-finding review justification.
    pub rationale: String,
    /// Non-transferable external authorization citation.
    pub grant_ref: String,
    /// Explicit treatment review expiry, if supplied.
    pub expires_at: Option<u64>,
}

fn validate_text(value: &str) -> Result<(), FindingGovernanceError> {
    if value.trim().is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(lifecycle_error(
            "INVALID_INPUT",
            "invalid review rationale or grant reference",
        ));
    }
    Ok(())
}

impl AdmissionRecord {
    /// Returns a stable content identity; loading the record establishes no permission.
    /// # Errors
    /// Refuses malformed identities and mismatched lifecycle anchors.
    pub fn digest(&self) -> Result<String, FindingGovernanceError> {
        let computed = self.compute_digest()?;
        if self.record_ref != computed {
            return Err(lifecycle_error(
                "INTEGRITY_ERROR",
                "admission record digest differs",
            ));
        }
        Ok(computed)
    }

    fn compute_digest(&self) -> Result<String, FindingGovernanceError> {
        for value in [
            &self.assessment_ref,
            &self.review_ref,
            &self.subject_ref,
            &self.introduced_scope_ref,
            &self.scope_slot_ref,
        ] {
            validate_digest(value)?;
        }
        self.original.validate()?;
        self.target.validate()?;
        self.lifecycle_anchor.validate()?;
        validate_text(&self.grant_ref)?;
        validate_text(&self.rationale)?;
        if self.target.state_ref != self.lifecycle_anchor.from_state
            || self.target.source_ref != self.lifecycle_anchor.subject_ref
            || self
                .expires_at
                .is_some_and(|time| time > 9_007_199_254_740_991)
        {
            return Err(lifecycle_error(
                "INVALID_BINDING",
                "admission record binding differs",
            ));
        }
        let mut unsigned = self.clone();
        unsigned.record_ref.clear();
        lifecycle_digest(&unsigned)
    }
}

impl AdmissionReview {
    /// Parses bounded explicit review intent.
    /// # Errors
    /// Refuses malformed, duplicated and oversized review inputs.
    pub fn from_json_str(source: &str) -> Result<Self, FindingGovernanceError> {
        if source.len() > super::MAX_GOVERNANCE_BYTES {
            return Err(lifecycle_error(
                "RESOURCE_LIMIT",
                "review exceeds byte limit",
            ));
        }
        let review = crate::wire::parse_public_json::<Self>(source)
            .map_err(|error| lifecycle_error("INVALID_INPUT", &error.to_string()))?;
        review.validate()?;
        Ok(review)
    }

    fn validate(&self) -> Result<(), FindingGovernanceError> {
        validate_digest(&self.assessment_ref)?;
        if self.schema != ADMISSION_REVIEW_SCHEMA || self.schema_version != 1 {
            return Err(lifecycle_error(
                "UNSUPPORTED_VERSION",
                "unknown admission review",
            ));
        }
        if self.decisions.is_empty() || self.decisions.len() > MAX_ADMISSION_FINDINGS {
            return Err(lifecycle_error(
                "RESOURCE_LIMIT",
                "explicit review population outside bounds",
            ));
        }
        if self
            .expires_at
            .is_some_and(|time| time > 9_007_199_254_740_991)
        {
            return Err(lifecycle_error(
                "INVALID_INPUT",
                "review time is outside the public integer range",
            ));
        }
        let mut ids = BTreeSet::new();
        for item in &self.decisions {
            validate_digest(&item.finding_id)?;
            validate_text(&item.rationale)?;
            if !ids.insert(&item.finding_id) {
                return Err(lifecycle_error(
                    "CONFLICTING_REVIEW",
                    "duplicate finding review",
                ));
            }
            if let Some(reference) = &item.grant_ref {
                validate_text(reference)?;
            }
        }
        lifecycle_bytes(self)?;
        Ok(())
    }

    /// Derives exact requested postimage records; this does not authenticate the reviewer.
    /// # Errors
    /// Refuses stale, expired, unrelated, ambiguous or ineligible selections.
    pub fn records(
        &self,
        assessment: &AdmissionAssessment,
        time: Option<u64>,
    ) -> Result<BTreeMap<String, AdmissionRecord>, FindingGovernanceError> {
        self.validate_binding(assessment)?;
        if self
            .expires_at
            .is_some_and(|expires| time.is_none_or(|now| expires <= now))
        {
            return Err(lifecycle_error(
                "EXPIRED_OR_TIME_REQUIRED",
                "review requires current trusted time",
            ));
        }
        let mut ordered = self.clone();
        ordered
            .decisions
            .sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
        let review_ref = lifecycle_digest(&ordered)?;
        let by_id: BTreeMap<_, _> = assessment
            .findings
            .iter()
            .map(|row| (&row.finding_id, row))
            .collect();
        let mut records = BTreeMap::new();
        for item in &ordered.decisions {
            let row = by_id.get(&item.finding_id).ok_or_else(|| {
                lifecycle_error(
                    "UNRELATED_FINDING",
                    "review targets a finding outside the assessment",
                )
            })?;
            if item.disposition != AdmissionDisposition::AcceptExisting {
                continue;
            }
            let unsupported = || {
                lifecycle_error(
                    "NOT_ADMISSIBLE",
                    "finding has no supported introduction proof",
                )
            };
            let mut record = AdmissionRecord {
                record_ref: String::new(),
                assessment_ref: self.assessment_ref.clone(),
                review_ref: review_ref.clone(),
                original: assessment.original.clone().ok_or_else(unsupported)?,
                target: assessment.target.clone().ok_or_else(unsupported)?,
                subject_ref: assessment.subject_ref.clone().ok_or_else(unsupported)?,
                introduced_scope_ref: row.introduced_scope_ref.clone().ok_or_else(unsupported)?,
                scope_slot_ref: row.scope_slot_ref.clone().ok_or_else(unsupported)?,
                lifecycle_anchor: row.anchor.clone().ok_or_else(unsupported)?,
                rationale: item.rationale.clone(),
                grant_ref: item.grant_ref.clone().ok_or_else(|| {
                    lifecycle_error(
                        "GRANT_REFERENCE_REQUIRED",
                        "review needs an explicit external citation",
                    )
                })?,
                expires_at: self.expires_at,
            };
            record.record_ref = record.compute_digest()?;
            records.insert(item.finding_id.clone(), record);
        }
        Ok(records)
    }

    /// Validates a review citation's exact comparison and selectors without assuming approval.
    /// # Errors
    /// Refuses malformed, inconsistent, stale or unrelated review records.
    pub fn validate_binding(
        &self,
        assessment: &AdmissionAssessment,
    ) -> Result<(), FindingGovernanceError> {
        self.validate()?;
        if assessment.digest()? != self.assessment_ref {
            return Err(lifecycle_error(
                "STALE_REVIEW",
                "review targets another assessment",
            ));
        }
        if self.decisions.iter().any(|item| {
            assessment
                .findings
                .binary_search_by(|row| row.finding_id.cmp(&item.finding_id))
                .is_err()
        }) {
            return Err(lifecycle_error(
                "UNRELATED_FINDING",
                "review targets a finding outside the assessment",
            ));
        }
        Ok(())
    }
}

impl super::FindingGovernanceDocument {
    /// Retained requirements and original review decisions, independent of enforcement.
    #[must_use]
    pub fn admissions(&self) -> &BTreeMap<String, AdmissionRecord> {
        &self.admissions
    }

    /// Proof references for deliberately retired admissions; originals are retained separately.
    #[must_use]
    pub fn admission_retirements(&self) -> &BTreeMap<String, RetirementEvidenceV2> {
        &self.admission_retirements
    }

    /// Produces a draft governance postimage. Only the migration/authority boundary can apply it.
    /// # Errors
    /// Refuses empty selection, historical collisions and compatibility-breaking upgrades.
    pub fn propose_admissions(
        &self,
        assessment: &AdmissionAssessment,
        review: &AdmissionReview,
        time: Option<u64>,
    ) -> Result<Self, FindingGovernanceError> {
        self.validate()?;
        let selected = review.records(assessment, time)?;
        if selected.is_empty() {
            return Err(lifecycle_error(
                "NO_ADMISSIONS_SELECTED",
                "no finding was explicitly accepted",
            ));
        }
        if self.lifecycle.is_none() && (self.baseline.is_some() || !self.exceptions.is_empty()) {
            return Err(lifecycle_error(
                "LEGACY_GOVERNANCE_REQUIRES_MIGRATION",
                "legacy unanchored authority needs an independent reviewed transition",
            ));
        }
        let mut next = self.clone();
        next.schema = FINDING_GOVERNANCE_SCHEMA_V3.into();
        next.schema_version = 3;
        next.lifecycle
            .get_or_insert_with(super::LifecycleRecords::default);
        for (id, record) in selected {
            if next.admissions.insert(id, record).is_some() {
                return Err(lifecycle_error(
                    "PREVIOUSLY_GOVERNED",
                    "original admission cannot be replaced",
                ));
            }
        }
        next.validate()?;
        Ok(next)
    }

    pub(super) fn validate_admissions(&self) -> Result<(), FindingGovernanceError> {
        let prior: BTreeSet<_> = self
            .baseline
            .iter()
            .flat_map(|baseline| {
                baseline
                    .active_entries
                    .iter()
                    .map(|entry| entry.finding_id.as_str())
                    .chain(
                        baseline
                            .retired_entries
                            .iter()
                            .map(|entry| entry.finding_id.as_str()),
                    )
            })
            .chain(
                self.exceptions
                    .iter()
                    .map(|entry| entry.finding_id.as_str()),
            )
            .collect();
        for (id, record) in &self.admissions {
            record.digest()?;
            if id != &record.lifecycle_anchor.finding_id || prior.contains(id.as_str()) {
                return Err(lifecycle_error(
                    "PREVIOUSLY_GOVERNED",
                    "admission overlaps existing finding history or has a mismatched identity",
                ));
            }
        }
        for (id, evidence) in &self.admission_retirements {
            self.validate_admission_retirement(id, evidence)?;
        }
        Ok(())
    }

    fn validate_admission_retirement(
        &self,
        id: &str,
        evidence: &RetirementEvidenceV2,
    ) -> Result<(), FindingGovernanceError> {
        evidence.validate()?;
        let anchor = &self
            .admissions
            .get(id)
            .ok_or(FindingGovernanceError::RetirementEvidenceRequired)?
            .lifecycle_anchor;
        if evidence.finding_id != id
            || !matches!(
                evidence.outcome,
                RetirementOutcome::Resolved | RetirementOutcome::SubjectRemoved
            )
            || evidence.comparison_basis.from_state != anchor.from_state
            || evidence.comparison_basis.anchor_ref.as_ref() != Some(&lifecycle_digest(anchor)?)
            || evidence.from_subject.as_ref() != Some(&anchor.subject_ref)
            || evidence.original_authority_ref.as_ref() != Some(&anchor.original_authority_ref)
            || evidence.claim_scope_ref.as_ref() != Some(&anchor.claim_scope_ref)
        {
            return Err(FindingGovernanceError::RetirementEvidenceRequired);
        }
        Ok(())
    }

    /// Prepares comparable retirement of specifically selected admission records.
    /// The exact postimage remains subject to existing protected migration review.
    /// # Errors
    /// Refuses missing original proof, stale governance and rewriting earlier history.
    pub fn retire_admissions_with_evidence(
        &mut self,
        evidence: &[RetirementEvidenceV2],
    ) -> Result<(), FindingGovernanceError> {
        if evidence.is_empty() || evidence.len() > MAX_ADMISSION_FINDINGS {
            return Err(FindingGovernanceError::RetirementEvidenceRequired);
        }
        let original = self.authority_digest()?;
        let mut next = self.clone();
        for record in evidence {
            self.validate_admission_retirement(&record.finding_id, record)?;
            if record.comparison_basis.governance_ref != original
                || next
                    .admission_retirements
                    .insert(record.finding_id.clone(), record.clone())
                    .is_some()
            {
                return Err(FindingGovernanceError::RetirementEvidenceRequired);
            }
        }
        next.validate()?;
        *self = next;
        Ok(())
    }
}
