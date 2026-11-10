//! Neutral, bounded lifecycle records. Semantic comparison belongs to State Governance.
use super::{
    BTreeMap, BTreeSet, BaselineEntry, BaselineMutationSummary, CanonicalFinding, Deserialize,
    ExceptionState, FINDING_GOVERNANCE_SCHEMA, FindingGovernanceDocument, FindingGovernanceError,
    FindingIdentityEligibility, RetiredBaselineEntry, RuleId, Serialize, is_strictly_sorted,
    validate_digest,
};
use sha2::{Digest, Sha256};

/// Current authored lifecycle schema; v1 retains its original reader and bytes.
pub const FINDING_GOVERNANCE_SCHEMA_V2: &str = "urn:fortress:schema:v2:finding-governance";
/// Aggregate wire admission, independent of performance certification.
pub const MAX_GOVERNANCE_BYTES: usize = 8 * 1024 * 1024;
/// Aggregate number of governed identities and retained events.
pub const MAX_GOVERNANCE_RECORDS: usize = 50_000;
pub(super) fn lifecycle_error(code: &str, message: &str) -> FindingGovernanceError {
    FindingGovernanceError::Lifecycle {
        code: code.into(),
        message: message.into(),
    }
}
fn text(value: &str) -> Result<(), FindingGovernanceError> {
    if value.trim().is_empty() || value.len() > 4096 {
        Err(lifecycle_error(
            "INVALID_INPUT",
            "empty or oversized lifecycle text",
        ))
    } else {
        Ok(())
    }
}
/// JCS identity for neutral lifecycle data; never an authenticity assertion.
/// # Errors
/// Refuses oversized or unserializable records.
pub fn lifecycle_digest<T: Serialize>(value: &T) -> Result<String, FindingGovernanceError> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(lifecycle_bytes(value)?)
    ))
}
/// Bounded public JCS serialization.
/// # Errors
/// Refuses aggregate byte exhaustion before allocating canonical output.
pub fn lifecycle_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, FindingGovernanceError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(b.len())
                .filter(|n| *n <= MAX_GOVERNANCE_BYTES)
                .ok_or_else(|| std::io::Error::other("lifecycle byte limit"))?;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter(0), value).map_err(|_| {
        lifecycle_error(
            "RESOURCE_LIMIT",
            "lifecycle serialization admission exceeded",
        )
    })?;
    serde_json_canonicalizer::to_vec(value).map_err(FindingGovernanceError::Json)
}
/// Stable semantic finding metadata, excluding location, message and witness order.
/// # Errors
/// Refuses malformed or oversized serialization.
pub fn finding_semantic_ref(f: &CanonicalFinding) -> Result<String, FindingGovernanceError> {
    lifecycle_digest(&(f.rule_id(), f.entities(), f.violation_discriminator()))
}

/// Original exact admission and governing meaning of one stable finding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingAnchor {
    /// Original stable finding identity.
    pub finding_id: String,
    /// Original rule, never inferred from an exception message.
    pub rule_id: String,
    /// Content identity of the original complete comparison input.
    pub from_state: String,
    /// Original exact source subject.
    pub subject_ref: String,
    /// Original aggregate governing authority.
    pub original_authority_ref: String,
    /// Comparable rule/policy/profile/context definition, excluding source and disposition history.
    pub meaning_ref: String,
    /// Stable claim slot that actually reported this finding.
    pub claim_scope_ref: String,
    /// Original stable semantic finding metadata.
    pub identity_ref: String,
    /// Original governed subjects; no occurrence paths or line numbers.
    pub subject_refs: Vec<String>,
}
impl FindingAnchor {
    /// Checks exact identity grammar and bounded ordered scope.
    /// # Errors
    /// Rejects malformed or conflicting metadata.
    pub fn validate(&self) -> Result<(), FindingGovernanceError> {
        for d in [
            &self.finding_id,
            &self.from_state,
            &self.subject_ref,
            &self.original_authority_ref,
            &self.meaning_ref,
            &self.identity_ref,
        ] {
            validate_digest(d)?;
        }
        RuleId::parse(&self.rule_id)
            .map_err(|_| FindingGovernanceError::InvalidRule(self.rule_id.clone().into()))?;
        text(&self.claim_scope_ref)?;
        if !is_strictly_sorted(&self.subject_refs)
            || self.subject_refs.len() > MAX_GOVERNANCE_RECORDS
        {
            return Err(lifecycle_error(
                "IDENTITY_AMBIGUOUS",
                "unordered or oversized subject identities",
            ));
        }
        for s in &self.subject_refs {
            text(s)?;
        }
        Ok(())
    }
    /// Same semantic occurrence and governing definition; source bytes may legitimately change.
    #[must_use]
    pub fn comparable_to(&self, next: &Self) -> bool {
        self.finding_id == next.finding_id
            && self.rule_id == next.rule_id
            && self.meaning_ref == next.meaning_ref
            && self.claim_scope_ref == next.claim_scope_ref
            && self.identity_ref == next.identity_ref
            && self.subject_refs == next.subject_refs
    }
}
/// Finding disappearance classifications; only two can support prune.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetirementOutcome {
    /// The original violation remains observed.
    Present,
    /// A sufficient comparable proof establishes no supported violation.
    Resolved,
    /// Complete comparable observation establishes original subject removal.
    SubjectRemoved,
    /// Evidence or relevant coverage is unavailable.
    NotObserved,
    /// Original governing rule or policy was removed.
    PolicyRetired,
    /// Observation scope excludes original subjects.
    ScopeExcluded,
    /// Original Standard/profile/context/evaluator meaning cannot be compared.
    AuthorityIncomparable,
    /// Stable semantic pairing is ambiguous.
    IdentityAmbiguous,
}
/// Exact derivation inputs, separate from a portable proof's authenticity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementComparisonBasis {
    /// Exact original input.
    pub from_state: String,
    /// Exact current input.
    pub to_state: String,
    /// Existing four-axis comparator output identity.
    pub transition_ref: String,
    /// Exact authored governance preimage, preventing replay after maintenance.
    pub governance_ref: String,
    /// Original admitted anchor identity; absent for legacy unanchored residue.
    pub anchor_ref: Option<String>,
}
/// Comparable retirement record. Legacy transition-v1 observations remain non-prunable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementEvidenceV2 {
    /// Comparable retirement v2; v1 observations retain their original non-prunable meaning.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Exact standalone wire version.
    pub schema_version: u16,
    /// Original stable identity.
    pub finding_id: String,
    /// Original authority, absent only when historical anchors are unavailable.
    pub original_authority_ref: Option<String>,
    /// Original exact subject.
    pub from_subject: Option<String>,
    /// Current exact subject, never silently a selected historical PASS.
    pub to_subject: Option<String>,
    /// Original rule or semantic slot.
    pub claim_scope_ref: Option<String>,
    /// Exact comparison and governance binding.
    pub comparison_basis: RetirementComparisonBasis,
    /// Supported classification or explicit unresolved state.
    pub outcome: RetirementOutcome,
    /// Existing sufficient evidence and complete subject-inventory citations.
    pub proof_refs: Vec<String>,
    /// Evidence-backed explanations, including missing premises.
    pub reasons: Vec<String>,
    /// Integrity, semantic and authorization limitations.
    pub limitations: Vec<String>,
}
impl RetirementEvidenceV2 {
    /// Validates wire safety, exact bindings and favorable-proof requirements.
    /// # Errors
    /// Refuses unsupported versions, incomplete favorable evidence and malformed inputs.
    pub fn validate(&self) -> Result<(), FindingGovernanceError> {
        if self.schema != "urn:fortress:derived:v2:retirement-evidence" || self.schema_version != 2
        {
            return Err(FindingGovernanceError::UnsupportedSchema);
        }
        for d in [
            &self.finding_id,
            &self.comparison_basis.from_state,
            &self.comparison_basis.to_state,
            &self.comparison_basis.transition_ref,
            &self.comparison_basis.governance_ref,
        ] {
            validate_digest(d)?;
        }
        for d in [
            &self.original_authority_ref,
            &self.from_subject,
            &self.to_subject,
            &self.comparison_basis.anchor_ref,
        ]
        .into_iter()
        .flatten()
        {
            validate_digest(d)?;
        }
        if !is_strictly_sorted(&self.proof_refs)
            || self.proof_refs.len() > MAX_GOVERNANCE_RECORDS
            || self.reasons.is_empty()
            || self.reasons.len() > 64
            || self.limitations.len() > 64
        {
            return Err(lifecycle_error(
                "INVALID_INPUT",
                "unordered proof references or invalid explanation inventory",
            ));
        }
        for s in self
            .proof_refs
            .iter()
            .chain(self.reasons.iter())
            .chain(self.limitations.iter())
            .chain(self.claim_scope_ref.iter())
        {
            text(s)?;
        }
        for r in &self.proof_refs {
            validate_digest(r)?;
        }
        if matches!(
            self.outcome,
            RetirementOutcome::Resolved | RetirementOutcome::SubjectRemoved
        ) && (self.proof_refs.is_empty()
            || self.original_authority_ref.is_none()
            || self.from_subject.is_none()
            || self.to_subject.is_none()
            || self.claim_scope_ref.is_none()
            || self.comparison_basis.anchor_ref.is_none())
        {
            return Err(lifecycle_error(
                "RETIREMENT_EVIDENCE_REQUIRED",
                "favorable retirement omitted comparable anchors or proof",
            ));
        }
        lifecycle_bytes(self)?;
        Ok(())
    }
    /// Parses a public record without treating its claims as authenticated authorization.
    /// # Errors
    /// Rejects duplicate keys, unknown fields and invalid proofs/bindings.
    pub fn from_json_str(s: &str) -> Result<Self, FindingGovernanceError> {
        if s.len() > MAX_GOVERNANCE_BYTES {
            return Err(lifecycle_error("RESOURCE_LIMIT", "retirement byte limit"));
        }
        let r: Self = crate::wire::parse_public_json(s)
            .map_err(|e| lifecycle_error("INVALID_INPUT", &e.to_string()))?;
        r.validate()?;
        Ok(r)
    }
    /// Content identity includes every explanation and original binding.
    /// # Errors
    /// Refuses malformed records.
    pub fn digest(&self) -> Result<String, FindingGovernanceError> {
        self.validate()?;
        lifecycle_digest(self)
    }
}
/// Explicit time policy; evaluation never reads the machine clock.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionReviewPolicy {
    /// At or after this input time the exception needs review.
    pub review_at: Option<u64>,
    /// At or after this input time it cannot apply.
    pub expires_at: Option<u64>,
}
impl ExceptionReviewPolicy {
    /// Deterministic review status; missing time never means current.
    #[must_use]
    pub fn state_at(&self, time: Option<u64>) -> &'static str {
        if self.review_at.is_none() && self.expires_at.is_none() {
            return "CURRENT";
        }
        let Some(t) = time else {
            return "TIME_REQUIRED";
        };
        if self.expires_at.is_some_and(|v| t >= v) {
            "EXPIRED"
        } else if self.review_at.is_some_and(|v| t >= v) {
            "REVIEW_REQUIRED"
        } else {
            "CURRENT"
        }
    }
    fn validate(&self) -> Result<(), FindingGovernanceError> {
        if self
            .review_at
            .into_iter()
            .chain(self.expires_at)
            .any(|v| v > 9_007_199_254_740_991)
            || self
                .review_at
                .zip(self.expires_at)
                .is_some_and(|(r, e)| r > e)
        {
            return Err(lifecycle_error(
                "INVALID_INPUT",
                "invalid explicit exception review bounds",
            ));
        }
        Ok(())
    }
}
/// Finding-specific authored review and exact original authority. Reference is not approval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionReview {
    /// Exact original finding scope.
    pub anchor: Option<FindingAnchor>,
    /// External authorization citation, never self-authenticated.
    pub grant_reference: String,
    /// Explicit review/expiry requirements.
    pub policy: ExceptionReviewPolicy,
    /// Deliberate retirement rationale; does not imply semantic resolution.
    pub retirement_reason: Option<String>,
}
/// Immutable original entry retained alongside the resolution evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredFindingRecord {
    /// Full original baseline metadata, never reconstructed from current source.
    pub original_entry: BaselineEntry,
    /// Original admission retained unchanged.
    pub anchor: FindingAnchor,
    /// Exact supported comparison used for retirement.
    pub evidence: RetirementEvidenceV2,
}
/// Current authored lifecycle state; event archives are not an alternate baseline.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRecords {
    /// Original active and retired admissions, keyed by stable finding identity.
    pub anchors: BTreeMap<String, FindingAnchor>,
    /// Full original metadata and evidence for deliberate retirements.
    pub retirements: BTreeMap<String, RetiredFindingRecord>,
    /// Exact finding-specific exception reviews, including retired history.
    pub exception_reviews: BTreeMap<String, ExceptionReview>,
}

/// Explicit immutable assessment inputs. No deserializer can create trusted grants.
#[derive(Clone, Debug)]
pub struct LifecycleContext {
    governance_ref: String,
    anchors: BTreeMap<String, FindingAnchor>,
    assessment_time: Option<u64>,
    verified_exceptions: BTreeMap<String, (String, String)>,
}
impl LifecycleContext {
    /// Composes observed current meanings and explicit assessment time, with no authorization.
    /// # Errors
    /// Refuses invalid anchors, time overflow and resource exhaustion.
    pub fn observed(
        governance_ref: String,
        anchors: BTreeMap<String, FindingAnchor>,
        assessment_time: Option<u64>,
    ) -> Result<Self, FindingGovernanceError> {
        validate_digest(&governance_ref)?;
        if anchors.len() > MAX_GOVERNANCE_RECORDS
            || assessment_time.is_some_and(|t| t > 9_007_199_254_740_991)
        {
            return Err(lifecycle_error(
                "RESOURCE_LIMIT",
                "invalid lifecycle context admission",
            ));
        }
        for (id, a) in &anchors {
            a.validate()?;
            if id != &a.finding_id {
                return Err(lifecycle_error(
                    "IDENTITY_AMBIGUOUS",
                    "current anchor key differs",
                ));
            }
        }
        Ok(Self {
            governance_ref,
            anchors,
            assessment_time,
            verified_exceptions: BTreeMap::new(),
        })
    }
    pub(super) fn validate(
        &self,
        authority: Option<&FindingGovernanceDocument>,
    ) -> Result<(), FindingGovernanceError> {
        if authority
            .map(FindingGovernanceDocument::authority_digest)
            .transpose()?
            .as_ref()
            != Some(&self.governance_ref)
        {
            return Err(lifecycle_error(
                "STALE_GOVERNANCE",
                "lifecycle context targets another authority preimage",
            ));
        }
        Ok(())
    }
    pub(super) fn baseline_comparable(
        &self,
        document: &FindingGovernanceDocument,
        id: &str,
    ) -> bool {
        document
            .lifecycle
            .as_ref()
            .and_then(|r| r.anchors.get(id))
            .zip(self.anchors.get(id))
            .is_some_and(|(a, b)| a.comparable_to(b))
    }
    pub(super) fn matches_finding(&self, finding: &CanonicalFinding) -> bool {
        self.anchors.get(finding.finding_id()).is_some_and(|a| {
            finding_semantic_ref(finding).is_ok_and(|id| id == a.identity_ref)
                && a.rule_id == finding.rule_id()
                && a.subject_refs == finding.entities()
        })
    }
    /// Used only by the composition-root adapter after checking opaque AUTHORITY grants.
    pub(crate) fn admit_exception(&mut self, id: &str, proposal_ref: String, receipt_ref: String) {
        self.verified_exceptions
            .insert(id.into(), (proposal_ref, receipt_ref));
    }
}
/// Review, semantic applicability and authorization are independent facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionReviewResult {
    /// Exact exception identity.
    pub exception_id: String,
    /// Original raw finding remains a violation.
    pub finding_id: String,
    /// Authored citation, never a grant by itself.
    pub authority_reference: String,
    /// `CURRENT`, `EXPIRED`, `REVIEW_REQUIRED`, `TIME_REQUIRED` or `RETIRED`.
    pub review_state: String,
    /// `COMPARABLE`, `NOT_COMPARABLE` or `LEGACY_UNANCHORED`.
    pub scope_state: String,
    /// `VERIFIED_EXTERNAL`, `UNVERIFIED_REFERENCE` or `LEGACY_REFERENCE_NOT_REVERIFIED`.
    pub authorization_state: String,
    /// Exact protected proposal actually validated by the host; absent for repository assertions.
    pub authorization_proposal_ref: Option<String>,
    /// Content identity of the validated host receipts, retained as provenance only.
    pub authorization_evidence_ref: Option<String>,
    /// Whether this exact exception affects this assessment's enforcement.
    pub applicable: bool,
}
pub(super) fn review_exceptions(
    document: &FindingGovernanceDocument,
    context: Option<&LifecycleContext>,
) -> Vec<ExceptionReviewResult> {
    document
        .exceptions
        .iter()
        .map(|e| {
            let review = document
                .lifecycle
                .as_ref()
                .and_then(|r| r.exception_reviews.get(&e.id));
            let comparable = review.zip(context).is_some_and(|(r, c)| {
                c.anchors.get(&e.finding_id).is_some_and(|a| {
                    r.anchor
                        .as_ref()
                        .is_some_and(|original| original.comparable_to(a))
                })
            });
            let legacy = document.lifecycle.is_none();
            let review_state = if e.state == ExceptionState::Retired {
                "RETIRED"
            } else {
                review.map_or("REVIEW_REQUIRED", |r| {
                    r.policy.state_at(context.and_then(|c| c.assessment_time))
                })
            };
            let verification = context.and_then(|c| c.verified_exceptions.get(&e.id));
            let verified = verification.is_some();
            ExceptionReviewResult {
                exception_id: e.id.clone(),
                finding_id: e.finding_id.clone(),
                authority_reference: e.authority.clone(),
                review_state: review_state.into(),
                scope_state: if legacy {
                    "LEGACY_UNANCHORED"
                } else if comparable {
                    "COMPARABLE"
                } else {
                    "NOT_COMPARABLE"
                }
                .into(),
                authorization_state: if legacy {
                    "LEGACY_REFERENCE_NOT_REVERIFIED"
                } else if verified {
                    "VERIFIED_EXTERNAL"
                } else {
                    "UNVERIFIED_REFERENCE"
                }
                .into(),
                authorization_proposal_ref: verification.map(|v| v.0.clone()),
                authorization_evidence_ref: verification.map(|v| v.1.clone()),
                applicable: if legacy {
                    e.state == ExceptionState::Active
                } else {
                    comparable && verified && review_state == "CURRENT"
                },
            }
        })
        .collect()
}
impl FindingGovernanceDocument {
    /// Current authority with no implied admission of legacy records.
    #[must_use]
    pub fn empty_current() -> Self {
        let mut d = Self::empty();
        d.upgrade_lifecycle();
        d
    }
    fn upgrade_lifecycle(&mut self) -> &mut LifecycleRecords {
        self.schema = FINDING_GOVERNANCE_SCHEMA_V2.into();
        self.schema_version = 2;
        self.lifecycle.get_or_insert_with(LifecycleRecords::default)
    }
    /// Versioned records; absent legacy anchors stay absent.
    #[must_use]
    pub fn lifecycle(&self) -> Option<&LifecycleRecords> {
        self.lifecycle.as_ref()
    }
    /// Reviews exceptions against explicit current scope/time and externally admitted grants.
    /// # Errors
    /// Refuses a context bound to another governance preimage.
    pub fn review_exceptions(
        &self,
        context: &LifecycleContext,
    ) -> Result<Vec<ExceptionReviewResult>, FindingGovernanceError> {
        context.validate(Some(self))?;
        Ok(review_exceptions(self, Some(context)))
    }
    /// Exact current authored preimage used by proposals and retirement evidence.
    /// # Errors
    /// Refuses serialization or validation failures.
    pub fn authority_digest(&self) -> Result<String, FindingGovernanceError> {
        self.validate()?;
        lifecycle_digest(self)
    }
    /// Creates a bounded original baseline with exact owner-produced admissions.
    /// # Errors
    /// Rejects replacement, missing/ambiguous anchors and mismatched finding metadata.
    pub fn create_anchored_baseline(
        &mut self,
        standard_id: &str,
        edition: &str,
        findings: &[CanonicalFinding],
        anchors: BTreeMap<String, FindingAnchor>,
    ) -> Result<BaselineMutationSummary, FindingGovernanceError> {
        if self.baseline.is_some() {
            return Err(FindingGovernanceError::BaselineAlreadyExists);
        }
        let mut next = self.clone();
        let original_records = next.lifecycle.take();
        next.schema = FINDING_GOVERNANCE_SCHEMA.into();
        next.schema_version = 1;
        next.lifecycle = None;
        let result = next.create_baseline(standard_id, edition, findings)?;
        let current = findings
            .iter()
            .filter(|f| f.identity_eligibility() == FindingIdentityEligibility::Eligible)
            .map(|f| (f.finding_id(), f))
            .collect::<BTreeMap<_, _>>();
        if anchors.len() != current.len() {
            return Err(lifecycle_error(
                "ANCHOR_REQUIRED",
                "every eligible original finding requires exactly one anchor",
            ));
        }
        for (id, a) in &anchors {
            a.validate()?;
            let f = current.get(id.as_str()).ok_or_else(|| {
                lifecycle_error("ANCHOR_REQUIRED", "anchor targets another finding")
            })?;
            if id != &a.finding_id
                || a.rule_id != f.rule_id()
                || a.identity_ref != finding_semantic_ref(f)?
                || a.subject_refs != f.entities()
            {
                return Err(lifecycle_error(
                    "IDENTITY_AMBIGUOUS",
                    "anchor semantic metadata differs",
                ));
            }
        }
        next.lifecycle = original_records;
        next.upgrade_lifecycle().anchors.extend(anchors);
        next.validate()?;
        *self = next;
        Ok(result)
    }
    /// Applies explicitly selected producer-validated retirement records, atomically in memory.
    /// Callers loading wire records must rederive them from authoritative compared states.
    /// This validates neutral records; it neither authenticates producers nor grants permission.
    /// # Errors
    /// Rejects stale governance, missing anchors, noncomparable proof and attempts to expand history.
    pub fn prune_with_evidence(
        &mut self,
        evidence: &[RetirementEvidenceV2],
    ) -> Result<BaselineMutationSummary, FindingGovernanceError> {
        let baseline = self
            .baseline
            .as_ref()
            .ok_or(FindingGovernanceError::BaselineAbsent)?;
        if evidence.is_empty() || evidence.len() > MAX_GOVERNANCE_RECORDS {
            return Err(FindingGovernanceError::RetirementEvidenceRequired);
        }
        let expected = self.authority_digest()?;
        let records = self
            .lifecycle
            .as_ref()
            .ok_or(FindingGovernanceError::RetirementEvidenceRequired)?;
        let entries = baseline
            .active_entries
            .iter()
            .map(|e| (e.finding_id.as_str(), e))
            .collect::<BTreeMap<_, _>>();
        let mut ids = BTreeSet::new();
        for e in evidence {
            e.validate()?;
            let a = records
                .anchors
                .get(&e.finding_id)
                .ok_or(FindingGovernanceError::RetirementEvidenceRequired)?;
            if !ids.insert(e.finding_id.clone())
                || !entries.contains_key(e.finding_id.as_str())
                || !matches!(
                    e.outcome,
                    RetirementOutcome::Resolved | RetirementOutcome::SubjectRemoved
                )
                || e.comparison_basis.governance_ref != expected
                || e.comparison_basis.from_state != a.from_state
                || e.comparison_basis.anchor_ref.as_ref() != Some(&lifecycle_digest(a)?)
                || e.from_subject.as_ref() != Some(&a.subject_ref)
                || e.original_authority_ref.as_ref() != Some(&a.original_authority_ref)
                || e.claim_scope_ref.as_ref() != Some(&a.claim_scope_ref)
            {
                return Err(FindingGovernanceError::RetirementEvidenceRequired);
            }
        }
        let mut next = self.clone();
        let records = next
            .lifecycle
            .as_mut()
            .ok_or(FindingGovernanceError::RetirementEvidenceRequired)?;
        let baseline = next
            .baseline
            .as_mut()
            .ok_or(FindingGovernanceError::BaselineAbsent)?;
        for e in evidence {
            let entry = entries
                .get(e.finding_id.as_str())
                .ok_or(FindingGovernanceError::RetirementEvidenceRequired)?;
            records.retirements.insert(
                e.finding_id.clone(),
                RetiredFindingRecord {
                    original_entry: (*entry).clone(),
                    anchor: records
                        .anchors
                        .get(&e.finding_id)
                        .ok_or(FindingGovernanceError::RetirementEvidenceRequired)?
                        .clone(),
                    evidence: e.clone(),
                },
            );
            baseline.retired_entries.push(RetiredBaselineEntry {
                finding_id: entry.finding_id.clone(),
                rule_id: entry.rule_id.clone(),
            });
        }
        baseline
            .active_entries
            .retain(|e| !ids.contains(&e.finding_id));
        baseline.retired_entries.sort();
        let active = baseline.active_entries.len();
        next.validate()?;
        *self = next;
        Ok(BaselineMutationSummary {
            active,
            removed: evidence.len(),
            ineligible: 0,
        })
    }
    /// Adds one reviewed current exception proposal; its reference alone cannot authorize it.
    /// # Errors
    /// Rejects duplicate identities, unanchored targets and malformed review policies.
    #[allow(clippy::too_many_arguments)]
    pub fn create_reviewed_exception(
        &mut self,
        id: &str,
        finding_id: &str,
        authority: &str,
        rationale: &str,
        findings: &[CanonicalFinding],
        anchor: FindingAnchor,
        policy: ExceptionReviewPolicy,
    ) -> Result<(), FindingGovernanceError> {
        anchor.validate()?;
        policy.validate()?;
        text(authority)?;
        text(rationale)?;
        if anchor.finding_id != finding_id {
            return Err(lifecycle_error(
                "ANCHOR_REQUIRED",
                "exception anchor differs from target",
            ));
        }
        let f = findings
            .iter()
            .find(|f| f.finding_id() == finding_id)
            .ok_or_else(|| FindingGovernanceError::UnknownFinding(finding_id.into()))?;
        if anchor.identity_ref != finding_semantic_ref(f)?
            || anchor.rule_id != f.rule_id()
            || anchor.subject_refs != f.entities()
        {
            return Err(lifecycle_error(
                "IDENTITY_AMBIGUOUS",
                "exception semantic target differs",
            ));
        }
        let mut next = self.clone();
        let original_records = next.lifecycle.take();
        next.schema = FINDING_GOVERNANCE_SCHEMA.into();
        next.schema_version = 1;
        next.create_exception(id, finding_id, authority, rationale, findings)?;
        next.lifecycle = original_records;
        next.upgrade_lifecycle().exception_reviews.insert(
            id.into(),
            ExceptionReview {
                anchor: Some(anchor),
                grant_reference: authority.into(),
                policy,
                retirement_reason: None,
            },
        );
        next.validate()?;
        *self = next;
        Ok(())
    }
    /// Retires an exception explicitly without declaring that the original violation resolved.
    /// # Errors
    /// Refuses missing review history and duplicate retirement.
    pub fn retire_reviewed_exception(
        &mut self,
        id: &str,
        reason: &str,
    ) -> Result<(), FindingGovernanceError> {
        text(reason)?;
        let mut next = self.clone();
        let original_records = next.lifecycle.take();
        next.schema = FINDING_GOVERNANCE_SCHEMA.into();
        next.schema_version = 1;
        next.retire_exception(id)?;
        let reference = next
            .exceptions
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| FindingGovernanceError::UnknownException(id.into()))?
            .authority
            .clone();
        next.lifecycle = original_records;
        let r = next
            .upgrade_lifecycle()
            .exception_reviews
            .entry(id.into())
            .or_insert(ExceptionReview {
                anchor: None,
                grant_reference: reference,
                policy: ExceptionReviewPolicy {
                    review_at: None,
                    expires_at: None,
                },
                retirement_reason: None,
            });
        r.retirement_reason = Some(reason.into());
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub(super) fn validate_lifecycle(&self) -> Result<(), FindingGovernanceError> {
        let Some(r) = &self.lifecycle else {
            return Ok(());
        };
        if r.anchors
            .len()
            .saturating_add(r.retirements.len())
            .saturating_add(r.exception_reviews.len())
            .saturating_add(self.exceptions.len())
            .saturating_add(
                self.baseline
                    .as_ref()
                    .map_or(0, |b| b.active_entries.len() + b.retired_entries.len()),
            )
            > MAX_GOVERNANCE_RECORDS
        {
            return Err(lifecycle_error(
                "RESOURCE_LIMIT",
                "governance record admission exceeded",
            ));
        }
        let active = self.baseline.as_ref().map_or_else(BTreeMap::new, |b| {
            b.active_entries
                .iter()
                .map(|e| (e.finding_id.as_str(), e))
                .collect()
        });
        let retired = self.baseline.as_ref().map_or_else(BTreeSet::new, |b| {
            b.retired_entries
                .iter()
                .map(|e| e.finding_id.as_str())
                .collect()
        });
        for (id, a) in &r.anchors {
            a.validate()?;
            if id != &a.finding_id
                || (!active.contains_key(id.as_str()) && !retired.contains(id.as_str()))
                || active
                    .get(id.as_str())
                    .is_some_and(|e| e.rule_id != a.rule_id || e.subjects != a.subject_refs)
            {
                return Err(lifecycle_error(
                    "INVALID_INPUT",
                    "orphan or conflicting original admission",
                ));
            }
        }
        for (id, h) in &r.retirements {
            h.original_entry.validate()?;
            h.evidence.validate()?;
            if !retired.contains(id.as_str())
                || r.anchors.get(id) != Some(&h.anchor)
                || &h.original_entry.finding_id != id
                || h.evidence.finding_id != *id
                || h.evidence.comparison_basis.anchor_ref.as_ref()
                    != Some(&lifecycle_digest(&h.anchor)?)
                || h.evidence.comparison_basis.from_state != h.anchor.from_state
                || h.evidence.original_authority_ref.as_ref()
                    != Some(&h.anchor.original_authority_ref)
                || h.evidence.from_subject.as_ref() != Some(&h.anchor.subject_ref)
                || h.evidence.claim_scope_ref.as_ref() != Some(&h.anchor.claim_scope_ref)
                || h.original_entry.rule_id != h.anchor.rule_id
                || h.original_entry.subjects != h.anchor.subject_refs
                || !matches!(
                    h.evidence.outcome,
                    RetirementOutcome::Resolved | RetirementOutcome::SubjectRemoved
                )
            {
                return Err(lifecycle_error(
                    "INVALID_INPUT",
                    "retirement history is inconsistent",
                ));
            }
        }
        self.validate_exception_reviews(r)?;
        lifecycle_bytes(self)?;
        Ok(())
    }
    fn validate_exception_reviews(
        &self,
        r: &LifecycleRecords,
    ) -> Result<(), FindingGovernanceError> {
        let exceptions = self
            .exceptions
            .iter()
            .map(|e| (e.id.as_str(), e))
            .collect::<BTreeMap<_, _>>();
        for (id, review) in &r.exception_reviews {
            if let Some(anchor) = &review.anchor {
                anchor.validate()?;
            }
            review.policy.validate()?;
            text(&review.grant_reference)?;
            let e = exceptions
                .get(id.as_str())
                .copied()
                .ok_or_else(|| lifecycle_error("INVALID_INPUT", "orphan exception review"))?;
            if review
                .anchor
                .as_ref()
                .is_some_and(|a| e.finding_id != a.finding_id || e.rule_id != a.rule_id)
                || (review.anchor.is_none() && e.state != ExceptionState::Retired)
                || e.authority != review.grant_reference
                || ((e.state == ExceptionState::Retired) != review.retirement_reason.is_some())
            {
                return Err(lifecycle_error(
                    "INVALID_INPUT",
                    "exception review binding differs",
                ));
            }
            if let Some(t) = &review.retirement_reason {
                text(t)?;
            }
        }
        Ok(())
    }
}
