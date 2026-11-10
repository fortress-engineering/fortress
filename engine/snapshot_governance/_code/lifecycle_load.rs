//! Read-only lifecycle orchestration and protected proposal admission; no grant deserializer.
use crate::control_layout::{ControlLayout, ControlRole};
use crate::development_governance::{ChangeEvaluation, Disposition};
use crate::finding::CanonicalFinding;
use crate::finding_governance::{
    ExceptionReviewPolicy, FindingGovernanceDocument, FindingGovernanceEvaluation,
    LifecycleContext, RetirementEvidenceV2, RetirementOutcome,
    evaluate_finding_governance_in_context,
};
use crate::state_governance::{
    ComparisonContext, ComparisonState, TransitionError, assess_retirements,
    current_governance_anchors, finding_anchors,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;
fn error(e: impl std::fmt::Display) -> TransitionError {
    TransitionError {
        code: "INVALID_INPUT".into(),
        message: e.to_string(),
    }
}
fn fail(code: &str, message: &str) -> TransitionError {
    TransitionError {
        code: code.into(),
        message: message.into(),
    }
}
fn path() -> Result<String, TransitionError> {
    ControlLayout::standard()
        .role_path(ControlRole::FindingGovernance)
        .map(str::to_owned)
        .ok_or_else(|| {
            fail(
                "UNSUPPORTED",
                "registered finding governance role is missing",
            )
        })
}
/// Builds a current read-only assessment context; repository references confer no authorization.
/// # Errors
/// Refuses ambiguous identities or malformed exact-state inputs.
pub fn current_context(
    state: &ComparisonState,
    authority: &FindingGovernanceDocument,
    time: Option<u64>,
) -> Result<LifecycleContext, TransitionError> {
    LifecycleContext::observed(
        authority.authority_digest().map_err(error)?,
        current_governance_anchors(state, authority)?,
        time,
    )
    .map_err(error)
}
/// Reads exactly the registered active authority; never scans event archives or selected history.
/// # Errors
/// Refuses unsafe paths, malformed data, conflicting versions and resource exhaustion.
pub fn load_finding_authority(root: &Path) -> Result<FindingGovernanceDocument, TransitionError> {
    let p = path()?;
    match crate::query::safe_read(
        root,
        &root.join(p),
        crate::finding_governance::MAX_GOVERNANCE_BYTES as u64,
    ) {
        Ok(bytes) => {
            FindingGovernanceDocument::from_json_str(std::str::from_utf8(&bytes).map_err(error)?)
                .map_err(error)
        }
        Err(e) if e.code == "MISSING" => Ok(FindingGovernanceDocument::empty_current()),
        Err(e) => Err(fail(&e.code, &e.message)),
    }
}
/// One derived immutable assessment, with raw violations and uncertainty kept intact.
#[derive(Clone, Debug, Serialize)]
pub struct FindingLifecycleReport {
    /// Versioned aggregate over existing finding and retirement meanings.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Exact aggregate wire edition.
    pub schema_version: u16,
    /// Original active governance preimage.
    pub governance_ref: String,
    /// Explicit compared exact states.
    pub from_state: String,
    /// Explicit current exact state.
    pub to_state: String,
    /// Explicit time input for review, never a machine-clock observation.
    pub assessment_time: Option<u64>,
    /// Existing finding vocabulary and progressive enforcement.
    pub current: FindingGovernanceEvaluation,
    /// Supported retirement or missing comparable premises.
    pub retirement_evidence: Vec<RetirementEvidenceV2>,
}
/// Compares already-loaded immutable results; invokes no semantic analyzer or project code.
/// # Errors
/// Refuses malformed authority, state mismatch, ambiguity and resource exhaustion.
pub fn assess_finding_lifecycle(
    authority: &FindingGovernanceDocument,
    before: &ComparisonState,
    after: &ComparisonState,
    findings: &[CanonicalFinding],
    standard_id: &str,
    edition: &str,
    time: Option<u64>,
) -> Result<FindingLifecycleReport, TransitionError> {
    let application = after
        .view
        .as_ref()
        .and_then(|v| v.application.as_ref())
        .or(after.retained_application.as_ref())
        .ok_or_else(|| {
            fail(
                "NOT_EVALUABLE",
                "current raw findings have no bound declaration",
            )
        })?;
    let declared = application
        .declaration
        .claims
        .iter()
        .flat_map(|c| c.findings.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    let supplied = findings
        .iter()
        .map(CanonicalFinding::finding_id)
        .collect::<BTreeSet<_>>();
    if declared != supplied {
        return Err(fail(
            "INVALID_BINDING",
            "current canonical findings differ from the exact current declaration",
        ));
    }
    let context = current_context(after, authority, time)?;
    Ok(FindingLifecycleReport {
        schema: "urn:fortress:derived:v1:finding-lifecycle".into(),
        schema_version: 1,
        governance_ref: authority.authority_digest().map_err(error)?,
        from_state: before.digest()?,
        to_state: after.digest()?,
        assessment_time: time,
        current: evaluate_finding_governance_in_context(
            findings,
            Some(authority),
            standard_id,
            edition,
            &context,
        )
        .map_err(error)?,
        retirement_evidence: assess_retirements(
            before,
            after,
            authority,
            &ComparisonContext::default(),
        )?,
    })
}
/// Reviewable maintenance proposal; serialization cannot approve or apply it.
#[derive(Clone, Debug, Serialize)]
pub struct GovernanceProposal {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    operation: String,
    governance_path: String,
    original_governance_ref: String,
    proposed_governance: FindingGovernanceDocument,
    original_state: Option<ComparisonState>,
    current_state: ComparisonState,
    retirement_evidence: Vec<RetirementEvidenceV2>,
    authorization: String,
    host_coverage: String,
}
impl GovernanceProposal {
    /// Proposed bytes remain authored intent until an independently authorized application.
    #[must_use]
    pub fn proposed_governance(&self) -> &FindingGovernanceDocument {
        &self.proposed_governance
    }
    /// Content identity of the reviewable proposal, independent from external approval.
    /// # Errors
    /// Refuses bounded canonical serialization failures.
    pub fn digest(&self) -> Result<String, TransitionError> {
        Ok(format!(
            "sha256:{:x}",
            Sha256::digest(self.to_canonical_bytes()?)
        ))
    }
    /// Bounded deterministic machine representation; no analysis is initiated.
    /// # Errors
    /// Refuses resource exhaustion or invalid neutral records.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TransitionError> {
        crate::finding_governance::lifecycle_bytes(self).map_err(error)
    }
    /// Human projection of precisely the same immutable proposal.
    #[must_use]
    pub fn to_human(&self) -> String {
        let mut s = format!(
            "{} proposal\ngovernance: {}\nauthorization: {}\nhost coverage: {}\n",
            self.operation, self.governance_path, self.authorization, self.host_coverage
        );
        if let Some(b) = self.proposed_governance.baseline() {
            let _ = writeln!(
                s,
                "baseline: {} active, {} retired",
                b.active_entries().len(),
                b.retired_entries().len()
            );
        }
        for e in &self.retirement_evidence {
            let _ = writeln!(
                s,
                "{}: {:?}: {}",
                e.finding_id,
                e.outcome,
                e.reasons.join("; ")
            );
        }
        s.push_str("Raw findings and historical authority are unchanged. This proposal is not permission or an applied update.\n");
        s
    }
}
fn proposal(
    operation: &str,
    original: &FindingGovernanceDocument,
    next: FindingGovernanceDocument,
    before: Option<ComparisonState>,
    current: ComparisonState,
    evidence: Vec<RetirementEvidenceV2>,
) -> Result<GovernanceProposal, TransitionError> {
    let p = GovernanceProposal {
        schema: "urn:fortress:derived:v1:governance-proposal".into(),
        schema_version: 1,
        operation: operation.into(),
        governance_path: path()?,
        original_governance_ref: original.authority_digest().map_err(error)?,
        proposed_governance: next,
        original_state: before,
        current_state: current,
        retirement_evidence: evidence,
        authorization: "REQUIRE_AUTHORITY_DECISION".into(),
        host_coverage: "UNMEDIATED".into(),
    };
    p.to_canonical_bytes()?;
    Ok(p)
}
/// Previews initial adoption only; an existing baseline can never expand or be replaced.
/// # Errors
/// Refuses unanchored/ineligible ambiguity and existing baseline authority.
pub fn propose_baseline(
    authority: &FindingGovernanceDocument,
    state: &ComparisonState,
    findings: &[CanonicalFinding],
    standard_id: &str,
    edition: &str,
) -> Result<GovernanceProposal, TransitionError> {
    let mut next = authority.clone();
    next.create_anchored_baseline(
        standard_id,
        edition,
        findings,
        finding_anchors(state, findings)?,
    )
    .map_err(error)?;
    proposal(
        "BASELINE_CREATE",
        authority,
        next,
        None,
        state.clone(),
        vec![],
    )
}
/// Previews only explicitly selected sufficient retirements, rederived from the exact states.
/// Empty selection means all eligible records; unresolved entries remain active and visible.
/// # Errors
/// Refuses unknown selectors, unsupported evidence and stale historical anchors.
pub fn propose_prune(
    authority: &FindingGovernanceDocument,
    before: &ComparisonState,
    after: &ComparisonState,
    selected: &BTreeSet<String>,
) -> Result<GovernanceProposal, TransitionError> {
    let evidence = assess_retirements(before, after, authority, &ComparisonContext::default())?;
    let eligible = evidence
        .iter()
        .filter(|e| {
            matches!(
                e.outcome,
                RetirementOutcome::Resolved | RetirementOutcome::SubjectRemoved
            ) && (selected.is_empty() || selected.contains(&e.finding_id))
        })
        .cloned()
        .collect::<Vec<_>>();
    if !selected.is_empty() && eligible.len() != selected.len() {
        return Err(fail(
            "RETIREMENT_EVIDENCE_REQUIRED",
            "one or more selected retirements lack comparable sufficient evidence",
        ));
    }
    let mut next = authority.clone();
    if !eligible.is_empty() {
        next.prune_with_evidence(&eligible).map_err(error)?;
    }
    proposal(
        "BASELINE_PRUNE",
        authority,
        next,
        Some(before.clone()),
        after.clone(),
        evidence,
    )
}
/// Previews one finding-specific reviewed exception; references remain unauthenticated.
/// # Errors
/// Rejects unknown targets, ambiguous anchors and invalid review bounds.
#[allow(clippy::too_many_arguments)]
pub fn propose_exception(
    authority: &FindingGovernanceDocument,
    state: &ComparisonState,
    findings: &[CanonicalFinding],
    id: &str,
    finding: &str,
    reference: &str,
    rationale: &str,
    policy: ExceptionReviewPolicy,
) -> Result<GovernanceProposal, TransitionError> {
    let anchor = finding_anchors(state, findings)?
        .remove(finding)
        .ok_or_else(|| {
            fail(
                "NOT_FOUND",
                "exception target lacks an eligible exact anchor",
            )
        })?;
    let mut next = authority.clone();
    next.create_reviewed_exception(id, finding, reference, rationale, findings, anchor, policy)
        .map_err(error)?;
    proposal(
        "EXCEPTION_CREATE",
        authority,
        next,
        None,
        state.clone(),
        vec![],
    )
}
/// Previews deliberate retirement with its original rationale and admission retained.
/// # Errors
/// Refuses missing review history and already retired exceptions.
pub fn propose_exception_retirement(
    authority: &FindingGovernanceDocument,
    state: &ComparisonState,
    id: &str,
    reason: &str,
) -> Result<GovernanceProposal, TransitionError> {
    let mut next = authority.clone();
    next.retire_reviewed_exception(id, reason).map_err(error)?;
    proposal(
        "EXCEPTION_RETIRE",
        authority,
        next,
        None,
        state.clone(),
        vec![],
    )
}
/// Opaque reviewed postimage; no serializer or public constructor can supply it.
pub struct AuthorizedGovernanceUpdate {
    bytes: Vec<u8>,
    proposal_ref: String,
}
impl AuthorizedGovernanceUpdate {
    /// Exactly authorized postimage for a future write-mediating host; does not write files.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Exact reviewed lifecycle proposal identity.
    #[must_use]
    pub fn proposal_ref(&self) -> &str {
        &self.proposal_ref
    }
}
/// Admits only the existing AUTHORITY process-local decision over exact base/candidate bytes.
/// No serialized receipt, URL, local approval flag or repository claim can implement this path.
/// # Errors
/// Refuses non-PERMIT, mismatched proposals, other writes and missing opaque scoped grants.
pub fn authorize_governance_update(
    p: &GovernanceProposal,
    base: &crate::authority_load::AuthoritySnapshot,
    candidate: &crate::authority_load::AuthoritySnapshot,
    comparison_context: &ComparisonContext,
    evaluation: &ChangeEvaluation,
) -> Result<AuthorizedGovernanceUpdate, TransitionError> {
    let prepared =
        crate::authority_load::prepare_authority_change(base, candidate, comparison_context)?;
    let decision = evaluation.decision();
    let bytes = p
        .proposed_governance
        .to_canonical_json()
        .map_err(error)?
        .into_bytes();
    if decision.disposition != Disposition::Permit
        || decision.proposal_ref != prepared.digest()?
        || base.state.source_ref != p.current_state.source_ref
        || candidate.files.get(&p.governance_path) != Some(&bytes)
    {
        return Err(fail(
            "AUTHORIZATION_REQUIRED",
            "opaque decision does not permit this exact reviewed postimage",
        ));
    }
    let original = base
        .files
        .get(&p.governance_path)
        .map(|b| {
            std::str::from_utf8(b)
                .map_err(error)
                .and_then(|s| FindingGovernanceDocument::from_json_str(s).map_err(error))
        })
        .transpose()?
        .unwrap_or_else(FindingGovernanceDocument::empty_current);
    if original.authority_digest().map_err(error)? != p.original_governance_ref {
        return Err(fail(
            "STALE_GOVERNANCE",
            "original governed authority changed",
        ));
    }
    if base
        .files
        .keys()
        .chain(candidate.files.keys())
        .any(|path| path != &p.governance_path && base.files.get(path) != candidate.files.get(path))
    {
        return Err(fail(
            "INVALID_BINDING",
            "lifecycle postimage includes unrelated operations",
        ));
    }
    let required = decision
        .requirements
        .iter()
        .filter(|r| {
            r.path == p.governance_path
                && r.class == crate::authority_roles::ProtectedClass::FindingGovernance
        })
        .map(|r| r.id.as_str())
        .collect::<BTreeSet<_>>();
    if required.is_empty()
        || required.iter().any(|id| {
            !evaluation
                .grants()
                .iter()
                .any(|g| g.assertion().requirement_ref == **id)
        })
    {
        return Err(fail(
            "AUTHORIZATION_REQUIRED",
            "exact finding-governance grant is unavailable",
        ));
    }
    Ok(AuthorizedGovernanceUpdate {
        bytes,
        proposal_ref: p.digest()?,
    })
}
/// Creates an authorized exception assessment context through the same opaque update boundary.
/// Permission stays separate from semantic correctness and the complete transition disposition.
/// # Errors
/// Rejects stale bytes, wrong scope and unavailable authorization.
pub fn authorized_exception_context(
    p: &GovernanceProposal,
    base: &crate::authority_load::AuthoritySnapshot,
    candidate: &crate::authority_load::AuthoritySnapshot,
    comparison_context: &ComparisonContext,
    evaluation: &ChangeEvaluation,
) -> Result<LifecycleContext, TransitionError> {
    authorize_governance_update(p, base, candidate, comparison_context, evaluation)?;
    let mut context = current_context(
        &candidate.state,
        &p.proposed_governance,
        evaluation.decision().evaluation_time,
    )?;
    if let Some(records) = p.proposed_governance.lifecycle() {
        for id in records.exception_reviews.keys() {
            context.admit_exception(
                id,
                evaluation.decision().proposal_ref.clone(),
                crate::finding_governance::lifecycle_digest(
                    &evaluation
                        .grants()
                        .iter()
                        .map(crate::development_governance::ValidatedGrant::assertion)
                        .collect::<Vec<_>>(),
                )
                .map_err(error)?,
            );
        }
    }
    Ok(context)
}
