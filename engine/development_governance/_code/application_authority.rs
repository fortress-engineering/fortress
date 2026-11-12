//! Non-transferable application proofs for governed and initially ungoverned inputs.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::authority_roles::protected_input_roles;
use crate::control_layout::{ControlLayout, ControlRole};
use crate::observation::{CandidateChangeSet, ChangeOperation, SourceView};
use crate::state_governance::{
    ComparisonContext, ComparisonState, TransitionError, compare_states,
};
use crate::state_view::StateViewStatus;

use super::{
    AuthorizationRequirement, ChangeDecision, ChangeEvaluation, Disposition, PreparedChange,
    canonical, check_digest, digest, error, source_subject,
};

/// Distinct application authority bases; none changes semantic truth.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationAuthorityKind {
    /// No authored or observed source mutation; derived historical recording only.
    NoSourceChange,
    /// Existing trusted base policy and its external grant requirements.
    Governed,
    /// Explicit creation of first reviewed intent, with no prior protected authority.
    InitialEstablishment,
    /// Ordinary unprotected changes where neither endpoint has governing authority.
    UngovernedUnprotected,
}

/// Exportable provenance. Deserializing this record never reconstructs application permission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationAuthorityRecord {
    /// Public versioned record identity.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Supported record edition.
    pub schema_version: u16,
    /// Applicable authority basis.
    pub kind: ApplicationAuthorityKind,
    /// Exact simultaneous operation set, including source and context identities.
    pub change_set_ref: String,
    /// Original full comparison endpoint identity.
    pub base_state_ref: String,
    /// Proposed full comparison endpoint identity.
    pub candidate_state_ref: String,
    /// Existing four-axis comparison identity.
    pub transition_ref: String,
    /// Selected existing base-policy decision, where applicable.
    pub governed_decision: Option<ChangeDecision>,
    /// Explicit initial owner-intent reference, never an authenticated grant.
    pub reviewed_initial_intent_ref: Option<String>,
    /// Honest assertion of what this record establishes.
    pub semantics: String,
}
impl ApplicationAuthorityRecord {
    /// Creates a provenance record from an existing decision without granting permission.
    /// # Errors
    /// Rejects malformed identities or invalid decision records.
    pub fn from_decision(
        decision: &ChangeDecision,
        prepared: &PreparedChange,
    ) -> Result<Self, TransitionError> {
        decision.digest()?;
        if decision.proposal_ref != prepared.digest()?
            || decision.base_state_ref != prepared.base_state_ref
            || decision.candidate_state_ref != prepared.candidate_state_ref
            || decision.transition.digest()? != prepared.transition.digest()?
        {
            return Err(error(
                "INVALID_BINDING",
                "decision does not bind exact physical application proposal",
            ));
        }
        let change_set_ref = &prepared.changes_ref;
        check_digest(change_set_ref)?;
        Ok(Self {
            schema: "urn:fortress:derived:v1:application-authority".into(),
            schema_version: 1,
            kind: ApplicationAuthorityKind::Governed,
            change_set_ref: change_set_ref.into(),
            base_state_ref: decision.base_state_ref.clone(),
            candidate_state_ref: decision.candidate_state_ref.clone(),
            transition_ref: decision.transition.digest()?,
            governed_decision: Some(decision.clone()),
            reviewed_initial_intent_ref: None,
            semantics: "PROVENANCE_ONLY_NOT_TRANSFERABLE".into(),
        })
    }
    /// Exact record identity; exported approval-shaped records remain untrusted provenance.
    /// # Errors
    /// Rejects malformed, inconsistent or excessive records.
    pub fn digest(&self) -> Result<String, TransitionError> {
        self.validate()?;
        digest(self)
    }
    /// Governing requirement identity, independent of subsequently supplied grant evidence.
    /// # Errors
    /// Rejects inconsistent provenance or excessive canonical output.
    pub fn requirement_contract_ref(&self) -> Result<String, TransitionError> {
        self.validate()?;
        let requirements = self
            .governed_decision
            .as_ref()
            .map(|d| (&d.proposal_ref, &d.policy_ref, &d.requirements));
        digest(&(
            self.kind,
            &self.change_set_ref,
            &self.base_state_ref,
            &self.candidate_state_ref,
            &self.transition_ref,
            &self.reviewed_initial_intent_ref,
            requirements,
        ))
    }
    /// Actual protected requirements, without interpreting their citations as grants.
    #[must_use]
    pub fn requirements(&self) -> &[AuthorizationRequirement] {
        self.governed_decision
            .as_ref()
            .map_or(&[], |d| d.requirements.as_slice())
    }
    fn validate(&self) -> Result<(), TransitionError> {
        if self.schema != "urn:fortress:derived:v1:application-authority"
            || self.schema_version != 1
            || self.semantics != "PROVENANCE_ONLY_NOT_TRANSFERABLE"
        {
            return Err(error(
                "UNSUPPORTED_VERSION",
                "unsupported application authority record",
            ));
        }
        for d in [
            &self.change_set_ref,
            &self.base_state_ref,
            &self.candidate_state_ref,
            &self.transition_ref,
        ] {
            check_digest(d)?;
        }
        match (
            self.kind,
            &self.governed_decision,
            &self.reviewed_initial_intent_ref,
        ) {
            (ApplicationAuthorityKind::Governed, Some(d), None) => {
                d.digest()?;
                if d.base_state_ref != self.base_state_ref
                    || d.candidate_state_ref != self.candidate_state_ref
                    || d.transition.digest()? != self.transition_ref
                {
                    return Err(error(
                        "INVALID_BINDING",
                        "application record differs from governed decision",
                    ));
                }
            }
            (ApplicationAuthorityKind::InitialEstablishment, None, Some(review)) => {
                check_digest(review)?;
            }
            (
                ApplicationAuthorityKind::UngovernedUnprotected
                | ApplicationAuthorityKind::NoSourceChange,
                None,
                None,
            ) => {}
            _ => {
                return Err(error(
                    "INVALID_BINDING",
                    "authority basis and record disagree",
                ));
            }
        }
        canonical(self)?;
        Ok(())
    }
}

/// Authorizes only an exact empty source change, without asserting semantic success or a grant.
/// # Errors
/// Refuses changed source, nonempty operations, different evaluation endpoints or context binding.
pub fn authorize_no_source_change(
    base: &ComparisonState,
    target: &ComparisonState,
    context: &ComparisonContext,
    before: &SourceView,
    changes: &CandidateChangeSet,
) -> Result<ApplicationAuthorization, TransitionError> {
    base.validate()?;
    target.validate()?;
    let transition = compare_states(base, target, context)?;
    if !changes.operations().is_empty()
        || changes.view() != before
        || changes.base_view_digest() != before.digest()
        || base.digest()? != target.digest()?
        || changes.context_digest() != transition.comparison_context
    {
        return Err(error(
            "AUTHORIZATION_REQUIRED",
            "no-source-change application is not exact",
        ));
    }
    let record = ApplicationAuthorityRecord {
        schema: "urn:fortress:derived:v1:application-authority".into(),
        schema_version: 1,
        kind: ApplicationAuthorityKind::NoSourceChange,
        change_set_ref: changes.digest().into(),
        base_state_ref: base.digest()?,
        candidate_state_ref: target.digest()?,
        transition_ref: transition.digest()?,
        governed_decision: None,
        reviewed_initial_intent_ref: None,
        semantics: "PROVENANCE_ONLY_NOT_TRANSFERABLE".into(),
    };
    record.digest()?;
    Ok(ApplicationAuthorization {
        record,
        governed: None,
    })
}

/// In-memory application permission. Repository-authored JSON cannot recreate this handle.
pub struct ApplicationAuthorization {
    record: ApplicationAuthorityRecord,
    governed: Option<ChangeEvaluation>,
}
impl ApplicationAuthorization {
    /// Admits only an existing successful AUTHORITY evaluation and its validated grants.
    /// # Errors
    /// Refuses denied, unassessed, unsupported or incompletely authorized changes.
    pub fn from_evaluation(
        evaluation: ChangeEvaluation,
        prepared: &PreparedChange,
    ) -> Result<Self, TransitionError> {
        let decision = evaluation.decision();
        if decision.disposition != Disposition::Permit
            || decision.authorization.iter().any(|a| a.state != "VERIFIED")
            || evaluation.grants().len() != decision.requirements.len()
        {
            return Err(error(
                "AUTHORIZATION_REQUIRED",
                format!(
                    "existing AUTHORITY boundary did not permit application: {:?}; semantic={}; protected={}; assurance={}; checks={:?}",
                    decision.disposition,
                    decision.semantic_enforcement.state,
                    decision.protected_authority.state,
                    decision.assurance_requirements.state,
                    decision
                        .authorization
                        .iter()
                        .map(|a| &a.state)
                        .collect::<Vec<_>>()
                ),
            ));
        }
        let record = ApplicationAuthorityRecord::from_decision(decision, prepared)?;
        Ok(Self {
            record,
            governed: Some(evaluation),
        })
    }
    /// Honest provenance, without a transferable serialized grant.
    #[must_use]
    pub const fn record(&self) -> &ApplicationAuthorityRecord {
        &self.record
    }
    /// Validated external grant handles supplied to the existing AUTHORITY service.
    #[must_use]
    pub fn grants(&self) -> &[super::ValidatedGrant] {
        self.governed.as_ref().map_or(&[], |g| g.grants())
    }
}

/// Applies absence-of-authority only to ordinary unprotected ungoverned changes.
/// The caller is a trusted embedding supplying complete canonical observations, not JSON approvals.
/// # Errors
/// Refuses any declared/partial authority, protected input, or mismatched exact byte binding.
pub fn authorize_ungoverned_unprotected(
    base: &ComparisonState,
    target: &ComparisonState,
    context: &ComparisonContext,
    before: &SourceView,
    changes: &CandidateChangeSet,
) -> Result<ApplicationAuthorization, TransitionError> {
    let mut record = absence_record(base, target, context, before, changes)?;
    require_ungoverned(target)?;
    if has_protected_inputs(changes.view()) {
        return Err(error(
            "AUTHORIZATION_REQUIRED",
            "target introduces protected intent; ordinary unprotected application is inapplicable",
        ));
    }
    record.kind = ApplicationAuthorityKind::UngovernedUnprotected;
    record.digest()?;
    Ok(ApplicationAuthorization {
        record,
        governed: None,
    })
}

/// Establishes first reviewed intent on explicit invocation without inventing an external grant.
/// Only creation of root configuration, root Module intent and optional initial residue is admitted.
/// Existing protected authority cannot be removed, replaced, bypassed or redefined through this path.
/// # Errors
/// Refuses existing authority, source edits, invalid target intent, or an inexact review reference.
pub fn authorize_initial_establishment(
    base: &ComparisonState,
    target: &ComparisonState,
    context: &ComparisonContext,
    before: &SourceView,
    changes: &CandidateChangeSet,
    reviewed_intent_ref: &str,
) -> Result<ApplicationAuthorization, TransitionError> {
    check_digest(reviewed_intent_ref)?;
    let mut record = absence_record(base, target, context, before, changes)?;
    let layout = ControlLayout::standard();
    let allowed = BTreeSet::from([
        "contract.json",
        layout
            .role_path(ControlRole::ProjectConfiguration)
            .ok_or_else(|| error("INVALID_INPUT", "configuration role unavailable"))?,
        layout
            .role_path(ControlRole::FindingGovernance)
            .ok_or_else(|| error("INVALID_INPUT", "finding governance role unavailable"))?,
    ]);
    if changes.operations().is_empty() || changes.operations().iter().any(|op| !matches!(op, ChangeOperation::Create { path, .. } if allowed.contains(path.as_str()))) {
        return Err(error("AUTHORIZATION_REQUIRED", "first establishment cannot mutate existing or ordinary source inputs"));
    }
    if target
        .view
        .as_ref()
        .is_none_or(|v| v.status == StateViewStatus::Invalid || v.application.is_none())
        || target.governing_identity()?.is_none()
    {
        return Err(error(
            "INVALID_TARGET_AUTHORITY",
            "first establishment requires completely evaluated valid declared target intent",
        ));
    }
    record.kind = ApplicationAuthorityKind::InitialEstablishment;
    record.reviewed_initial_intent_ref = Some(reviewed_intent_ref.into());
    record.digest()?;
    Ok(ApplicationAuthorization {
        record,
        governed: None,
    })
}

fn require_ungoverned(state: &ComparisonState) -> Result<(), TransitionError> {
    state.validate()?;
    if state
        .view
        .as_ref()
        .is_none_or(|v| v.status != StateViewStatus::Ungoverned || v.application.is_some())
        || state.governing_identity()?.is_some()
    {
        return Err(error(
            "AUTHORIZATION_REQUIRED",
            "absence of governing authority was not established",
        ));
    }
    Ok(())
}

/// Establishes reviewed Module intent and canonical structure on a completely ungoverned base.
/// Existing protected inputs remain ineligible for this boundary. Ordinary source operations
/// require an explicit canonical review; this is first-intent provenance, never an external grant.
/// The original three-file establishment API keeps its narrower contract unchanged.
/// # Errors
/// Refuses partial/existing authority, unbound changes, new trust/schema authority, invalid Module
/// intent, noncanonical source review, or attempts to overwrite a protected input.
#[allow(clippy::too_many_lines)]
pub fn authorize_reviewed_initial_establishment(
    base: &ComparisonState,
    target: &ComparisonState,
    context: &ComparisonContext,
    before: &SourceView,
    changes: &CandidateChangeSet,
    reviewed_intent_ref: &str,
    canonical_source_review: bool,
) -> Result<ApplicationAuthorization, TransitionError> {
    check_digest(reviewed_intent_ref)?;
    let mut record = absence_record(base, target, context, before, changes)?;
    let Some(application) = target
        .view
        .as_ref()
        .filter(|v| v.status != StateViewStatus::Invalid)
        .and_then(|v| v.application.as_ref())
    else {
        return Err(error(
            "INVALID_TARGET_AUTHORITY",
            "first intent requires a complete valid evaluated target",
        ));
    };
    if target.governing_identity()?.is_none() || changes.operations().is_empty() {
        return Err(error(
            "INVALID_TARGET_AUTHORITY",
            "first intent has no governing target or changes",
        ));
    }
    if canonical_source_review {
        let manifest = serde_json::to_value(&application.declaration.required_dimension_manifest)
            .map_err(|e| error("INVALID_INPUT", e.to_string()))?;
        if !manifest["profiles"]
            .as_array()
            .is_some_and(|profiles| profiles.iter().any(|p| p["id"] == "GOV-FORTRESS-CANONICAL"))
        {
            return Err(error(
                "AUTHORIZATION_REQUIRED",
                "source relocation requires the explicitly selected canonical profile",
            ));
        }
    }
    let assets = target.assets.as_ref().ok_or_else(|| {
        error(
            "INVALID_TARGET_AUTHORITY",
            "Module inventory is unavailable",
        )
    })?;
    let contracts = assets
        .entities
        .iter()
        .filter(|e| e.kind == "module")
        .filter_map(|e| e.path.clone())
        .collect::<BTreeSet<_>>();
    if !contracts.contains("contract.json") {
        return Err(error(
            "INVALID_TARGET_AUTHORITY",
            "compiled root Module identity is missing",
        ));
    }
    let layout = ControlLayout::standard();
    let configuration = layout
        .role_path(ControlRole::ProjectConfiguration)
        .ok_or_else(|| error("INVALID_INPUT", "configuration role unavailable"))?;
    let governance = layout
        .role_path(ControlRole::FindingGovernance)
        .ok_or_else(|| error("INVALID_INPUT", "finding role unavailable"))?;
    let mut created = contracts.clone();
    created.insert(configuration.into());
    created.insert(governance.into());
    if canonical_source_review {
        for contract in &contracts {
            let prefix = contract.strip_suffix("contract.json").ok_or_else(|| {
                error(
                    "INVALID_TARGET_AUTHORITY",
                    "compiled contract has an unsupported occurrence",
                )
            })?;
            for file in [
                "README.md",
                "_docs/code_docs.md",
                "_docs/data_docs.md",
                "_docs/info_docs.md",
                "_docs/modules_docs.md",
            ] {
                created.insert(format!("{prefix}{file}"));
            }
        }
    }
    let protected = |path: &str, source: &SourceView| -> Result<bool, TransitionError> {
        let Some(bytes) = source.bytes(path) else {
            return Ok(false);
        };
        let singleton = SourceView::from_bytes([(path, bytes.to_vec())])
            .map_err(|e| error("INVALID_INPUT", e.to_string()))?;
        Ok(has_protected_inputs(&singleton))
    };
    for operation in changes.operations() {
        match operation {
            ChangeOperation::Create { path, .. } if created.contains(path) => {}
            ChangeOperation::Create { path, .. } if canonical_source_review => {
                if protected(path, changes.view())? {
                    return Err(error(
                        "AUTHORIZATION_REQUIRED",
                        "first intent cannot introduce trust, evaluator, Standard or schema authority",
                    ));
                }
            }
            ChangeOperation::Replace { path, .. } | ChangeOperation::Delete { path, .. }
                if canonical_source_review =>
            {
                if protected(path, before)? || protected(path, changes.view())? {
                    return Err(error(
                        "AUTHORIZATION_REQUIRED",
                        "first intent cannot replace existing protected authority",
                    ));
                }
            }
            ChangeOperation::Move {
                source,
                destination,
                ..
            } if canonical_source_review => {
                if protected(source, before)? || protected(destination, changes.view())? {
                    return Err(error(
                        "AUTHORIZATION_REQUIRED",
                        "canonical relocation cannot redefine a protected input",
                    ));
                }
            }
            _ => {
                return Err(error(
                    "AUTHORIZATION_REQUIRED",
                    "native first intent may only create the exact reviewed Module and registered governance artifacts",
                ));
            }
        }
    }
    record.kind = ApplicationAuthorityKind::InitialEstablishment;
    record.reviewed_initial_intent_ref = Some(reviewed_intent_ref.into());
    record.digest()?;
    Ok(ApplicationAuthorization {
        record,
        governed: None,
    })
}
fn has_protected_inputs(source: &SourceView) -> bool {
    let layout = ControlLayout::standard();
    source.iter().any(|(path, bytes)| {
        let value = std::str::from_utf8(bytes)
            .ok()
            .and_then(|s| crate::wire::parse_public_json::<serde_json::Value>(s).ok());
        let schema = value.as_ref().and_then(|v| v["$schema"].as_str());
        !protected_input_roles(&layout, path, schema).is_empty()
            || path == "contract.json"
            || path.ends_with("/contract.json")
            || value
                .as_ref()
                .and_then(|v| v["$id"].as_str())
                .is_some_and(|id| id.starts_with("urn:fortress:"))
    })
}
fn absence_record(
    base: &ComparisonState,
    target: &ComparisonState,
    context: &ComparisonContext,
    before: &SourceView,
    changes: &CandidateChangeSet,
) -> Result<ApplicationAuthorityRecord, TransitionError> {
    for source in [before, changes.view()] {
        if source.len() > crate::state_governance::MAX_TRANSITION_RECORDS
            || source
                .values()
                .try_fold(0usize, |n, b| n.checked_add(b.len()))
                .is_none_or(|n| n > crate::state_governance::MAX_TRANSITION_BYTES)
        {
            return Err(error(
                "RESOURCE_LIMIT",
                "application authority inventory exceeds admission",
            ));
        }
    }
    require_ungoverned(base)?;
    target.validate()?;
    let transition = compare_states(base, target, context)?;
    if has_protected_inputs(before)
        || base.source_ref.as_deref() != Some(source_subject(before).as_str())
        || target.source_ref.as_deref() != Some(source_subject(changes.view()).as_str())
        || before.digest() != changes.base_view_digest()
        || changes.context_digest() != transition.comparison_context
        || changes.target_authority_digest() != application_target_authority_ref(target)?
    {
        return Err(error(
            "AUTHORIZATION_REQUIRED",
            "exact complete absence-of-authority inputs were not established",
        ));
    }
    Ok(ApplicationAuthorityRecord {
        schema: "urn:fortress:derived:v1:application-authority".into(),
        schema_version: 1,
        kind: ApplicationAuthorityKind::UngovernedUnprotected,
        change_set_ref: changes.digest().into(),
        base_state_ref: base.digest()?,
        candidate_state_ref: target.digest()?,
        transition_ref: transition.digest()?,
        governed_decision: None,
        reviewed_initial_intent_ref: None,
        semantics: "PROVENANCE_ONLY_NOT_TRANSFERABLE".into(),
    })
}

/// Returns the exact governing identity or a state-bound absence marker, never a policy.
/// # Errors
/// Refuses ambiguous, incomplete or invalid authority; absence requires a canonical ungoverned view.
pub fn application_target_authority_ref(
    state: &ComparisonState,
) -> Result<String, TransitionError> {
    if let Some(authority) = state.governing_identity()? {
        return Ok(authority);
    }
    require_ungoverned(state)?;
    digest(&("NO_DECLARED_GOVERNING_AUTHORITY", state.digest()?))
}
