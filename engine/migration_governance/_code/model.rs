//! Versioned exact-state migration plans and injected canonical evaluation ports.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{
    ExecutableStep, MAX_MIGRATION_BYTES, MigrationError, MigrationOperation, OperationGraph,
    canonical, content_digest, fail,
};
use crate::development_governance::{
    ApplicationAuthorityRecord, ApplicationAuthorization, AuthorizationRequirement, ProtectedInput,
    application_target_authority_ref,
};
use crate::observation::{CandidateChangeSet, SourceView};
use crate::state_governance::{
    ComparisonContext, ComparisonState, TransitionAnalysis, compare_states,
};

/// Supported validation requirements; these are operational requirements, not new rule evaluators.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MigrationValidation {
    /// Full canonical evaluation completed over the exact supplied source.
    EvaluationCompleted,
    /// Canonical owner results establish valid declared governance.
    GovernanceDeclared,
    /// Existing progressive enforcement has no blocking supported findings.
    ProgressiveEnforcement,
    /// Existing Profile Assessment satisfies its selected assurance requirements.
    ProfileAssurance,
    /// Existing finding-lifecycle evidence establishes a requested comparable retirement.
    ComparableRetirement,
}
/// Honest result of a requested existing-owner validation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MigrationValidationState {
    /// The existing owner supplies sufficient support for this precise requirement.
    Satisfied,
    /// The owner reports a failed requirement.
    Failed,
    /// The owner lacks sufficient evaluation evidence.
    NotEvaluable,
    /// The requirement has no applicable subject; this is not satisfaction.
    NotApplicable,
}
/// One owner-supplied validation fact, preserving its scope and evidence limitations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationValidationFact {
    /// Existing-owner result.
    pub state: MigrationValidationState,
    /// Exact existing evidence references, not newly invented proofs.
    pub evidence_refs: Vec<String>,
    /// Human-readable reason and limitations.
    pub detail: String,
}
/// Canonical evaluator output. The Migration Module never derives semantic facts itself.
#[derive(Clone, Debug)]
pub struct MigrationEvaluation {
    /// Existing comparison endpoint, retaining original conformance and uncertainty.
    pub state: ComparisonState,
    /// Exact source admitted by this endpoint's observation policy.
    pub evaluated_source: SourceView,
    /// Existing canonical owner identities for physically observed file paths.
    pub ownership: BTreeMap<String, String>,
    /// Existing registered protected-role facts, including physically present excluded inputs.
    pub protected_inputs: Vec<ProtectedInput>,
    /// Existing-owner validation outcomes.
    pub validations: BTreeMap<MigrationValidation, MigrationValidationFact>,
}
impl MigrationEvaluation {
    pub(crate) fn validate(&self, physical: &SourceView) -> Result<(), MigrationError> {
        self.state.validate().map_err(convert)?;
        if self
            .evaluated_source
            .iter()
            .any(|(p, b)| physical.get(p) != Some(b))
            || self.state.source_ref.as_deref()
                != Some(
                    crate::certification::certification_source_digest(
                        self.evaluated_source.files(),
                    )
                    .as_str(),
                )
        {
            return Err(fail(
                "EVALUATOR_BINDING_MISMATCH",
                "canonical endpoint does not bind the supplied immutable source",
            ));
        }
        if self
            .validations
            .get(&MigrationValidation::EvaluationCompleted)
            .is_none_or(|f| f.state != MigrationValidationState::Satisfied)
        {
            return Err(fail(
                "EVALUATION_INCOMPLETE",
                "complete canonical evaluation did not finish",
            ));
        }
        if self.ownership.len() > 50_000
            || self.protected_inputs.len() > 50_000
            || self.validations.len() > 16
        {
            return Err(fail("RESOURCE_LIMIT", "evaluation facts exceed admission"));
        }
        for fact in self.validations.values() {
            if fact.detail.len() > 4096
                || fact.evidence_refs.len() > 50_000
                || fact
                    .evidence_refs
                    .iter()
                    .any(|r| !crate::declaration::is_digest(r))
                || fact.evidence_refs.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(fail(
                    "EVALUATOR_BINDING_MISMATCH",
                    "invalid or unordered validation evidence facts",
                ));
            }
        }
        Ok(())
    }
}

/// Injected full canonical evaluation and actual observation, implemented by Snapshot Governance.
/// Evaluation must not execute project code or mutate the supplied repository.
pub trait MigrationEvaluator {
    /// Evaluates one immutable byte view using the established complete analysis pipeline.
    /// # Errors
    /// Refuses incomplete, malformed, unsupported or resource-exhausted inputs.
    fn evaluate(&self, source: &SourceView) -> Result<MigrationEvaluation, MigrationError>;
    /// Independently observes the actual bounded physical source scope.
    /// # Errors
    /// Refuses unstable source, unsafe paths, unavailable bytes and exhausted admission.
    fn observe(&self, repository: &Path) -> Result<SourceView, MigrationError>;
}

/// Existing AUTHORITY integration. Exported references cannot supply this process-local port.
pub trait MigrationAuthority {
    /// Returns a provenance-only preview under the trusted base selection.
    /// # Errors
    /// Refuses ambiguous authority, invalid bindings and unsupported requirements.
    fn preview(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        before: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<ApplicationAuthorityRecord, MigrationError>;
    /// Obtains an existing in-memory AUTHORITY proof on explicit apply/recovery invocation.
    /// # Errors
    /// Refuses missing, invalid, unsupported or out-of-scope external permission.
    fn authorize(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        before: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<ApplicationAuthorization, MigrationError>;
}

/// Explicit plan construction inputs, independent of any editor or host transport.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationOptions {
    /// Requested target validation requirements; complete evaluation is always mandatory.
    pub validation_requirements: BTreeSet<MigrationValidation>,
    /// Existing retirement evidence references; references alone are not sufficient proof.
    pub retirement_evidence_refs: BTreeSet<String>,
    /// Original comparison context, including honest authorization citations.
    pub comparison_context: ComparisonContext,
}

/// Exact per-path before/after conditions and inverse expectations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationPathExpectation {
    /// Portable repository-relative path.
    pub path: String,
    /// Original regular-file content identity, or required absence.
    pub preimage: Option<String>,
    /// Expected regular-file content identity, or required absence.
    pub postimage: Option<String>,
}

/// Versioned immutable content-addressed migration contract, never transferable permission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationPlan {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    plan_digest: String,
    base_source_ref: String,
    target_source_ref: String,
    base_state_ref: String,
    target_state_ref: String,
    context_ref: String,
    transition_ref: String,
    authorization_decision_ref: String,
    authorization_requirement_ref: String,
    authorization: ApplicationAuthorityRecord,
    required_grants: Vec<AuthorizationRequirement>,
    operations: Vec<MigrationOperation>,
    operation_graph: Vec<ExecutableStep>,
    preconditions: Vec<MigrationPathExpectation>,
    inverse_expectations: Vec<MigrationPathExpectation>,
    options: MigrationOptions,
    validation_facts: BTreeMap<MigrationValidation, MigrationValidationFact>,
    evaluation_mode: String,
}
impl MigrationPlan {
    /// Exact content identity, defined as JCS with `plan_digest` set to the empty string.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.plan_digest
    }
    /// Original exact physical input identity.
    #[must_use]
    pub fn base_source_ref(&self) -> &str {
        &self.base_source_ref
    }
    /// Evaluated expected physical result identity.
    #[must_use]
    pub fn target_source_ref(&self) -> &str {
        &self.target_source_ref
    }
    /// Original exact canonical evaluation identity.
    #[must_use]
    pub fn base_state_ref(&self) -> &str {
        &self.base_state_ref
    }
    /// Evaluated target canonical identity; not an assertion that it has been applied.
    #[must_use]
    pub fn target_state_ref(&self) -> &str {
        &self.target_state_ref
    }
    /// Complete immutable normalized file operations.
    #[must_use]
    pub fn operations(&self) -> &[MigrationOperation] {
        &self.operations
    }
    /// Executable dependency graph, including exclusively owned staging slots.
    #[must_use]
    pub fn operation_graph(&self) -> &[ExecutableStep] {
        &self.operation_graph
    }
    /// Per-path known before/after content.
    #[must_use]
    pub fn preconditions(&self) -> &[MigrationPathExpectation] {
        &self.preconditions
    }
    /// Original validation and comparison requirements.
    #[must_use]
    pub const fn options(&self) -> &MigrationOptions {
        &self.options
    }
    /// Provenance-only existing authorization decision and governing requirements.
    #[must_use]
    pub const fn authorization(&self) -> &ApplicationAuthorityRecord {
        &self.authorization
    }
    /// Whether every requested validation is actually satisfied; unknown is never approval.
    #[must_use]
    pub fn validations_satisfied(&self) -> bool {
        self.validation_facts
            .values()
            .all(|f| f.state == MigrationValidationState::Satisfied)
    }
    /// Canonical versioned plan bytes; no repository mutation occurs.
    /// # Errors
    /// Refuses invalid digests, unsupported versions, tampering and resource exhaustion.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        self.validate()?;
        canonical(self)
    }
    /// Reads provenance and exact proposed bytes without accepting any serialized grant.
    /// # Errors
    /// Refuses malformed, tampered, incompatible or oversized records.
    pub fn from_json_str(text: &str) -> Result<Self, MigrationError> {
        if text.len() > MAX_MIGRATION_BYTES {
            return Err(fail("RESOURCE_LIMIT", "plan exceeds public admission"));
        }
        let value: Self = crate::wire::parse_public_json(text)
            .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<(), MigrationError> {
        if self.schema != "urn:fortress:derived:v1:migration-plan"
            || self.schema_version != 1
            || self.evaluation_mode != "CANONICAL_FULL"
        {
            return Err(fail(
                "UNSUPPORTED_VERSION",
                "unsupported migration plan or evaluation mode",
            ));
        }
        for id in [
            &self.plan_digest,
            &self.base_source_ref,
            &self.target_source_ref,
            &self.base_state_ref,
            &self.target_state_ref,
            &self.context_ref,
            &self.transition_ref,
            &self.authorization_decision_ref,
            &self.authorization_requirement_ref,
        ] {
            if !crate::declaration::is_digest(id) {
                return Err(fail("INVALID_IDENTITY", id));
            }
        }
        if self.authorization.digest().map_err(convert)? != self.authorization_decision_ref
            || self
                .authorization
                .requirement_contract_ref()
                .map_err(convert)?
                != self.authorization_requirement_ref
            || self.authorization.base_state_ref != self.base_state_ref
            || self.authorization.candidate_state_ref != self.target_state_ref
            || self.authorization.transition_ref != self.transition_ref
            || canonical(&self.required_grants)? != canonical(&self.authorization.requirements())?
        {
            return Err(fail(
                "INVALID_BINDING",
                "plan and authorization provenance disagree",
            ));
        }
        let mut unsigned = self.clone();
        unsigned.plan_digest.clear();
        if content_digest(&canonical(&unsigned)?) != self.plan_digest {
            return Err(fail("TAMPERED_PLAN", "plan content identity differs"));
        }
        self.validate_structure()?;
        Ok(())
    }
    fn validate_structure(&self) -> Result<(), MigrationError> {
        let originals = self
            .operations
            .iter()
            .filter_map(|op| op.original())
            .map(|(path, bytes)| (path.to_owned(), bytes.to_vec()))
            .collect::<BTreeMap<_, _>>();
        let before =
            SourceView::from_bytes(originals).map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
        // These are merely authored ownership assertions during parsing. Actual
        // application recompiles ownership from the complete canonical base.
        let owners = self
            .operations
            .iter()
            .filter_map(|op| match op {
                MigrationOperation::DeleteOwnedFile {
                    path, owner_ref, ..
                } => Some((path.clone(), owner_ref.clone())),
                _ => None,
            })
            .collect();
        let graph = OperationGraph::compile(&before, self.operations.clone(), &owners)?;
        if graph.operations() != self.operations || graph.steps() != self.operation_graph {
            return Err(fail(
                "INVALID_GRAPH",
                "operations or dependencies are not the canonical executable graph",
            ));
        }
        let paths = self
            .operations
            .iter()
            .flat_map(|op| {
                op.original()
                    .into_iter()
                    .chain(op.destination())
                    .map(|(p, _)| p)
            })
            .collect::<BTreeSet<_>>();
        let expected = paths
            .iter()
            .map(|path| MigrationPathExpectation {
                path: (*path).into(),
                preimage: before.bytes(path).map(content_digest),
                postimage: graph.target().bytes(path).map(content_digest),
            })
            .collect::<Vec<_>>();
        let inverse = expected
            .iter()
            .map(|item| MigrationPathExpectation {
                path: item.path.clone(),
                preimage: item.postimage.clone(),
                postimage: item.preimage.clone(),
            })
            .collect::<Vec<_>>();
        let required = &self.options.validation_requirements;
        if self.preconditions != expected
            || self.inverse_expectations != inverse
            || !required.contains(&MigrationValidation::EvaluationCompleted)
            || self
                .validation_facts
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != *required
            || !self.options.retirement_evidence_refs.is_empty()
                && !required.contains(&MigrationValidation::ComparableRetirement)
        {
            return Err(fail(
                "INVALID_BINDING",
                "preconditions, inverse or validation requirements disagree",
            ));
        }
        Ok(())
    }
    pub(crate) fn authorization_contract_ref(&self) -> &str {
        &self.authorization_requirement_ref
    }
    pub(crate) fn validation_facts(
        &self,
    ) -> &BTreeMap<MigrationValidation, MigrationValidationFact> {
        &self.validation_facts
    }
}

/// Read-only preview, preserving complete owner results beside the immutable executable plan.
pub struct MigrationPreview {
    /// Exact operations, state identities, requirements and inverse expectations.
    pub plan: MigrationPlan,
    /// Original immutable canonical evaluation.
    pub base: MigrationEvaluation,
    /// Proposed immutable canonical evaluation; never actual-state evidence.
    pub target: MigrationEvaluation,
    /// Existing four-axis comparison, with unsupported/noncomparable cases preserved.
    pub transition: TransitionAnalysis,
    pub(crate) changes: CandidateChangeSet,
}

/// Constructs an immutable evaluated plan without filesystem mutation or external execution.
/// # Errors
/// Rejects stale operation bytes, unsafe paths, incomplete canonical evaluation and bad bindings.
pub fn preview_migration(
    evaluator: &impl MigrationEvaluator,
    authority: &impl MigrationAuthority,
    before: &SourceView,
    operations: Vec<MigrationOperation>,
    mut options: MigrationOptions,
) -> Result<MigrationPreview, MigrationError> {
    let base = evaluator.evaluate(before)?;
    base.validate(before)?;
    let graph = OperationGraph::compile(before, operations, &base.ownership)?;
    let target = if graph.target() == before {
        base.clone()
    } else {
        evaluator.evaluate(graph.target())?
    };
    target.validate(graph.target())?;
    reuse_original_cell(&base.state, &target.state, &mut options.comparison_context)?;
    let transition =
        compare_states(&base.state, &target.state, &options.comparison_context).map_err(convert)?;
    let changes = CandidateChangeSet::new_simultaneous(
        before,
        &transition.comparison_context,
        application_target_authority_ref(&target.state).map_err(convert)?,
        graph.operations().iter().map(MigrationOperation::neutral),
    )
    .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
    let authorization = authority.preview(
        &base,
        &target,
        before,
        &changes,
        &options.comparison_context,
    )?;
    if authorization.change_set_ref != changes.digest()
        || authorization.base_state_ref != base.state.digest().map_err(convert)?
        || authorization.candidate_state_ref != target.state.digest().map_err(convert)?
        || authorization.transition_ref != transition.digest().map_err(convert)?
    {
        return Err(fail(
            "AUTHORITY_BINDING_MISMATCH",
            "preview authority does not bind exact proposed changes",
        ));
    }
    validate_retirement_selection(&mut options, &target)?;
    let validation_facts = options
        .validation_requirements
        .iter()
        .map(|r| {
            (
                *r,
                target
                    .validations
                    .get(r)
                    .cloned()
                    .unwrap_or(MigrationValidationFact {
                        state: MigrationValidationState::NotEvaluable,
                        evidence_refs: vec![],
                        detail: "Existing owner supplied no sufficient validation fact.".into(),
                    }),
            )
        })
        .collect();
    let plan = assemble_plan(
        (&base, before),
        &target,
        &graph,
        &transition,
        authorization,
        options,
        validation_facts,
    )?;
    Ok(MigrationPreview {
        plan,
        base,
        target,
        transition,
        changes,
    })
}
pub(crate) fn convert(error: crate::state_governance::TransitionError) -> MigrationError {
    fail(&error.code, error.message)
}

fn reuse_original_cell(
    base: &ComparisonState,
    target: &ComparisonState,
    context: &mut ComparisonContext,
) -> Result<(), MigrationError> {
    // Existing owner identities establish exact software equality. Reuse of
    // original evidence never substitutes candidate authority or adds proof.
    if let (Some(subject), Some(original_authority), Some(view), Some(assets)) = (
        target.subject_identity().map_err(convert)?,
        base.governing_identity().map_err(convert)?,
        base.view.as_ref().filter(|view| view.application.is_some()),
        base.assets.as_ref(),
    ) && base.subject_identity().map_err(convert)?.as_ref() == Some(&subject)
        && target.governing_identity().map_err(convert)?.as_ref() != Some(&original_authority)
        && !context
            .counterfactuals
            .iter()
            .any(|cell| cell.subject_ref == subject && cell.authority_ref == original_authority)
    {
        context
            .counterfactuals
            .push(crate::state_governance::Counterfactual {
                subject_ref: subject,
                authority_ref: original_authority,
                view: view.clone(),
                assets: Some(assets.clone()),
            });
    }
    context.counterfactuals.sort_by(|a, b| {
        (&a.subject_ref, &a.authority_ref).cmp(&(&b.subject_ref, &b.authority_ref))
    });
    Ok(())
}

fn assemble_plan(
    base: (&MigrationEvaluation, &SourceView),
    target: &MigrationEvaluation,
    graph: &OperationGraph,
    transition: &TransitionAnalysis,
    authorization: ApplicationAuthorityRecord,
    options: MigrationOptions,
    validation_facts: BTreeMap<MigrationValidation, MigrationValidationFact>,
) -> Result<MigrationPlan, MigrationError> {
    let (base, before) = base;
    let paths = graph
        .operations()
        .iter()
        .flat_map(|op| {
            op.original()
                .into_iter()
                .chain(op.destination())
                .map(|(p, _)| p.to_owned())
        })
        .collect::<BTreeSet<_>>();
    let preconditions = paths
        .iter()
        .map(|p| MigrationPathExpectation {
            path: p.clone(),
            preimage: before.bytes(p).map(content_digest),
            postimage: graph.target().bytes(p).map(content_digest),
        })
        .collect::<Vec<_>>();
    let inverse_expectations = preconditions
        .iter()
        .map(|p| MigrationPathExpectation {
            path: p.path.clone(),
            preimage: p.postimage.clone(),
            postimage: p.preimage.clone(),
        })
        .collect();
    let mut plan = MigrationPlan {
        schema: "urn:fortress:derived:v1:migration-plan".into(),
        schema_version: 1,
        plan_digest: String::new(),
        base_source_ref: before.digest().into(),
        target_source_ref: graph.target().digest().into(),
        base_state_ref: base.state.digest().map_err(convert)?,
        target_state_ref: target.state.digest().map_err(convert)?,
        context_ref: transition.comparison_context.clone(),
        transition_ref: transition.digest().map_err(convert)?,
        authorization_decision_ref: authorization.digest().map_err(convert)?,
        authorization_requirement_ref: authorization.requirement_contract_ref().map_err(convert)?,
        required_grants: authorization.requirements().to_vec(),
        authorization,
        operations: graph.operations().to_vec(),
        operation_graph: graph.steps().to_vec(),
        preconditions,
        inverse_expectations,
        options,
        validation_facts,
        evaluation_mode: "CANONICAL_FULL".into(),
    };
    plan.plan_digest = content_digest(&canonical(&plan)?);
    plan.validate()?;

    Ok(plan)
}

fn validate_retirement_selection(
    options: &mut MigrationOptions,
    target: &MigrationEvaluation,
) -> Result<(), MigrationError> {
    if options.retirement_evidence_refs.len() > 64
        || options
            .retirement_evidence_refs
            .iter()
            .any(|r| !crate::declaration::is_digest(r))
    {
        return Err(fail(
            "INVALID_INPUT",
            "retirement references are malformed or excessive",
        ));
    }
    options
        .validation_requirements
        .insert(MigrationValidation::EvaluationCompleted);
    if !options.retirement_evidence_refs.is_empty() {
        options
            .validation_requirements
            .insert(MigrationValidation::ComparableRetirement);
        if target
            .validations
            .get(&MigrationValidation::ComparableRetirement)
            .is_some_and(|fact| {
                fact.state == MigrationValidationState::Satisfied
                    && options
                        .retirement_evidence_refs
                        .iter()
                        .any(|r| !fact.evidence_refs.contains(r))
            })
        {
            return Err(fail(
                "RETIREMENT_BINDING_MISMATCH",
                "validation does not support every selected original retirement proof",
            ));
        }
    }
    Ok(())
}
