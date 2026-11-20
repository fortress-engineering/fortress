//! Exact reviewed operation preparation. The common migration writer owns all mutations.
use super::{
    MigrationAuthority, MigrationError, MigrationEvaluation, MigrationEvaluator,
    MigrationOperation, MigrationOptions, MigrationPreview, OperationGraph, fail,
    preview_migration,
};
use crate::control_layout::{ControlLayout, ControlRole};
use crate::finding_governance::{AdmissionAssessment, AdmissionReview, FindingGovernanceDocument};
use crate::observation::{CandidateChangeSet, SourceView};
use std::collections::BTreeMap;

/// Owner-produced, read-only evaluation of the proposed governing inputs.
/// It is intentionally reconstructed from actual bytes instead of deserialized for review.
pub struct EvaluatedAdmission {
    pub(crate) assessment: AdmissionAssessment,
    pub(crate) target_state: crate::state_governance::ComparisonState,
    pub(crate) original: SourceView,
    pub(crate) proposed: SourceView,
    pub(crate) operations: Vec<MigrationOperation>,
    pub(crate) ownership: BTreeMap<String, String>,
    pub(crate) governance: FindingGovernanceDocument,
    pub(crate) exact_introduction_inputs: bool,
}

/// Exact review plus prepared bytes. It grants no permission, and cannot be reconstructed
/// through a public reader. A trusted authority must independently authorize application.
pub struct ReviewedAdmission {
    assessment_ref: String,
    original_state_ref: String,
    original: SourceView,
    target: SourceView,
    operations: Vec<MigrationOperation>,
    proposed_governance: FindingGovernanceDocument,
    expires_at: Option<u64>,
    history_refs: std::collections::BTreeSet<String>,
}

impl EvaluatedAdmission {
    /// Returns the immutable proposed classification.
    #[must_use]
    pub const fn assessment(&self) -> &AdmissionAssessment {
        &self.assessment
    }

    /// Exact target before treatment, retained independently for later comparable retirement.
    #[must_use]
    pub const fn pre_admission_state(&self) -> &crate::state_governance::ComparisonState {
        &self.target_state
    }

    /// Derives a proposed finding-governance postimage from exact finding-specific review.
    /// # Errors
    /// Refuses conflicting review, unrelated source or authority changes, and malformed plans.
    pub fn review(
        &self,
        review: &AdmissionReview,
        time: Option<u64>,
    ) -> Result<ReviewedAdmission, MigrationError> {
        if !self.exact_introduction_inputs {
            return Err(fail(
                "MIXED_OR_UNSUPPORTED_ADMISSION",
                "split implementation, ownership, visibility, evaluator and unrelated authority changes before admission",
            ));
        }
        let path = governance_path()?;
        if self.original.bytes(&path) != self.proposed.bytes(&path) {
            return Err(fail(
                "CHANGED_FINDING_GOVERNANCE",
                "the candidate may not supply its own admissions, baseline edits or review history",
            ));
        }
        let proposed_governance = self
            .governance
            .propose_admissions(&self.assessment, review, time)
            .map_err(convert)?;
        let postimage = proposed_governance
            .to_canonical_json()
            .map_err(convert)?
            .into_bytes();
        let mut operations = self.operations.clone();
        operations.push(match self.original.bytes(&path) {
            Some(preimage) => MigrationOperation::ReplaceFile {
                path,
                preimage: preimage.to_vec(),
                postimage,
            },
            None => MigrationOperation::CreateFile { path, postimage },
        });
        let graph = OperationGraph::compile(&self.original, operations, &self.ownership)?;
        let original_state_ref = self
            .assessment
            .original
            .as_ref()
            .ok_or_else(|| {
                fail(
                    "ORIGINAL_HISTORY_UNAVAILABLE",
                    "original assessment required",
                )
            })?
            .state_ref
            .clone();
        Ok(ReviewedAdmission {
            assessment_ref: self.assessment.digest().map_err(convert)?,
            original_state_ref,
            original: self.original.clone(),
            target: graph.target().clone(),
            operations: graph.operations().to_vec(),
            proposed_governance,
            expires_at: review.expires_at,
            history_refs: self.assessment.history_refs.clone(),
        })
    }
}

impl ReviewedAdmission {
    /// Content-addressed reviewed classification that is included in the changed authority bytes.
    #[must_use]
    pub fn assessment_ref(&self) -> &str {
        &self.assessment_ref
    }

    /// Exact original state, used by independent authority to select historical scope.
    #[must_use]
    pub fn original_state_ref(&self) -> &str {
        &self.original_state_ref
    }

    /// Exact historical inputs used by the producer, without any implication of completeness.
    #[must_use]
    pub const fn history_refs(&self) -> &std::collections::BTreeSet<String> {
        &self.history_refs
    }

    /// Draft document, preserving all baseline and lifecycle records.
    #[must_use]
    pub const fn proposed_governance(&self) -> &FindingGovernanceDocument {
        &self.proposed_governance
    }

    /// Composes the existing, fully evaluated migration plan; writes and rollback remain shared.
    /// # Errors
    /// Refuses stale bindings, invalid operations and unavailable authority requirements.
    pub fn preview(
        &self,
        evaluator: &impl MigrationEvaluator,
        authority: &impl MigrationAuthority,
    ) -> Result<MigrationPreview, MigrationError> {
        preview_migration(
            evaluator,
            authority,
            &self.original,
            self.operations.clone(),
            MigrationOptions::default(),
        )
    }

    /// Gets the original authority port's opaque authorization for this exact reviewed plan.
    /// The migration writer independently rechecks it at the mutation boundary.
    /// # Errors
    /// Refuses stale plans, invalid bindings or unavailable independent grants.
    pub fn authorize_preview(
        &self,
        preview: &MigrationPreview,
        authority: &impl MigrationAuthority,
        time: Option<u64>,
    ) -> Result<crate::development_governance::ApplicationAuthorization, MigrationError> {
        self.validate_operations(&preview.base, &self.original, &preview.changes, time)?;
        authority.authorize(
            &preview.base,
            &preview.target,
            &self.original,
            &preview.changes,
            &preview.plan.options().comparison_context,
        )
    }

    /// Verifies the fully reobserved state that may be given the process-local treatment.
    /// # Errors
    /// Refuses stale scope, changed actual state, expired time and other approvals.
    pub fn validate_actual(
        &self,
        state: &MigrationEvaluation,
        source: &SourceView,
        permission: &crate::development_governance::ApplicationAuthorization,
        time: Option<u64>,
    ) -> Result<(), MigrationError> {
        self.validate_time(time)?;
        if self.target != *source
            || self.original_state_ref != permission.record().base_state_ref
            || state.state.digest().map_err(super::convert)?
                != permission.record().candidate_state_ref
            || permission.grants().iter().any(|grant| {
                grant
                    .assertion()
                    .expires_at
                    .is_some_and(|expiry| time.is_none_or(|now| expiry <= now))
            })
        {
            return Err(fail(
                "STALE_ADMISSION_REVIEW",
                "actual source or canonical state differs from authorized treatment, or its grant expired",
            ));
        }
        Ok(())
    }

    /// Rechecks the exact changed bytes against the canonical original and this explicit review.
    /// # Errors
    /// Refuses even a same-purpose additional operation, stale expiry or source drift.
    pub fn validate_operations(
        &self,
        base: &MigrationEvaluation,
        before: &SourceView,
        changes: &CandidateChangeSet,
        time: Option<u64>,
    ) -> Result<(), MigrationError> {
        self.validate_time(time)?;
        if self.original != *before
            || self.target != *changes.view()
            || self.original_state_ref != base.state.digest().map_err(super::convert)?
        {
            return Err(fail(
                "STALE_ADMISSION_REVIEW",
                "the source, evaluated original or reviewed target changed",
            ));
        }
        let expected = self
            .operations
            .iter()
            .map(MigrationOperation::neutral)
            .collect::<Vec<_>>();
        if !expected
            .iter()
            .all(|operation| changes.operations().contains(operation))
            || expected.len() != changes.operations().len()
        {
            return Err(fail(
                "STALE_ADMISSION_REVIEW",
                "application operations exceed the exact reviewed operation set",
            ));
        }
        Ok(())
    }

    fn validate_time(&self, time: Option<u64>) -> Result<(), MigrationError> {
        if self
            .expires_at
            .is_some_and(|expiry| time.is_none_or(|now| expiry <= now))
        {
            return Err(fail(
                "EXPIRED_OR_TIME_REQUIRED",
                "this review needs current trusted time",
            ));
        }
        Ok(())
    }
}

pub(crate) fn governance_path() -> Result<String, MigrationError> {
    ControlLayout::standard()
        .role_path(ControlRole::FindingGovernance)
        .map(str::to_owned)
        .ok_or_else(|| {
            fail(
                "UNAVAILABLE_ROLE",
                "registered finding governance role required",
            )
        })
}

fn convert(error: impl std::fmt::Display) -> MigrationError {
    fail("INVALID_ADMISSION", error.to_string())
}
