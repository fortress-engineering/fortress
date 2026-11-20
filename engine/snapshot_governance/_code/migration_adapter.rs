//! Snapshot composition of full canonical evaluation, AUTHORITY and explicit migration calls.
use crate::development_governance::{
    ApplicationAuthorityRecord, ApplicationAuthorization, GrantValidator, HostCoverage,
    PhysicalMigrationInputs, PreparedChange, TrustedBasePolicy, authorize_initial_establishment,
    authorize_no_source_change, authorize_ungoverned_unprotected, evaluate_change_with_grants,
};
use crate::migration_governance::{
    MAX_MIGRATION_BYTES, MigrationAuthority, MigrationError, MigrationEvaluation,
    MigrationEvaluator, MigrationValidation, MigrationValidationFact, MigrationValidationState,
};
use crate::observation::{CandidateChangeSet, ObservationLimits, ObservationPolicy, SourceView};
use crate::state_governance::ComparisonContext;
use std::collections::BTreeSet;
use std::path::Path;

fn convert(e: impl std::fmt::Display) -> MigrationError {
    MigrationError {
        code: "CANONICAL_INPUT_ERROR".into(),
        message: e.to_string(),
        transaction_ref: None,
    }
}
fn authority_error(error: crate::state_governance::TransitionError) -> MigrationError {
    MigrationError {
        code: error.code,
        message: error.message,
        transaction_ref: None,
    }
}

/// Full immutable canonical evaluation; never executes project build scripts.
pub struct CanonicalMigrationEvaluator;
impl MigrationEvaluator for CanonicalMigrationEvaluator {
    fn evaluate(&self, source: &SourceView) -> Result<MigrationEvaluation, MigrationError> {
        crate::audit::evaluate_migration_source(source).map_err(convert)
    }
    fn observe(&self, repository: &Path) -> Result<SourceView, MigrationError> {
        crate::audit::observe_migration_source(repository).map_err(convert)
    }
}
/// Trusted embedding supplies original base policy and independently authenticated grant port.
/// Candidate files, JSON plans and command-line references cannot construct external grants.
pub struct CanonicalMigrationAuthority<'a, H, V> {
    /// Explicit trusted original policy; never selected from the candidate by this adapter.
    pub policy: Option<&'a TrustedBasePolicy>,
    /// Existing host mediation knowledge, kept independent of grant verification.
    pub host: &'a H,
    /// Existing independently trusted external validation boundary.
    pub validator: &'a V,
    /// Explicit clock input, where expiring grants require it.
    pub evaluation_time: Option<u64>,
    /// Exact first-intent review identity, only for narrow initially ungoverned creation.
    pub reviewed_initial_intent_ref: Option<&'a str>,
    /// Owner-created RATCHET maintenance proposal; repository JSON cannot construct it.
    pub finding_proposal: Option<&'a crate::lifecycle_load::GovernanceProposal>,
    /// Exact identity-owner plan; normalization evidence remains separate from external permission.
    pub identity_plan: Option<&'a crate::identity_migration::IdentityMigrationPlan>,
}
impl<H: HostCoverage, V: GrantValidator> CanonicalMigrationAuthority<'_, H, V> {
    fn absent(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<Option<ApplicationAuthorization>, MigrationError> {
        if changes.operations().is_empty() {
            return authorize_no_source_change(
                &base.state,
                &target.state,
                context,
                source,
                changes,
            )
            .map(Some)
            .map_err(authority_error);
        }
        if base
            .state
            .governing_identity()
            .map_err(authority_error)?
            .is_none()
        {
            if let Some(review) = self.reviewed_initial_intent_ref {
                return authorize_initial_establishment(
                    &base.state,
                    &target.state,
                    context,
                    source,
                    changes,
                    review,
                )
                .map(Some)
                .map_err(authority_error);
            }
            return authorize_ungoverned_unprotected(
                &base.state,
                &target.state,
                context,
                source,
                changes,
            )
            .map(Some)
            .map_err(authority_error);
        }
        Ok(None)
    }
    fn prepared(
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<PreparedChange, MigrationError> {
        let complete = [&base.state, &target.state].iter().all(|source| {
            source
                .assets
                .as_ref()
                .is_some_and(|a| a.complete_axes.len() == 4)
        });
        PreparedChange::new_for_migration(
            &base.state,
            &target.state,
            context,
            PhysicalMigrationInputs {
                base: source,
                changes,
                evaluated_base: &base.evaluated_source,
                evaluated_target: &target.evaluated_source,
            },
            (
                base.protected_inputs.clone(),
                target.protected_inputs.clone(),
            ),
            complete,
        )
        .map_err(authority_error)
    }
    fn check_finding_maintenance(
        &self,
        base: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
    ) -> Result<(), MigrationError> {
        let path = crate::control_layout::ControlLayout::standard()
            .role_path(crate::control_layout::ControlRole::FindingGovernance)
            .ok_or_else(|| convert("finding governance role unavailable"))?
            .to_owned();
        let after = changes.view();
        if source.bytes(&path) != after.bytes(&path) {
            if self.finding_proposal.is_some() && self.identity_plan.is_some() {
                return Err(MigrationError { code: "AMBIGUOUS_MAINTENANCE_PROOF".into(), message: "Finding maintenance requires one exact owner-produced proof; competing interpretations are refused.".into(), transaction_ref: None });
            }
            if let Some(identity) = self.identity_plan {
                return crate::lifecycle_load::migration_identity_evidence(
                    identity, source, changes,
                )
                .map_err(authority_error);
            }
            let proposal = self.finding_proposal.ok_or_else(|| MigrationError {
                code: "REVIEWED_LIFECYCLE_PROPOSAL_REQUIRED".into(),
                message: "Finding governance maintenance requires the existing RATCHET owner's immutable proposal; permission alone does not establish retirement evidence.".into(), transaction_ref: None,
            })?;
            crate::lifecycle_load::migration_proposal_evidence(
                proposal,
                &base.state,
                source,
                after,
            )
            .map_err(authority_error)?;
        }
        Ok(())
    }
    fn policy(&self) -> Result<&TrustedBasePolicy, MigrationError> {
        self.policy.ok_or_else(||MigrationError{code:"TRUSTED_BASE_POLICY_REQUIRED".into(),message:"Existing governing authority requires an explicitly trusted original policy; repository approval assertions are not grants.".into(),transaction_ref:None})
    }
}
impl<H: HostCoverage, V: GrantValidator> MigrationAuthority
    for CanonicalMigrationAuthority<'_, H, V>
{
    fn preview(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<ApplicationAuthorityRecord, MigrationError> {
        if let Some(permission) = self.absent(base, target, source, changes, context)? {
            return Ok(permission.record().clone());
        }
        self.check_finding_maintenance(base, source, changes)?;
        let prepared = Self::prepared(base, target, source, changes, context)?;
        let decision = crate::development_governance::evaluate_change(
            &prepared,
            self.policy()?,
            self.host,
            &crate::development_governance::NoGrantValidator,
            self.evaluation_time,
        )
        .map_err(authority_error)?;
        ApplicationAuthorityRecord::from_decision(&decision, &prepared).map_err(authority_error)
    }
    fn authorize(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<ApplicationAuthorization, MigrationError> {
        if let Some(permission) = self.absent(base, target, source, changes, context)? {
            return Ok(permission);
        }
        self.check_finding_maintenance(base, source, changes)?;
        let prepared = Self::prepared(base, target, source, changes, context)?;
        let evaluated = evaluate_change_with_grants(
            &prepared,
            self.policy()?,
            self.host,
            self.validator,
            self.evaluation_time,
        )
        .map_err(authority_error)?;
        ApplicationAuthorization::from_evaluation(evaluated, &prepared).map_err(authority_error)
    }
}

/// Historical endpoints independently selected by the trusted embedding for this original state.
/// Repository-provided records and omissions may not establish the completeness of this set.
pub struct TrustedAdmissionHistory {
    original_state_ref: String,
    history_refs: BTreeSet<String>,
}

impl TrustedAdmissionHistory {
    /// Installs the independently checked history selection. An empty set is only appropriate
    /// when the embedding has independently established the original boundary.
    /// # Errors
    /// Refuses missing identities, malformed digests or exhaustive resource limits.
    pub fn from_host(
        original_state_ref: String,
        history_refs: BTreeSet<String>,
    ) -> Result<Self, MigrationError> {
        if history_refs.len() > 64
            || !std::iter::once(&original_state_ref)
                .chain(&history_refs)
                .all(|id| {
                    id.strip_prefix("sha256:").is_some_and(|suffix| {
                        suffix.len() == 64
                            && suffix
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                })
        {
            return Err(convert(
                "trusted admission history requires bounded exact state identities",
            ));
        }
        Ok(Self {
            original_state_ref,
            history_refs,
        })
    }
}

/// Applies the existing original-authority grant boundary to one owner-reviewed admission.
/// Decision references and unsigned receipts cannot create this prepared operation or a grant.
pub struct CanonicalAdmissionMigrationAuthority<'a, H, V> {
    /// Standard trusted-base policy and external grant validation port.
    pub authority: CanonicalMigrationAuthority<'a, H, V>,
    /// Exact evaluated and explicitly reviewed finding set.
    pub reviewed: &'a crate::migration_governance::ReviewedAdmission,
    /// Independent history selection, required for actual authorization.
    pub history: Option<&'a TrustedAdmissionHistory>,
}

impl<H: HostCoverage, V: GrantValidator> CanonicalAdmissionMigrationAuthority<'_, H, V> {
    fn prepared(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<PreparedChange, MigrationError> {
        if self.authority.finding_proposal.is_some()
            || self.authority.identity_plan.is_some()
            || self.authority.reviewed_initial_intent_ref.is_some()
        {
            return Err(convert(
                "competing authority interpretations cannot apply admissions",
            ));
        }
        self.reviewed
            .validate_operations(base, source, changes, self.authority.evaluation_time)?;
        CanonicalMigrationAuthority::<H, V>::prepared(base, target, source, changes, context)
    }
}

impl<H: HostCoverage, V: GrantValidator> MigrationAuthority
    for CanonicalAdmissionMigrationAuthority<'_, H, V>
{
    fn preview(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<ApplicationAuthorityRecord, MigrationError> {
        let prepared = self.prepared(base, target, source, changes, context)?;
        let decision = crate::development_governance::evaluate_change(
            &prepared,
            self.authority.policy()?,
            self.authority.host,
            &crate::development_governance::NoGrantValidator,
            self.authority.evaluation_time,
        )
        .map_err(authority_error)?;
        ApplicationAuthorityRecord::from_decision(&decision, &prepared).map_err(authority_error)
    }

    fn authorize(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<ApplicationAuthorization, MigrationError> {
        let prepared = self.prepared(base, target, source, changes, context)?;
        if self.history.is_none_or(|history| {
            history.original_state_ref != self.reviewed.original_state_ref()
                || &history.history_refs != self.reviewed.history_refs()
        }) {
            return Err(MigrationError {
                code: "TRUSTED_HISTORY_REQUIRED".into(),
                message: "Independently selected original authority and history are required to rule out reactivation.".into(),
                transaction_ref: None,
            });
        }
        let evaluated = evaluate_change_with_grants(
            &prepared,
            self.authority.policy()?,
            self.authority.host,
            self.authority.validator,
            self.authority.evaluation_time,
        )
        .map_err(authority_error)?;
        let authorization = ApplicationAuthorization::from_evaluation(evaluated, &prepared)
            .map_err(authority_error)?;
        require_finding_grant(&authorization)?;
        Ok(authorization)
    }
}

pub(crate) fn require_finding_grant(
    authorization: &ApplicationAuthorization,
) -> Result<(), MigrationError> {
    let path = crate::migration_governance::admission_governance_path()?;
    if !authorization.record().requirements().iter().any(|r| {
        r.path == path
            && r.class == crate::authority_roles::ProtectedClass::FindingGovernance
            && authorization
                .grants()
                .iter()
                .any(|g| g.assertion().requirement_ref == r.id)
    }) {
        return Err(MigrationError {
            code: "AUTHORIZATION_REQUIRED".into(),
            message: "The exact admission postimage requires an independently validated finding-governance grant.".into(),
            transaction_ref: None,
        });
    }
    Ok(())
}
/// Builds the physical source observation policy from registered output families only.
pub(crate) fn physical_policy() -> Result<ObservationPolicy, MigrationError> {
    let layout = crate::control_layout::ControlLayout::standard();
    let mut excluded = layout
        .artifact_logical_paths()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    excluded.extend(
        layout
            .migration_record_roots()
            .into_iter()
            .map(str::to_owned),
    );
    if let Some(path) = layout
        .role_path(crate::control_layout::ControlRole::AssessmentSelectionIndex)
        .and_then(|prepared| prepared.rsplit_once('/').map(|context| context.0))
    {
        excluded.push(path.into());
    }
    ObservationPolicy::new(excluded).map_err(convert)
}
/// Bounded physical observation admission used independently of candidate exclusions.
pub(crate) const fn physical_limits() -> ObservationLimits {
    ObservationLimits {
        max_files: 50_000,
        max_entries: 100_000,
        max_source_bytes: MAX_MIGRATION_BYTES as u64,
        max_path_bytes: 8 * 1024 * 1024,
    }
}

/// Established external storage default, with explicit override for same-volume selection.
/// # Errors
/// Refuses unsafe storage configuration; acquire independently verifies native volume identity.
pub fn default_migration_storage()
-> Result<crate::runtime_storage::MigrationStorage, MigrationError> {
    let root = std::env::var_os("FORTRESS_EXECUTION_STORAGE_DIR")
        .map_or_else(|| std::env::temp_dir().join("fx"), std::path::PathBuf::from);
    crate::runtime_storage::MigrationStorage::new(
        root,
        crate::runtime_storage::StoragePolicy::default(),
    )
}

/// Explicit owner-reviewed retirement inputs, kept outside the serialized migration plan.
pub struct MigrationRetirementInputs {
    /// Exact physical pre-maintenance source, preserving original proof bindings.
    pub base: SourceView,
    /// Existing RATCHET owner-created proposal; not deserializable approval.
    pub proposal: crate::lifecycle_load::GovernanceProposal,
    /// Exact selected original proof references required by this migration.
    pub required_refs: std::collections::BTreeSet<String>,
}
/// Canonical evaluation plus existing-owner retirement proof admission, without self-reference.
pub struct CanonicalRetirementMigrationEvaluator<'a> {
    /// Immutable original proof inputs supplied by the embedding.
    pub retirement: &'a MigrationRetirementInputs,
}
impl MigrationEvaluator for CanonicalRetirementMigrationEvaluator<'_> {
    fn observe(&self, root: &Path) -> Result<SourceView, MigrationError> {
        CanonicalMigrationEvaluator.observe(root)
    }
    fn evaluate(&self, source: &SourceView) -> Result<MigrationEvaluation, MigrationError> {
        if self.retirement.required_refs.is_empty() || self.retirement.required_refs.len() > 64 {
            return Err(convert(
                "explicit bounded retirement proof selection required",
            ));
        }
        let mut evaluated = CanonicalMigrationEvaluator.evaluate(source)?;
        if source == &self.retirement.base {
            return Ok(evaluated);
        }
        let original = CanonicalMigrationEvaluator.evaluate(&self.retirement.base)?;
        let supported = crate::lifecycle_load::migration_proposal_evidence(
            &self.retirement.proposal,
            &original.state,
            &self.retirement.base,
            source,
        )
        .map_err(authority_error)?;
        let satisfied = self.retirement.required_refs.is_subset(&supported);
        evaluated.validations.insert(MigrationValidation::ComparableRetirement, MigrationValidationFact {
            state: if satisfied { MigrationValidationState::Satisfied } else { MigrationValidationState::NotEvaluable },
            evidence_refs: self.retirement.required_refs.intersection(&supported).cloned().collect(),
            detail: "Existing RATCHET owner rederived original/current evidence before maintenance and bound the exact reviewed governance-only postimage. Permission and disappearance do not prove resolution.".into(),
        });
        Ok(evaluated)
    }
}
