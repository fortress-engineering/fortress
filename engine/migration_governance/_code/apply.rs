//! One explicit source writer, final validation and immutable receipt publication.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::journal::{
    Journal, JournalAction, JournalHeader, PreparedObject, io_error, linked, read_regular,
    write_new,
};
use super::paths::{
    checked_path, checked_relative, observed_file, require_absent, require_owned_file,
    sync_directory,
};
use super::{
    BoundaryPhase, ExecutableAction, MAX_MIGRATION_BYTES, MigrationAuthority, MigrationError,
    MigrationEvaluator, MigrationPlan, MigrationPreview, MigrationResourceLease,
    MigrationValidation, MigrationValidationFact, MutationBoundary, MutationObserver,
    ResourceLeasePort, canonical, content_digest, fail, preview_migration,
};
use crate::development_governance::ApplicationAuthorityRecord;

/// Recorded outcome over the exact evaluated target; this is not semantic certification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MigrationOutcome {
    /// The reviewed source operations reached their independently validated target.
    Applied,
    /// The reviewed operation set was empty and actual state remained exact.
    NoOp,
}
/// Immutable successful application facts, never current authority or a transferable grant.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReceipt {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    receipt_digest: String,
    /// Exact reviewed plan identity.
    pub plan_ref: String,
    /// Original canonical endpoint.
    pub base_state_ref: String,
    /// Previously evaluated expected endpoint.
    pub target_state_ref: String,
    /// Independently reobserved and reevaluated actual endpoint.
    pub actual_state_ref: String,
    /// Actual exact bounded physical source inventory.
    pub actual_source_ref: String,
    /// Original four-axis comparison.
    pub transition_ref: String,
    /// Actual AUTHORITY result, retained only as provenance when exported.
    pub authorization: ApplicationAuthorityRecord,
    /// External grant provenance; these serialized records do not reconstruct grant handles.
    pub grant_provenance: Vec<serde_json::Value>,
    /// Original owner validation facts independently confirmed after application.
    pub validations: BTreeMap<MigrationValidation, MigrationValidationFact>,
    /// Actual supported operation count.
    pub operation_count: usize,
    /// Honest successful application outcome.
    pub outcome: MigrationOutcome,
    /// Migration itself never executes untrusted project code or implies runtime test execution.
    pub project_execution: String,
    /// Integrity and application provenance are independent of authentication and semantic proof.
    pub assurance_limitations: Vec<String>,
}
impl MigrationReceipt {
    /// Content identity, defined by JCS with `receipt_digest` empty.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.receipt_digest
    }
    /// Deterministic public receipt bytes.
    /// # Errors
    /// Refuses unsupported, tampered, inconsistent or oversized records.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        self.validate()?;
        canonical(self)
    }
    /// Validates an unsigned historical receipt without treating it as present-state authority.
    /// # Errors
    /// Refuses incompatible versions, tampered content and invalid exact-state bindings.
    pub fn from_json_str(text: &str) -> Result<Self, MigrationError> {
        if text.len() > MAX_MIGRATION_BYTES {
            return Err(fail("RESOURCE_LIMIT", "receipt exceeds public admission"));
        }
        let receipt: Self = crate::wire::parse_public_json(text)
            .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
        receipt.validate()?;
        Ok(receipt)
    }
    fn validate(&self) -> Result<(), MigrationError> {
        if self.schema != "urn:fortress:derived:v1:migration-receipt"
            || self.schema_version != 1
            || self.project_execution != "NOT_PERFORMED_BY_MIGRATION"
        {
            return Err(fail("UNSUPPORTED_VERSION", "unsupported migration receipt"));
        }
        if self.actual_state_ref != self.target_state_ref
            || self.authorization.candidate_state_ref != self.target_state_ref
            || self.authorization.base_state_ref != self.base_state_ref
            || self.authorization.transition_ref != self.transition_ref
        {
            return Err(fail(
                "INVALID_BINDING",
                "receipt actual/expected/authorization endpoints differ",
            ));
        }
        if self.operation_count > super::MAX_MIGRATION_OPERATIONS
            || (self.outcome == MigrationOutcome::NoOp) != (self.operation_count == 0)
            || self
                .validations
                .get(&MigrationValidation::EvaluationCompleted)
                .is_none_or(|f| f.state != super::MigrationValidationState::Satisfied)
            || self.validations.values().any(|f| {
                f.state != super::MigrationValidationState::Satisfied
                    || f.detail.len() > 4096
                    || f.evidence_refs.len() > 50_000
                    || f.evidence_refs
                        .iter()
                        .any(|r| !crate::declaration::is_digest(r))
                    || f.evidence_refs.windows(2).any(|r| r[0] >= r[1])
            })
        {
            return Err(fail(
                "INVALID_BINDING",
                "completed receipt lacks bounded satisfied owner validations or coherent operation outcome",
            ));
        }
        self.authorization.digest().map_err(super::model::convert)?;
        for id in [
            &self.receipt_digest,
            &self.plan_ref,
            &self.base_state_ref,
            &self.target_state_ref,
            &self.actual_state_ref,
            &self.actual_source_ref,
            &self.transition_ref,
        ] {
            if !crate::declaration::is_digest(id) {
                return Err(fail("INVALID_IDENTITY", id));
            }
        }
        let mut unsigned = self.clone();
        unsigned.receipt_digest.clear();
        if content_digest(&canonical(&unsigned)?) != self.receipt_digest {
            return Err(fail("TAMPERED_RECEIPT", "receipt content identity differs"));
        }
        Ok(())
    }
}
/// Actual application and its immutable registered record location.
pub struct MigrationApplication {
    /// Independently established completed facts.
    pub receipt: MigrationReceipt,
    /// Registered repository-relative immutable record path.
    pub record_path: String,
    /// Machine-local transaction incarnation for retained recovery/audit material.
    pub transaction_ref: String,
}
/// Explicit application dependencies; none may be loaded from candidate approval assertions.
pub struct MigrationServices<'a, E, A, R, O> {
    /// Existing complete canonical evaluation adapter.
    pub evaluator: &'a E,
    /// Existing trusted AUTHORITY integration.
    pub authority: &'a A,
    /// Existing OPS lease/storage integration.
    pub resources: &'a R,
    /// Cancellation and bounded deterministic fault controls.
    pub observer: &'a O,
}

struct Boundaries<'a, O> {
    observer: &'a O,
    ordinal: u64,
}
impl<O: MutationObserver> Boundaries<'_, O> {
    fn at(&mut self, kind: MutationBoundary, phase: BoundaryPhase) -> Result<(), MigrationError> {
        let n = self.ordinal;
        self.ordinal += 1;
        self.observer.boundary(n, kind, phase)
    }
    fn append(
        &mut self,
        journal: &mut Journal,
        action: JournalAction,
        intent: bool,
    ) -> Result<(), MigrationError> {
        let kind = if intent {
            MutationBoundary::JournalIntent
        } else {
            MutationBoundary::JournalCompletion
        };
        self.at(kind, BoundaryPhase::Before)?;
        journal.append(action)?;
        self.at(kind, BoundaryPhase::After)
    }
}

/// Applies only after fresh complete preview and process-local AUTHORITY verification.
/// Failures retain journal/rollback material; an attempted rollback is never reported as success.
/// # Errors
/// Refuses stale reviews, missing grants, bad ownership, unsafe paths, incomplete target validation
/// and conflicting actual state. Errors after lease allocation identify the retained transaction.
pub fn apply_migration<
    E: MigrationEvaluator,
    A: MigrationAuthority,
    R: ResourceLeasePort,
    O: MutationObserver,
>(
    repository: &Path,
    plan: &MigrationPlan,
    services: &MigrationServices<'_, E, A, R, O>,
) -> Result<MigrationApplication, MigrationError> {
    plan.validate()?;
    let before = services.evaluator.observe(repository)?;
    if before.digest() != plan.base_source_ref() {
        return Err(fail(
            "STALE_REVIEWED_PLAN",
            "actual source differs from reviewed base; no repository mutation performed",
        ));
    }
    verify_base_paths(repository, plan)?;
    let preview = preview_migration(
        services.evaluator,
        services.authority,
        &before,
        plan.operations().to_vec(),
        plan.options().clone(),
    )?;
    if preview.plan.digest() != plan.digest() {
        return Err(fail(
            "REVIEWED_TARGET_CHANGED",
            "fresh canonical target, authority or validation differs from reviewed plan",
        ));
    }
    if !plan.validations_satisfied() {
        return Err(fail(
            "VALIDATION_REQUIRED",
            "requested validation is not sufficiently established",
        ));
    }
    let permission = services.authority.authorize(
        &preview.base,
        &preview.target,
        &before,
        &preview.changes,
        &plan.options().comparison_context,
    )?;
    if permission
        .record()
        .requirement_contract_ref()
        .map_err(super::model::convert)?
        != plan.authorization_contract_ref()
    {
        return Err(fail(
            "AUTHORIZATION_BINDING_MISMATCH",
            "actual grant requirements differ from the reviewed plan",
        ));
    }
    let receipt = proposed_receipt(plan, &preview, &permission)?;
    let required = (plan.to_canonical_bytes()?.len() as u64)
        .checked_mul(4)
        .and_then(|n| n.checked_add(16 * 1024 * 1024))
        .ok_or_else(|| fail("RESOURCE_LIMIT", "migration allocation overflow"))?;
    let mut lease = services
        .resources
        .acquire(repository, plan.digest(), required)?;
    let transaction = lease.transaction_ref().to_owned();
    let result = apply_owned(
        repository,
        plan,
        &preview,
        &receipt,
        &mut lease,
        services.evaluator,
        services.observer,
    );
    result.map_err(|mut error| {
        error.transaction_ref = Some(transaction);
        error
    })
}

fn proposed_receipt(
    plan: &MigrationPlan,
    preview: &MigrationPreview,
    permission: &crate::development_governance::ApplicationAuthorization,
) -> Result<MigrationReceipt, MigrationError> {
    let mut receipt = MigrationReceipt {
        schema: "urn:fortress:derived:v1:migration-receipt".into(), schema_version: 1, receipt_digest: String::new(),
        plan_ref: plan.digest().into(), base_state_ref: plan.base_state_ref().into(), target_state_ref: plan.target_state_ref().into(),
        actual_state_ref: plan.target_state_ref().into(), actual_source_ref: plan.target_source_ref().into(), transition_ref: preview.transition.digest().map_err(super::model::convert)?,
        authorization: permission.record().clone(), grant_provenance: permission.grants().iter().map(serde_json::to_value).collect::<Result<_, _>>().map_err(|e| fail("INVALID_INPUT", e.to_string()))?,
        validations: plan.validation_facts().clone(), operation_count: plan.operations().len(), outcome: if plan.operations().is_empty() { MigrationOutcome::NoOp } else { MigrationOutcome::Applied },
        project_execution: "NOT_PERFORMED_BY_MIGRATION".into(),
        assurance_limitations: vec!["Completed application facts are historical, not current authority or general correctness proof.".into(), "Serialized authorization is provenance, not an authenticated transferable grant.".into(), "Qualified cooperative process-crash recovery does not establish filesystem-wide atomicity, hostile-filesystem safety or power-loss ordering.".into()],
    };
    receipt.receipt_digest = content_digest(&canonical(&receipt)?);
    receipt.validate()?;
    Ok(receipt)
}

fn apply_owned<L: MigrationResourceLease, E: MigrationEvaluator, O: MutationObserver>(
    repository: &Path,
    plan: &MigrationPlan,
    preview: &MigrationPreview,
    receipt: &MigrationReceipt,
    lease: &mut L,
    evaluator: &E,
    observer: &O,
) -> Result<MigrationApplication, MigrationError> {
    lease.verify(repository)?;
    if evaluator.observe(repository)?.digest() != plan.base_source_ref() {
        return Err(fail(
            "STALE_REVIEWED_PLAN",
            "source changed before prepared transaction",
        ));
    }
    let mut boundary = Boundaries {
        observer,
        ordinal: 0,
    };
    let (header, mut journal) =
        prepare_transaction(repository, plan, receipt, lease, &mut boundary)?;
    lease.verify(repository)?;
    if evaluator.observe(repository)?.digest() != plan.base_source_ref() {
        return Err(fail(
            "STALE_REVIEWED_PLAN",
            "source changed during transaction preparation",
        ));
    }
    verify_base_paths(repository, plan)?;
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::Before)?;
    lease.applying(plan.digest(), journal.path())?;
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::After)?;
    install_parents(
        repository,
        &header.objects,
        lease,
        &mut journal,
        &mut boundary,
    )?;
    run_steps(
        repository,
        plan,
        &header.objects,
        lease,
        &mut journal,
        &mut boundary,
    )?;
    validate_actual(repository, plan, evaluator, &mut journal, &mut boundary)?;
    // `preview` is retained only to keep the exact evaluated inputs live throughout application.
    if preview
        .target
        .state
        .digest()
        .map_err(super::model::convert)?
        != plan.target_state_ref()
    {
        return Err(fail(
            "EVALUATOR_BINDING_MISMATCH",
            "prepared target changed",
        ));
    }
    let record_path = publish_receipt(
        repository,
        receipt,
        &header.objects,
        lease,
        &mut journal,
        &mut boundary,
        (evaluator, plan),
    )?;
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::Before)?;
    if evaluator.observe(repository)?.digest() != plan.target_source_ref() {
        return Err(fail(
            "SOURCE_DRIFT",
            "actual source changed before application completion",
        ));
    }
    journal.verify_integrity()?;
    verify_expected_paths(repository, plan)?;
    lease.finish("COMMITTED", receipt.digest())?;
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::After)?;
    Ok(MigrationApplication {
        receipt: receipt.clone(),
        record_path,
        transaction_ref: lease.transaction_ref().into(),
    })
}

fn prepare_transaction<L: MigrationResourceLease, O: MutationObserver>(
    repository: &Path,
    plan: &MigrationPlan,
    receipt: &MigrationReceipt,
    lease: &L,
    boundary: &mut Boundaries<'_, O>,
) -> Result<(JournalHeader, Journal), MigrationError> {
    let root = lease.root();
    if root.starts_with(repository) {
        return Err(fail(
            "INVALID_STORAGE",
            "transaction staging must remain external",
        ));
    }
    let mut objects = vec![];
    for step in plan.operation_graph() {
        if let ExecutableAction::Evacuate { path, slot, digest } = &step.action {
            let source = checked_path(repository, path)?;
            let bytes = read_regular(&source, MAX_MIGRATION_BYTES)?;
            if content_digest(&bytes) != *digest {
                return Err(fail("STALE_PREIMAGE", path));
            }
            objects.push(PreparedObject {
                slot: slot.clone(),
                path: path.clone(),
                identity: lease.object_identity(&source)?,
                digest: Some(digest.clone()),
                directory: false,
            });
        }
    }
    let initial = JournalHeader {
        schema_version: 1,
        plan_ref: plan.digest().into(),
        transaction_ref: lease.transaction_ref().into(),
        repository_identity: lease.repository_identity().into(),
        objects: objects.clone(),
    };
    let mut journal = Journal::create(root, &initial, |phase| {
        boundary.at(MutationBoundary::Preparation, phase)
    })?;
    boundary.append(&mut journal, JournalAction::PlanIntent, true)?;
    boundary.at(MutationBoundary::Preparation, BoundaryPhase::Before)?;
    write_new(&root.join("plan.json"), &plan.to_canonical_bytes()?)?;
    boundary.at(MutationBoundary::Preparation, BoundaryPhase::After)?;
    boundary.append(&mut journal, JournalAction::PlanComplete, false)?;
    prepare_outputs(plan, receipt, lease, &mut objects, &mut journal, boundary)?;
    prepare_parents(
        repository,
        plan,
        receipt,
        lease,
        &mut objects,
        &mut journal,
        boundary,
    )?;
    let completed = JournalHeader { objects, ..initial };
    let bytes = canonical(&completed)?;
    boundary.append(
        &mut journal,
        JournalAction::PrepareIntent {
            slot: "prepared.json".into(),
            digest: Some(content_digest(&bytes)),
            directory: false,
        },
        true,
    )?;
    boundary.at(MutationBoundary::Preparation, BoundaryPhase::Before)?;
    write_new(&root.join("prepared.json"), &bytes)?;
    boundary.at(MutationBoundary::Preparation, BoundaryPhase::After)?;
    boundary.append(
        &mut journal,
        JournalAction::ObjectsPrepared {
            digest: content_digest(&bytes),
        },
        false,
    )?;
    let parent_bytes = completed
        .objects
        .iter()
        .filter(|o| o.directory)
        .try_fold(0usize, |n, o| {
            n.checked_add(o.path.len().saturating_mul(4).saturating_add(2048))
        })
        .ok_or_else(|| fail("RESOURCE_LIMIT", "journal reservation overflow"))?;
    let recovery_bytes = parent_bytes
        .saturating_add(plan.operation_graph().len().saturating_mul(2048))
        .saturating_add(65_536);
    let recovery_events = completed
        .objects
        .len()
        .saturating_add(plan.operation_graph().len())
        .saturating_mul(8)
        .saturating_add(64);
    journal.require_capacity(recovery_bytes, recovery_events)?;
    lease.reserve(recovery_bytes as u64)?;
    Ok((completed, journal))
}

fn prepare_file<L: MigrationResourceLease, O: MutationObserver>(
    root: &Path,
    slot: &str,
    bytes: &[u8],
    digest: &str,
    lease: &L,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
) -> Result<PreparedObject, MigrationError> {
    boundary.append(
        journal,
        JournalAction::PrepareIntent {
            slot: slot.into(),
            digest: Some(digest.into()),
            directory: false,
        },
        true,
    )?;
    boundary.at(MutationBoundary::Preparation, BoundaryPhase::Before)?;
    let path = root.join("slots").join(slot);
    write_new(&path, bytes)?;
    let identity = lease.object_identity(&path)?;
    require_owned_file(lease, &path, &identity, digest)?;
    boundary.at(MutationBoundary::Preparation, BoundaryPhase::After)?;
    boundary.append(
        journal,
        JournalAction::PrepareComplete {
            slot: slot.into(),
            identity: identity.clone(),
        },
        false,
    )?;
    Ok(PreparedObject {
        slot: slot.into(),
        path: String::new(),
        identity,
        digest: Some(digest.into()),
        directory: false,
    })
}
fn postimage_for_slot(plan: &MigrationPlan, slot: &str) -> Result<Vec<u8>, MigrationError> {
    for (i, op) in plan.operations().iter().enumerate() {
        if slot == format!("output-{i:04}") {
            return op
                .destination()
                .map(|(_, bytes)| bytes.to_vec())
                .ok_or_else(|| fail("INVALID_GRAPH", "staged operation has no postimage"));
        }
    }
    Err(fail("INVALID_GRAPH", "unknown output staging slot"))
}
fn object<'a>(
    objects: &'a [PreparedObject],
    slot: &str,
) -> Result<&'a PreparedObject, MigrationError> {
    objects
        .iter()
        .find(|o| o.slot == slot)
        .ok_or_else(|| fail("INVALID_JOURNAL", "missing prepared object"))
}
fn install_parents<L: MigrationResourceLease, O: MutationObserver>(
    repository: &Path,
    objects: &[PreparedObject],
    lease: &L,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
) -> Result<(), MigrationError> {
    let mut parents = objects.iter().filter(|o| o.directory).collect::<Vec<_>>();
    parents.sort_by_key(|o| (o.path.matches('/').count(), o.path.clone()));
    for parent in parents {
        let destination = checked_relative(repository, &parent.path)?;
        if fs::symlink_metadata(&destination).is_ok() {
            if lease.object_identity(&destination)? == parent.identity {
                continue;
            }
            return Err(fail("OWNERSHIP_CONFLICT", &parent.path));
        }
        boundary.append(
            journal,
            JournalAction::ParentIntent {
                path: parent.path.clone(),
                slot: parent.slot.clone(),
            },
            true,
        )?;
        boundary.at(MutationBoundary::ParentInstall, BoundaryPhase::Before)?;
        lease.verify(repository)?;
        require_absent(&checked_relative(repository, &parent.path)?)?;
        let staged = lease.root().join("parents").join(&parent.slot);
        if lease.object_identity(&staged)? != parent.identity {
            return Err(fail("OWNERSHIP_CONFLICT", &parent.slot));
        }
        fs::rename(&staged, &destination).map_err(io_error)?;
        if lease.object_identity(&destination)? != parent.identity {
            return Err(fail("OWNERSHIP_CONFLICT", &parent.path));
        }
        sync_directory(
            destination
                .parent()
                .ok_or_else(|| fail("UNSAFE_PATH", "parent unavailable"))?,
        )?;
        boundary.at(MutationBoundary::ParentInstall, BoundaryPhase::After)?;
        boundary.append(
            journal,
            JournalAction::ParentComplete {
                path: parent.path.clone(),
            },
            false,
        )?;
    }
    Ok(())
}
fn run_steps<L: MigrationResourceLease, O: MutationObserver>(
    repository: &Path,
    plan: &MigrationPlan,
    objects: &[PreparedObject],
    lease: &L,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
) -> Result<(), MigrationError> {
    for step in plan.operation_graph() {
        let slot = match &step.action {
            ExecutableAction::Evacuate { slot, .. }
            | ExecutableAction::Stage { slot, .. }
            | ExecutableAction::Install { slot, .. } => slot,
        };
        let prepared = object(objects, slot)?;
        let staged = lease.root().join("slots").join(slot);
        match &step.action {
            ExecutableAction::Stage { digest, .. } => {
                require_owned_file(lease, &staged, &prepared.identity, digest)?;
            }
            ExecutableAction::Evacuate { path, digest, .. } => {
                if staged.exists() {
                    require_owned_file(lease, &staged, &prepared.identity, digest)?;
                    continue;
                }
                boundary.append(journal, JournalAction::StepIntent { id: step.id }, true)?;
                boundary.at(MutationBoundary::Evacuate, BoundaryPhase::Before)?;
                lease.verify(repository)?;
                let source = checked_path(repository, path)?;
                require_owned_file(lease, &source, &prepared.identity, digest)?;
                require_absent(&staged)?;
                fs::rename(&source, &staged).map_err(io_error)?;
                require_owned_file(lease, &staged, &prepared.identity, digest)?;
                sync_directory(
                    source
                        .parent()
                        .ok_or_else(|| fail("UNSAFE_PATH", "parent unavailable"))?,
                )?;
                boundary.at(MutationBoundary::Evacuate, BoundaryPhase::After)?;
                boundary.append(journal, JournalAction::StepComplete { id: step.id }, false)?;
            }
            ExecutableAction::Install { path, digest, .. } => {
                let destination = checked_path(repository, path)?;
                if destination.exists() {
                    require_owned_file(lease, &destination, &prepared.identity, digest)?;
                    continue;
                }
                boundary.append(journal, JournalAction::StepIntent { id: step.id }, true)?;
                boundary.at(MutationBoundary::Install, BoundaryPhase::Before)?;
                lease.verify(repository)?;
                require_absent(&checked_path(repository, path)?)?;
                require_owned_file(lease, &staged, &prepared.identity, digest)?;
                fs::hard_link(&staged, &destination).map_err(io_error)?;
                require_owned_file(lease, &destination, &prepared.identity, digest)?;
                sync_directory(
                    destination
                        .parent()
                        .ok_or_else(|| fail("UNSAFE_PATH", "parent unavailable"))?,
                )?;
                boundary.at(MutationBoundary::Install, BoundaryPhase::After)?;
                boundary.append(journal, JournalAction::StepComplete { id: step.id }, false)?;
            }
        }
    }
    Ok(())
}

fn validate_actual<E: MigrationEvaluator, O: MutationObserver>(
    repository: &Path,
    plan: &MigrationPlan,
    evaluator: &E,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
) -> Result<(), MigrationError> {
    boundary.append(journal, JournalAction::ValidationIntent, true)?;
    verify_expected_paths(repository, plan)?;
    let source = evaluator.observe(repository)?;
    if source.digest() != plan.target_source_ref() {
        return Err(fail(
            "ACTUAL_TARGET_MISMATCH",
            "successful filesystem writes did not establish evaluated target bytes",
        ));
    }
    let actual = evaluator.evaluate(&source)?;
    actual.validate(&source)?;
    if actual.state.digest().map_err(super::model::convert)? != plan.target_state_ref()
        || plan
            .options()
            .validation_requirements
            .iter()
            .any(|r| actual.validations.get(r) != plan.validation_facts().get(r))
    {
        return Err(fail(
            "ACTUAL_EVALUATION_MISMATCH",
            "actual canonical validation differs from previously evaluated target",
        ));
    }
    if evaluator.observe(repository)? != source {
        return Err(fail(
            "SOURCE_DRIFT",
            "source changed during final actual validation",
        ));
    }
    boundary.append(
        journal,
        JournalAction::ValidationComplete {
            source_ref: source.digest().into(),
            state_ref: plan.target_state_ref().into(),
        },
        false,
    )
}
fn verify_base_paths(repository: &Path, plan: &MigrationPlan) -> Result<(), MigrationError> {
    verify_paths(repository, plan, true)
}
fn verify_expected_paths(repository: &Path, plan: &MigrationPlan) -> Result<(), MigrationError> {
    verify_paths(repository, plan, false)
}
fn verify_paths(
    repository: &Path,
    plan: &MigrationPlan,
    original: bool,
) -> Result<(), MigrationError> {
    for condition in plan.preconditions() {
        let path = checked_path(repository, &condition.path)?;
        let expected = if original {
            &condition.preimage
        } else {
            &condition.postimage
        };
        if let Some(digest) = expected {
            if observed_file(&path)?
                .as_deref()
                .map(content_digest)
                .as_ref()
                != Some(digest)
            {
                return Err(fail(
                    if original {
                        "STALE_PREIMAGE"
                    } else {
                        "ACTUAL_TARGET_MISMATCH"
                    },
                    &condition.path,
                ));
            }
        } else {
            require_absent(&path)?;
        }
    }
    Ok(())
}
fn receipt_path(receipt: &MigrationReceipt) -> Result<String, MigrationError> {
    crate::control_layout::ControlLayout::standard()
        .migration_receipt_path(receipt.digest())
        .ok_or_else(|| {
            fail(
                "UNAVAILABLE_ROLE",
                "registered migration receipt role unavailable",
            )
        })
}
fn publish_receipt<L: MigrationResourceLease, O: MutationObserver, E: MigrationEvaluator>(
    repository: &Path,
    receipt: &MigrationReceipt,
    objects: &[PreparedObject],
    lease: &L,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
    validation: (&E, &MigrationPlan),
) -> Result<String, MigrationError> {
    let (evaluator, plan) = validation;
    let relative = receipt_path(receipt)?;
    let destination = checked_relative(repository, &relative)?;
    let bytes = receipt.to_canonical_bytes()?;
    let prepared = object(objects, "receipt")?;
    let staged = lease.root().join("slots/receipt");
    let digest = content_digest(&bytes);
    require_owned_file(lease, &staged, &prepared.identity, &digest)?;
    boundary.append(
        journal,
        JournalAction::ReceiptIntent {
            path: relative.clone(),
            digest: digest.clone(),
        },
        true,
    )?;
    boundary.at(MutationBoundary::ReceiptPublication, BoundaryPhase::Before)?;
    lease.verify(repository)?;
    journal.verify_integrity()?;
    verify_expected_paths(repository, plan)?;
    if evaluator.observe(repository)?.digest() != plan.target_source_ref() {
        return Err(fail(
            "ACTUAL_TARGET_MISMATCH",
            "source changed before immutable receipt publication",
        ));
    }
    if let Some(existing) = observed_file(&destination)? {
        if existing != bytes {
            return Err(fail("IMMUTABLE_RECORD_CONFLICT", relative));
        }
    } else {
        require_absent(&checked_relative(repository, &relative)?)?;
        fs::hard_link(staged, &destination).map_err(io_error)?;
    }
    if read_regular(&destination, MAX_MIGRATION_BYTES)? != bytes {
        return Err(fail("IMMUTABLE_RECORD_CONFLICT", &relative));
    }
    sync_directory(
        destination
            .parent()
            .ok_or_else(|| fail("UNSAFE_PATH", "record parent unavailable"))?,
    )?;
    boundary.at(MutationBoundary::ReceiptPublication, BoundaryPhase::After)?;
    boundary.append(
        journal,
        JournalAction::ReceiptComplete {
            path: relative.clone(),
            digest,
        },
        false,
    )?;
    Ok(relative)
}

/// Explicit direction for recovery of an inactive owned transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationRecoveryMode {
    /// Recheck authorization, resume known steps and validate actual target.
    Resume,
    /// Restore only known original bytes, without overwriting independent edits.
    Rollback,
}
/// Verified recovery result; no attempted rollback is silently promoted to completion.
pub struct MigrationRecovery {
    /// Operational outcome, including byte-verified rollback rather than semantic improvement.
    pub outcome: String,
    /// Reobserved actual bounded source identity.
    pub actual_source_ref: String,
    /// Existing successful receipt only when the actual target is established.
    pub receipt: Option<MigrationReceipt>,
    /// Retained machine-local transaction incarnation.
    pub transaction_ref: String,
}

/// Recovers only an inactive, exclusively owned plan incarnation.
/// # Errors
/// Refuses malformed ownership, unknown bytes, changed external files, stale authorization
/// or failed actual validation. All ambiguous content and recovery material are retained.
pub fn recover_migration<
    E: MigrationEvaluator,
    A: MigrationAuthority,
    R: ResourceLeasePort,
    O: MutationObserver,
>(
    repository: &Path,
    plan: &MigrationPlan,
    transaction_ref: &str,
    mode: MigrationRecoveryMode,
    services: &MigrationServices<'_, E, A, R, O>,
) -> Result<MigrationRecovery, MigrationError> {
    plan.validate()?;
    let mut lease = services
        .resources
        .recover(repository, transaction_ref, plan.digest())?;
    let result = recover_owned(repository, plan, mode, &mut lease, services);
    result.map_err(|mut error| {
        error.transaction_ref = Some(transaction_ref.into());
        error
    })
}
fn recover_owned<
    E: MigrationEvaluator,
    A: MigrationAuthority,
    R: ResourceLeasePort,
    L: MigrationResourceLease,
    O: MutationObserver,
>(
    repository: &Path,
    plan: &MigrationPlan,
    mode: MigrationRecoveryMode,
    lease: &mut L,
    services: &MigrationServices<'_, E, A, R, O>,
) -> Result<MigrationRecovery, MigrationError> {
    lease.verify(repository)?;
    let mut boundary = Boundaries {
        observer: services.observer,
        ordinal: 0,
    };
    let header_path = lease.root().join("header.json");
    if !header_path.exists() {
        return recover_original_without_prepared_journal(
            repository,
            plan,
            lease,
            services.evaluator,
            &mut boundary,
        );
    }
    let initial: JournalHeader =
        crate::wire::parse_strict_json_bytes(&read_regular(&header_path, MAX_MIGRATION_BYTES)?)
            .map_err(|e| fail("INVALID_JOURNAL", e.to_string()))?;
    if initial.schema_version != 1
        || initial.plan_ref != plan.digest()
        || initial.transaction_ref != lease.transaction_ref()
        || initial.repository_identity != lease.repository_identity()
    {
        return Err(fail(
            "OWNERSHIP_CONFLICT",
            "journal header does not bind the reviewed transaction",
        ));
    }
    if matches!(fs::symlink_metadata(lease.root().join("operations.jsonl")), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        && matches!(fs::symlink_metadata(lease.root().join("prepared.json")), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return recover_original_without_prepared_journal(
            repository,
            plan,
            lease,
            services.evaluator,
            &mut boundary,
        );
    }
    let mut journal = Journal::load(lease.root(), &initial)?;
    let prepared_digest = journal.actions.iter().rev().find_map(|a| match a {
        JournalAction::ObjectsPrepared { digest } => Some(digest.clone()),
        _ => None,
    });
    let Some(prepared_digest) = prepared_digest else {
        return recover_original_without_prepared_journal(
            repository,
            plan,
            lease,
            services.evaluator,
            &mut boundary,
        );
    };
    let prepared_bytes = read_regular(&lease.root().join("prepared.json"), MAX_MIGRATION_BYTES)?;
    if content_digest(&prepared_bytes) != prepared_digest {
        return Err(fail(
            "INVALID_JOURNAL",
            "prepared ownership inventory differs from durable intent",
        ));
    }
    let header: JournalHeader = crate::wire::parse_strict_json_bytes(&prepared_bytes)
        .map_err(|e| fail("INVALID_JOURNAL", e.to_string()))?;
    validate_recovery_objects(plan, &initial, &header)?;
    let stored = MigrationPlan::from_json_str(
        std::str::from_utf8(&read_regular(
            &lease.root().join("plan.json"),
            MAX_MIGRATION_BYTES,
        )?)
        .map_err(|e| fail("INVALID_JOURNAL", e.to_string()))?,
    )?;
    if stored.digest() != plan.digest() {
        return Err(fail(
            "INVALID_JOURNAL",
            "stored plan differs from reviewed recovery input",
        ));
    }
    match mode {
        MigrationRecoveryMode::Rollback => rollback_known(
            repository,
            plan,
            &header.objects,
            lease,
            services.evaluator,
            &mut journal,
            &mut boundary,
        ),
        MigrationRecoveryMode::Resume => resume_known(
            repository,
            plan,
            &header.objects,
            lease,
            services,
            &mut journal,
            &mut boundary,
        ),
    }
}
fn validate_recovery_objects(
    plan: &MigrationPlan,
    initial: &JournalHeader,
    prepared: &JournalHeader,
) -> Result<(), MigrationError> {
    if prepared.schema_version != 1
        || prepared.plan_ref != initial.plan_ref
        || prepared.transaction_ref != initial.transaction_ref
        || prepared.repository_identity != initial.repository_identity
        || prepared.objects.len() > 8192
    {
        return Err(fail(
            "INVALID_JOURNAL",
            "prepared transaction header differs",
        ));
    }
    let mut slots = BTreeSet::new();
    for item in &prepared.objects {
        if item.slot.is_empty()
            || item.slot.len() > 64
            || !item
                .slot
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !slots.insert(item.slot.clone())
            || item.identity.is_empty()
            || item.identity.len() > 256
        {
            return Err(fail(
                "INVALID_JOURNAL",
                "invalid or duplicate ownership slot",
            ));
        }
        if item.directory {
            if !plan.operation_graph().iter().any(|s| matches!(&s.action, ExecutableAction::Install { path, .. } if path.starts_with(&(item.path.clone()+"/"))))
                && !receipt_record_parent(plan, &item.path) { return Err(fail("INVALID_JOURNAL", "unrelated directory ownership claim")); }
        } else if item.slot != "receipt" {
            let step = plan.operation_graph().iter().find(|s| match &s.action {
                ExecutableAction::Evacuate { slot, .. } | ExecutableAction::Stage { slot, .. } => {
                    *slot == item.slot
                }
                ExecutableAction::Install { .. } => false,
            });
            let Some(
                ExecutableAction::Evacuate { digest, .. } | ExecutableAction::Stage { digest, .. },
            ) = step.map(|s| &s.action)
            else {
                return Err(fail("INVALID_JOURNAL", "unknown prepared file slot"));
            };
            if item.digest.as_deref() != Some(digest) {
                return Err(fail("INVALID_JOURNAL", "prepared file digest differs"));
            }
        }
    }
    for original in &initial.objects {
        let retained = object(&prepared.objects, &original.slot)?;
        if canonical(original)? != canonical(retained)? {
            return Err(fail(
                "INVALID_JOURNAL",
                "original object ownership was rewritten",
            ));
        }
    }
    Ok(())
}
fn receipt_record_parent(_plan: &MigrationPlan, parent: &str) -> bool {
    let placeholder = format!("sha256:{}", "0".repeat(64));
    crate::control_layout::ControlLayout::standard()
        .migration_receipt_path(&placeholder)
        .is_some_and(|p| p.starts_with(&(parent.to_owned() + "/")))
}
fn reconstruct_base<E: MigrationEvaluator, L: MigrationResourceLease>(
    repository: &Path,
    plan: &MigrationPlan,
    objects: &[PreparedObject],
    lease: &L,
    evaluator: &E,
) -> Result<crate::observation::SourceView, MigrationError> {
    let actual = evaluator.observe(repository)?;
    for condition in plan.preconditions() {
        let path = checked_path(repository, &condition.path)?;
        let bytes = observed_file(&path)?;
        let digest = bytes.as_deref().map(content_digest);
        if digest.is_some() && digest == condition.preimage {
            continue;
        }
        if let Some(digest) = digest {
            if condition.postimage.as_deref() != Some(&digest) {
                return Err(fail("RECOVERY_CONFLICT", &condition.path));
            }
            let installed = plan
                .operation_graph()
                .iter()
                .find_map(|s| match &s.action {
                    ExecutableAction::Install { path, slot, digest } if *path == condition.path => {
                        Some((slot, digest))
                    }
                    _ => None,
                })
                .ok_or_else(|| fail("RECOVERY_CONFLICT", &condition.path))?;
            require_owned_file(
                lease,
                &path,
                &object(objects, installed.0)?.identity,
                installed.1,
            )?;
        } else if condition.preimage.is_some() {
            let original = original_for_path(plan, objects, &condition.path)?;
            let staged = lease.root().join("slots").join(&original.slot);
            require_owned_file(
                lease,
                &staged,
                &original.identity,
                original
                    .digest
                    .as_deref()
                    .ok_or_else(|| fail("INVALID_JOURNAL", "original digest missing"))?,
            )?;
        }
    }
    let mut files = actual.files().clone();
    for op in plan.operations() {
        if let Some((path, _)) = op.destination() {
            files.remove(path);
        }
    }
    for op in plan.operations() {
        if let Some((path, bytes)) = op.original() {
            files.insert(path.into(), bytes.to_vec());
        }
    }
    let base = crate::observation::SourceView::from_bytes(files)
        .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
    if base.digest() != plan.base_source_ref() {
        return Err(fail(
            "RECOVERY_CONFLICT",
            "independent source edits outside the reviewed operation set are preserved",
        ));
    }
    Ok(base)
}
fn original_for_path<'a>(
    plan: &MigrationPlan,
    objects: &'a [PreparedObject],
    path: &str,
) -> Result<&'a PreparedObject, MigrationError> {
    let slot = plan
        .operation_graph()
        .iter()
        .find_map(|s| match &s.action {
            ExecutableAction::Evacuate { path: p, slot, .. } if p == path => Some(slot),
            _ => None,
        })
        .ok_or_else(|| fail("INVALID_JOURNAL", "original staging slot missing"))?;
    object(objects, slot)
}
fn published_receipt(
    repository: &Path,
    objects: &[PreparedObject],
    lease: &impl MigrationResourceLease,
    journal: &Journal,
) -> Result<Option<MigrationReceipt>, MigrationError> {
    let prepared = object(objects, "receipt")?;
    let bytes = read_regular(&lease.root().join("slots/receipt"), MAX_MIGRATION_BYTES)?;
    require_owned_file(
        lease,
        &lease.root().join("slots/receipt"),
        &prepared.identity,
        prepared
            .digest
            .as_deref()
            .ok_or_else(|| fail("INVALID_JOURNAL", "receipt digest missing"))?,
    )?;
    let receipt = MigrationReceipt::from_json_str(
        std::str::from_utf8(&bytes).map_err(|e| fail("INVALID_JOURNAL", e.to_string()))?,
    )?;
    let recorded = journal.actions.iter().any(|a| matches!(a, JournalAction::ReceiptIntent { path, digest } | JournalAction::ReceiptComplete { path, digest } if path == &prepared.path && digest == &content_digest(&bytes)));
    if recorded
        && observed_file(&checked_relative(repository, &prepared.path)?)?.as_deref()
            == Some(bytes.as_slice())
    {
        return Ok(Some(receipt));
    }
    Ok(None)
}
fn rollback_known<L: MigrationResourceLease, E: MigrationEvaluator, O: MutationObserver>(
    repository: &Path,
    plan: &MigrationPlan,
    objects: &[PreparedObject],
    lease: &mut L,
    evaluator: &E,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
) -> Result<MigrationRecovery, MigrationError> {
    if published_receipt(repository, objects, lease, journal)?.is_some() {
        return Err(fail(
            "TRANSACTION_ALREADY_PUBLISHED",
            "completed migration cannot be undone as crash recovery; use a new reviewed inverse plan",
        ));
    }
    let base = reconstruct_base(repository, plan, objects, lease, evaluator)?;
    // Preflight every needed original before making any recovery mutation.
    for condition in plan.preconditions() {
        let path = checked_path(repository, &condition.path)?;
        if observed_file(&path)?.as_deref().map(content_digest) == condition.preimage {
            continue;
        }
        if condition.preimage.is_some() {
            let original = original_for_path(plan, objects, &condition.path)?;
            require_owned_file(
                lease,
                &lease.root().join("slots").join(&original.slot),
                &original.identity,
                original
                    .digest
                    .as_deref()
                    .ok_or_else(|| fail("INVALID_JOURNAL", "original digest missing"))?,
            )?;
        }
    }
    boundary.append(
        journal,
        JournalAction::RecoveryIntent {
            mode: "ROLLBACK".into(),
        },
        true,
    )?;
    remove_owned_postimages(repository, plan, objects, lease, journal, boundary)?;
    restore_preimages(repository, plan, objects, lease, journal, boundary)?;
    remove_owned_parents(repository, objects, lease, journal, boundary)?;
    let actual = evaluator.observe(repository)?;
    if actual != base {
        return Err(fail(
            "ROLLBACK_NOT_ESTABLISHED",
            "actual bytes differ from reviewed original state",
        ));
    }
    boundary.append(
        journal,
        JournalAction::RecoveryComplete {
            outcome: "ROLLED_BACK_BYTES_VERIFIED".into(),
            source_ref: actual.digest().into(),
        },
        false,
    )?;
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::Before)?;
    if evaluator.observe(repository)? != base {
        return Err(fail(
            "RECOVERY_CONFLICT",
            "source drift during rollback completion",
        ));
    }
    journal.verify_integrity()?;
    lease.finish("ROLLED_BACK", actual.digest())?;
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::After)?;
    Ok(MigrationRecovery {
        outcome: "ROLLED_BACK_BYTES_VERIFIED".into(),
        actual_source_ref: actual.digest().into(),
        receipt: None,
        transaction_ref: lease.transaction_ref().into(),
    })
}
fn remove_owned_parents<L: MigrationResourceLease, O: MutationObserver>(
    repository: &Path,
    objects: &[PreparedObject],
    lease: &L,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
) -> Result<(), MigrationError> {
    let mut parents = objects.iter().filter(|o| o.directory).collect::<Vec<_>>();
    parents.sort_by_key(|o| std::cmp::Reverse((o.path.matches('/').count(), o.path.clone())));
    for parent in parents {
        let path = checked_relative(repository, &parent.path)?;
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_error(e)),
            Ok(m) if linked(&m) || !m.is_dir() => {
                return Err(fail("RECOVERY_CONFLICT", &parent.path));
            }
            Ok(_) => {}
        }
        if lease.object_identity(&path)? != parent.identity
            || fs::read_dir(&path).map_err(io_error)?.next().is_some()
        {
            return Err(fail(
                "RECOVERY_CONFLICT",
                format!("independent directory content retained: {}", parent.path),
            ));
        }
        boundary.append(
            journal,
            JournalAction::RecoveryStepIntent {
                path: parent.path.clone(),
                action: "REMOVE_OWNED_EMPTY_PARENT".into(),
            },
            true,
        )?;
        boundary.at(MutationBoundary::ParentInstall, BoundaryPhase::Before)?;
        if lease.object_identity(&checked_relative(repository, &parent.path)?)? != parent.identity {
            return Err(fail("RECOVERY_CONFLICT", &parent.path));
        }
        fs::remove_dir(&path).map_err(io_error)?;
        boundary.at(MutationBoundary::ParentInstall, BoundaryPhase::After)?;
        boundary.append(
            journal,
            JournalAction::RecoveryStepComplete {
                path: parent.path.clone(),
            },
            false,
        )?;
    }
    Ok(())
}
fn resume_known<
    E: MigrationEvaluator,
    A: MigrationAuthority,
    R: ResourceLeasePort,
    L: MigrationResourceLease,
    O: MutationObserver,
>(
    repository: &Path,
    plan: &MigrationPlan,
    objects: &[PreparedObject],
    lease: &mut L,
    services: &MigrationServices<'_, E, A, R, O>,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
) -> Result<MigrationRecovery, MigrationError> {
    if journal
        .actions
        .iter()
        .any(|a| matches!(a, JournalAction::RecoveryIntent { mode } if mode == "ROLLBACK"))
    {
        return Err(fail(
            "RECOVERY_DIRECTION_CONFLICT",
            "rollback already began; continue its explicit direction",
        ));
    }
    let before = reconstruct_base(repository, plan, objects, lease, services.evaluator)?;
    let preview = preview_migration(
        services.evaluator,
        services.authority,
        &before,
        plan.operations().to_vec(),
        plan.options().clone(),
    )?;
    if preview.plan.digest() != plan.digest() || !plan.validations_satisfied() {
        return Err(fail(
            "REVIEWED_TARGET_CHANGED",
            "current evaluator/authority no longer matches reviewed recovery target",
        ));
    }
    let permission = services.authority.authorize(
        &preview.base,
        &preview.target,
        &before,
        &preview.changes,
        &plan.options().comparison_context,
    )?;
    if permission
        .record()
        .requirement_contract_ref()
        .map_err(super::model::convert)?
        != plan.authorization_contract_ref()
    {
        return Err(fail(
            "AUTHORIZATION_REQUIRED",
            "fresh recovery permission differs from original requirements",
        ));
    }
    boundary.append(
        journal,
        JournalAction::RecoveryIntent {
            mode: "RESUME".into(),
        },
        true,
    )?;
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::Before)?;
    lease.applying(plan.digest(), journal.path())?;
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::After)?;
    install_parents(repository, objects, lease, journal, boundary)?;
    run_steps(repository, plan, objects, lease, journal, boundary)?;
    validate_actual(repository, plan, services.evaluator, journal, boundary)?;
    let bytes = read_regular(&lease.root().join("slots/receipt"), MAX_MIGRATION_BYTES)?;
    let receipt = MigrationReceipt::from_json_str(
        std::str::from_utf8(&bytes).map_err(|e| fail("INVALID_JOURNAL", e.to_string()))?,
    )?;
    if receipt.plan_ref != plan.digest()
        || receipt.target_state_ref != plan.target_state_ref()
        || receipt.actual_source_ref != plan.target_source_ref()
        || receipt
            .authorization
            .requirement_contract_ref()
            .map_err(super::model::convert)?
            != plan.authorization_contract_ref()
    {
        return Err(fail(
            "INVALID_JOURNAL",
            "prepared receipt does not bind reviewed recovery scope",
        ));
    }
    publish_receipt(
        repository,
        &receipt,
        objects,
        lease,
        journal,
        boundary,
        (services.evaluator, plan),
    )?;
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::Before)?;
    if services.evaluator.observe(repository)?.digest() != plan.target_source_ref() {
        return Err(fail(
            "SOURCE_DRIFT",
            "actual source changed before recovery publication completed",
        ));
    }
    journal.verify_integrity()?;
    verify_expected_paths(repository, plan)?;
    lease.finish("COMMITTED", receipt.digest())?;
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::After)?;
    Ok(MigrationRecovery {
        outcome: "COMMITTED_ACTUAL_TARGET_VERIFIED".into(),
        actual_source_ref: plan.target_source_ref().into(),
        receipt: Some(receipt),
        transaction_ref: lease.transaction_ref().into(),
    })
}

fn prepare_outputs<L: MigrationResourceLease, O: MutationObserver>(
    plan: &MigrationPlan,
    receipt: &MigrationReceipt,
    lease: &L,
    objects: &mut Vec<PreparedObject>,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
) -> Result<(), MigrationError> {
    let root = lease.root();
    for directory in ["slots", "parents"] {
        boundary.append(
            journal,
            JournalAction::PrepareIntent {
                slot: directory.into(),
                digest: None,
                directory: true,
            },
            true,
        )?;
        boundary.at(MutationBoundary::Preparation, BoundaryPhase::Before)?;
        fs::create_dir(root.join(directory)).map_err(io_error)?;
        boundary.at(MutationBoundary::Preparation, BoundaryPhase::After)?;
        boundary.append(
            journal,
            JournalAction::PrepareComplete {
                slot: directory.into(),
                identity: lease.object_identity(&root.join(directory))?,
            },
            false,
        )?;
    }
    for step in plan.operation_graph() {
        if let ExecutableAction::Stage { slot, digest } = &step.action {
            let bytes = postimage_for_slot(plan, slot)?;
            objects.push(prepare_file(
                root, slot, &bytes, digest, lease, journal, boundary,
            )?);
        }
    }
    let receipt_bytes = receipt.to_canonical_bytes()?;
    let mut receipt_object = prepare_file(
        root,
        "receipt",
        &receipt_bytes,
        &content_digest(&receipt_bytes),
        lease,
        journal,
        boundary,
    )?;
    receipt_object.path = receipt_path(receipt)?;
    boundary.append(
        journal,
        JournalAction::PrepareIntent {
            slot: "hardlink-probe".into(),
            digest: Some(content_digest(&receipt_bytes)),
            directory: false,
        },
        true,
    )?;
    boundary.at(MutationBoundary::Preparation, BoundaryPhase::Before)?;
    let probe = root.join("slots/hardlink-probe");
    fs::hard_link(root.join("slots/receipt"), &probe).map_err(io_error)?;
    require_owned_file(
        lease,
        &probe,
        &receipt_object.identity,
        &content_digest(&receipt_bytes),
    )?;
    boundary.at(MutationBoundary::Preparation, BoundaryPhase::After)?;
    boundary.append(
        journal,
        JournalAction::PrepareComplete {
            slot: "hardlink-probe".into(),
            identity: receipt_object.identity.clone(),
        },
        false,
    )?;
    objects.push(receipt_object);
    Ok(())
}

fn prepare_parents<L: MigrationResourceLease, O: MutationObserver>(
    repository: &Path,
    plan: &MigrationPlan,
    receipt: &MigrationReceipt,
    lease: &L,
    objects: &mut Vec<PreparedObject>,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
) -> Result<(), MigrationError> {
    let root = lease.root();
    let mut parents = BTreeSet::new();
    let destinations = plan
        .operation_graph()
        .iter()
        .filter_map(|s| match &s.action {
            ExecutableAction::Install { path, .. } => Some(path.clone()),
            _ => None,
        })
        .chain(std::iter::once(receipt_path(receipt)?));
    for destination in destinations {
        for (offset, _) in destination.match_indices('/') {
            let relative = &destination[..offset];
            let path = checked_relative(repository, relative)?;
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() && !linked(&metadata) => {}
                Ok(_) => return Err(fail("UNSAFE_PATH_KIND", relative)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    parents.insert(relative.to_owned());
                    if parents.len() > 4096 {
                        return Err(fail("RESOURCE_LIMIT", "too many new parent directories"));
                    }
                }
                Err(error) => return Err(io_error(error)),
            }
        }
    }
    if parents.len() > 4096 {
        return Err(fail("RESOURCE_LIMIT", "too many new parent directories"));
    }
    for (i, path) in parents.iter().enumerate() {
        let slot = format!("parent-{i:04}");
        boundary.append(
            journal,
            JournalAction::PrepareIntent {
                slot: slot.clone(),
                digest: None,
                directory: true,
            },
            true,
        )?;
        boundary.at(MutationBoundary::Preparation, BoundaryPhase::Before)?;
        fs::create_dir(root.join("parents").join(&slot)).map_err(io_error)?;
        boundary.at(MutationBoundary::Preparation, BoundaryPhase::After)?;
        let identity = lease.object_identity(&root.join("parents").join(&slot))?;
        boundary.append(
            journal,
            JournalAction::PrepareComplete {
                slot: slot.clone(),
                identity: identity.clone(),
            },
            false,
        )?;
        objects.push(PreparedObject {
            slot,
            path: path.clone(),
            identity,
            digest: None,
            directory: true,
        });
    }
    Ok(())
}

fn remove_owned_postimages<L: MigrationResourceLease, O: MutationObserver>(
    repository: &Path,
    plan: &MigrationPlan,
    objects: &[PreparedObject],
    lease: &L,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
) -> Result<(), MigrationError> {
    for condition in plan.preconditions() {
        let path = checked_path(repository, &condition.path)?;
        if observed_file(&path)?.as_deref().map(content_digest) == condition.preimage {
            continue;
        }
        if let Some(bytes) = observed_file(&path)? {
            let (slot, digest) = plan
                .operation_graph()
                .iter()
                .find_map(|s| match &s.action {
                    ExecutableAction::Install {
                        path: p,
                        slot,
                        digest,
                    } if p == &condition.path => Some((slot, digest)),
                    _ => None,
                })
                .ok_or_else(|| fail("RECOVERY_CONFLICT", &condition.path))?;
            let owner = object(objects, slot)?;
            if content_digest(&bytes) != *digest {
                return Err(fail("RECOVERY_CONFLICT", &condition.path));
            }
            boundary.append(
                journal,
                JournalAction::RecoveryStepIntent {
                    path: condition.path.clone(),
                    action: "REMOVE_OWNED_POSTIMAGE".into(),
                },
                true,
            )?;
            boundary.at(MutationBoundary::Evacuate, BoundaryPhase::Before)?;
            lease.verify(repository)?;
            require_owned_file(
                lease,
                &checked_path(repository, &condition.path)?,
                &owner.identity,
                digest,
            )?;
            fs::remove_file(&path).map_err(io_error)?;
            sync_directory(
                path.parent()
                    .ok_or_else(|| fail("UNSAFE_PATH", "parent unavailable"))?,
            )?;
            boundary.at(MutationBoundary::Evacuate, BoundaryPhase::After)?;
            boundary.append(
                journal,
                JournalAction::RecoveryStepComplete {
                    path: condition.path.clone(),
                },
                false,
            )?;
        }
    }
    Ok(())
}

fn restore_preimages<L: MigrationResourceLease, O: MutationObserver>(
    repository: &Path,
    plan: &MigrationPlan,
    objects: &[PreparedObject],
    lease: &L,
    journal: &mut Journal,
    boundary: &mut Boundaries<'_, O>,
) -> Result<(), MigrationError> {
    for condition in plan.preconditions() {
        let Some(digest) = &condition.preimage else {
            continue;
        };
        let path = checked_path(repository, &condition.path)?;
        if observed_file(&path)?
            .as_deref()
            .map(content_digest)
            .as_deref()
            == Some(digest)
        {
            continue;
        }
        let original = original_for_path(plan, objects, &condition.path)?;
        let staged = lease.root().join("slots").join(&original.slot);
        boundary.append(
            journal,
            JournalAction::RecoveryStepIntent {
                path: condition.path.clone(),
                action: "RESTORE_KNOWN_PREIMAGE".into(),
            },
            true,
        )?;
        boundary.at(MutationBoundary::Install, BoundaryPhase::Before)?;
        lease.verify(repository)?;
        require_absent(&checked_path(repository, &condition.path)?)?;
        require_owned_file(lease, &staged, &original.identity, digest)?;
        fs::hard_link(&staged, &path).map_err(io_error)?;
        require_owned_file(lease, &path, &original.identity, digest)?;
        sync_directory(
            path.parent()
                .ok_or_else(|| fail("UNSAFE_PATH", "parent unavailable"))?,
        )?;
        boundary.at(MutationBoundary::Install, BoundaryPhase::After)?;
        boundary.append(
            journal,
            JournalAction::RecoveryStepComplete {
                path: condition.path.clone(),
            },
            false,
        )?;
    }
    Ok(())
}

fn recover_original_without_prepared_journal<
    L: MigrationResourceLease,
    E: MigrationEvaluator,
    O: MutationObserver,
>(
    repository: &Path,
    plan: &MigrationPlan,
    lease: &mut L,
    evaluator: &E,
    boundary: &mut Boundaries<'_, O>,
) -> Result<MigrationRecovery, MigrationError> {
    // No missing journal becomes application proof. Explicit recovery may establish
    // the original exact bytes without making a source mutation or a successful receipt.
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::Before)?;
    lease.verify(repository)?;
    verify_base_paths(repository, plan)?;
    let original = evaluator.observe(repository)?;
    if original.digest() != plan.base_source_ref() {
        return Err(fail(
            "RECOVERY_CONFLICT",
            "missing preparation journal and independent source changes are preserved",
        ));
    }
    lease.verify(repository)?;
    if evaluator.observe(repository)? != original {
        return Err(fail(
            "RECOVERY_CONFLICT",
            "source changed during original-byte verification",
        ));
    }
    lease.finish("ROLLED_BACK", original.digest())?;
    boundary.at(MutationBoundary::ActiveState, BoundaryPhase::After)?;
    Ok(MigrationRecovery {
        outcome: "ORIGINAL_BYTES_VERIFIED_INCOMPLETE_JOURNAL".into(),
        actual_source_ref: original.digest().into(),
        receipt: None,
        transaction_ref: lease.transaction_ref().into(),
    })
}
