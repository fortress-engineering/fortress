//! Read-only composition of the existing canonical owners for edition upgrades.

use std::path::Path;

use crate::migration_adapter::CanonicalMigrationEvaluator;
use crate::migration_governance::upgrade::{
    EditionPin, EditionUpgrade, UpgradeAdapter, assess_upgrade, configuration_upgrade_operation,
};
use crate::migration_governance::{
    MigrationAuthority, MigrationError, MigrationEvaluator, MigrationOperation, MigrationOptions,
    preview_migration,
};
use crate::observation::SourceView;
use serde::Serialize;

/// The explicit operation source for a preview. Neither selection supplies authority.
pub enum UpgradeOperations<'a> {
    /// Materialize the current native configuration shape from its registered historical reader.
    NativeConfiguration,
    /// Evaluate exact reviewed operations without transforming them.
    Explicit(Vec<MigrationOperation>),
    /// Reuse a process-local plan from the existing exact identity owner.
    Identity(&'a crate::identity_migration::IdentityMigrationPlan),
}

/// Exact source and original governing selection, without approval.
#[derive(Serialize)]
pub struct UpgradeBase {
    /// Canonical Standard loaded for this endpoint.
    pub edition: EditionPin,
    /// Exact physically observed source identity.
    pub source_ref: String,
    /// Canonical observation and evaluation identity.
    pub state_ref: String,
    /// Governing identity needed by the original-policy selection.
    pub authority_ref: String,
}

/// Observes the repository and reports its exact canonically loaded Standard edition.
///
/// # Errors
/// Refuses unsafe observation, incomplete migration, and missing governing authority.
pub fn inspect_upgrade_base(root: &Path) -> Result<UpgradeBase, MigrationError> {
    let evaluator = CanonicalMigrationEvaluator;
    let source = observe(root)?;
    let input = evaluator.evaluate(&source)?;
    let bundle = crate::audit::migration_standard(&input.evaluated_source).map_err(convert)?;
    if observe(root)? != source {
        return Err(error(
            "STALE_BASE",
            "repository changed during edition discovery",
        ));
    }
    let authority_ref = input
        .state
        .governing_identity()
        .map_err(convert)?
        .ok_or_else(|| {
            error(
                "MISSING_ORIGINAL_AUTHORITY",
                "upgrade requires declared original authority",
            )
        })?;
    Ok(UpgradeBase {
        edition: EditionPin::for_standard(&bundle),
        source_ref: source.digest().into(),
        state_ref: input.state.digest().map_err(convert)?,
        authority_ref,
    })
}

/// Derives an exact proposed edition, reusing the migration planner and four-axis comparison.
///
/// The returned plan may be supplied to the existing trusted mediator after independent
/// review. Neither this function nor the returned public record grants authorization.
///
/// # Errors
/// Refuses stale source, mismatched edition pins, unsupported transformations and invalid authority.
pub fn preview_repository_upgrade(
    root: &Path,
    adapter: &UpgradeAdapter,
    operations: UpgradeOperations<'_>,
    authority: &impl MigrationAuthority,
) -> Result<EditionUpgrade, MigrationError> {
    let evaluator = CanonicalMigrationEvaluator;
    let source = observe(root)?;
    let preview_edits = |operations| {
        let mut options = MigrationOptions::default();
        options
            .validation_requirements
            .insert(crate::migration_governance::MigrationValidation::GovernanceDeclared);
        preview_migration(&evaluator, authority, &source, operations, options)
    };
    let (preview, identity) = match operations {
        UpgradeOperations::NativeConfiguration => (
            preview_edits(vec![configuration_upgrade_operation(&source)?])?,
            None,
        ),
        UpgradeOperations::Explicit(operations) => (preview_edits(operations)?, None),
        UpgradeOperations::Identity(plan) => (
            crate::identity_migration::preview_repository_identity_migration(
                root, plan, &evaluator, authority,
            )
            .map_err(convert)?,
            Some(plan),
        ),
    };
    if preview.plan.base_source_ref() != source.digest() {
        return Err(error(
            "STALE_BASE",
            "preview did not use the exact observed base",
        ));
    }
    let original =
        crate::audit::migration_standard(&preview.base.evaluated_source).map_err(convert)?;
    let target =
        crate::audit::migration_standard(&preview.target.evaluated_source).map_err(convert)?;
    let target_state_ref = preview.plan.target_state_ref().to_owned();
    let mut assessment = assess_upgrade(adapter, &original, &target, preview)?;
    if let Some(identity) = identity {
        assessment.bind_identity(identity)?;
    }
    if adapter.preview_admission {
        let admission = crate::admission_load::evaluate_governance_admission(
            &source,
            assessment.operations.clone(),
            &[],
        )?;
        if admission.pre_admission_state().digest().map_err(convert)? != target_state_ref {
            return Err(error(
                "UPGRADE_ADMISSION_BINDING_MISMATCH",
                "admission did not evaluate the same proposed state",
            ));
        }
        assessment.bind_admission(admission.assessment().clone())?;
    }
    if observe(root)? != source {
        return Err(error(
            "STALE_BASE",
            "repository changed during the edition preview",
        ));
    }
    Ok(assessment)
}

fn observe(root: &Path) -> Result<SourceView, MigrationError> {
    crate::heavy_admission::assert_no_incomplete_migration(root).map_err(convert)?;
    CanonicalMigrationEvaluator.observe(root)
}

fn error(code: &str, message: impl Into<String>) -> MigrationError {
    MigrationError {
        code: code.into(),
        message: message.into(),
        transaction_ref: None,
    }
}

fn convert(error: impl std::fmt::Display) -> MigrationError {
    self::error("INVALID_UPGRADE_INPUT", error.to_string())
}
