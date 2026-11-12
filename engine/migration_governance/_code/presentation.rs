//! Deterministic explanations and explicitly invoked registered proposal export.
use super::journal::{io_error, linked, write_new};
use super::paths::{checked_relative, observed_file, sync_directory};
use super::{MigrationError, MigrationPlan, MigrationReceipt, fail};
use std::fs;
use std::path::Path;
impl MigrationPlan {
    /// Formats only already-evaluated immutable plan facts; never starts analysis.
    #[must_use]
    pub fn to_human(&self) -> String {
        let mut text = format!(
            "Migration plan: {}\nBase source: {}\nEvaluated target source: {}\nBase state: {}\nEvaluated target state: {}\nTransition: {}\nOperations: {}\nAuthorization basis: {:?}\nRequired external grants: {}\nTarget validations satisfied: {}\nApplication: NOT_PERFORMED\n",
            self.digest(),
            self.base_source_ref(),
            self.target_source_ref(),
            self.base_state_ref(),
            self.target_state_ref(),
            self.authorization().transition_ref,
            self.operations().len(),
            self.authorization().kind,
            self.authorization().requirements().len(),
            self.validations_satisfied()
        );
        for operation in self.operations() {
            let description = match operation {
                super::MigrationOperation::CreateFile { path, postimage } => {
                    format!("CREATE_FILE {path} ({} bytes)", postimage.len())
                }
                super::MigrationOperation::ReplaceFile {
                    path,
                    preimage,
                    postimage,
                } => format!(
                    "REPLACE_FILE {path} ({} -> {} bytes)",
                    preimage.len(),
                    postimage.len()
                ),
                super::MigrationOperation::MovePath {
                    source,
                    destination,
                    preimage,
                } => format!(
                    "MOVE_PATH {source} -> {destination} ({} bytes)",
                    preimage.len()
                ),
                super::MigrationOperation::DeleteOwnedFile {
                    path,
                    owner_ref,
                    preimage,
                } => format!(
                    "DELETE_OWNED_FILE {path} ({} bytes, owner {owner_ref})",
                    preimage.len()
                ),
            };
            text.push_str("  ");
            text.push_str(&description);
            text.push('\n');
        }
        text
    }
}
impl MigrationReceipt {
    /// Formats historical actual-application facts without implying current certification.
    #[must_use]
    pub fn to_human(&self) -> String {
        format!(
            "Migration receipt: {}\nOutcome: {:?}\nPlan: {}\nActual source: {}\nActual evaluated state: {}\nProject execution: {}\nHistorical application facts; no present-state freshness or transferable authorization inferred.\n",
            self.digest(),
            self.outcome,
            self.plan_ref,
            self.actual_source_ref,
            self.actual_state_ref,
            self.project_execution
        )
    }
}
/// Exports only on explicit invocation to the registered content-addressed proposal family.
/// This derived proposal never becomes active authority or a validated external grant.
/// # Errors
/// Refuses unsafe paths, conflicting records, incompatible plans and failed synchronized writes.
pub fn export_reviewed_migration_plan(
    repository: &Path,
    plan: &MigrationPlan,
) -> Result<String, MigrationError> {
    let bytes = plan.to_canonical_bytes()?;
    let relative = crate::control_layout::ControlLayout::standard()
        .migration_plan_path(plan.digest())
        .ok_or_else(|| fail("UNAVAILABLE_ROLE", "reviewed plan role unavailable"))?;
    export_proposal_record(repository, relative, &bytes)
}

/// Common safe immutable derived-record writer; never accepts active authority paths.
pub(crate) fn export_proposal_record(
    repository: &Path,
    relative: String,
    bytes: &[u8],
) -> Result<String, MigrationError> {
    let entry = crate::control_layout::ControlLayout::standard()
        .resolve(&relative)
        .ok_or_else(|| fail("UNAVAILABLE_ROLE", "proposal role unavailable"))?;
    if !matches!(
        entry.role(),
        crate::control_layout::ControlRole::ReviewedMigrationPlan
            | crate::control_layout::ControlRole::HypotheticalProposal
            | crate::control_layout::ControlRole::OnboardingProposal
    ) {
        return Err(fail(
            "UNSAFE_PATH",
            "immutable proposal export requires a registered proposal role",
        ));
    }
    for (offset, _) in relative.match_indices('/') {
        let path = checked_relative(repository, &relative[..offset])?;
        match fs::create_dir(&path) {
            Ok(()) => sync_directory(
                path.parent()
                    .ok_or_else(|| fail("UNSAFE_PATH", "missing proposal parent"))?,
            )?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let m = fs::symlink_metadata(&path).map_err(io_error)?;
                if linked(&m) || !m.is_dir() {
                    return Err(fail("UNSAFE_PATH_KIND", &relative));
                }
            }
            Err(e) => return Err(io_error(e)),
        }
    }
    let path = checked_relative(repository, &relative)?;
    if let Some(existing) = observed_file(&path)? {
        if existing == bytes {
            return Ok(relative);
        }
        return Err(fail("IMMUTABLE_RECORD_CONFLICT", relative));
    }
    write_new(&path, bytes)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| fail("UNSAFE_PATH", "proposal parent unavailable"))?,
    )?;
    Ok(relative)
}
