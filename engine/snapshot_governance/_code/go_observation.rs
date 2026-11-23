//! Explicit actual-state Go observation supervision owned by Snapshot Governance.

use std::path::Path;

use crate::audit::{bind_go_observation_source, observe_candidate_source};
use crate::heavy_admission::{DirectoryIdentity, assert_no_incomplete_migration};
use crate::observation::SourceView;
use crate::program_semantics::go_observation::{ExactClosedPackage, admit_go};

pub use crate::program_semantics::go_observation::{
    GoCollectorPin, GoNativeObservation, GoObservationError,
};

/// Independently selected observation context for a closed Go source directory.
#[derive(Clone, Copy)]
pub struct GoPackageSelection<'a> {
    /// Exact repository-relative directory, with an empty value for the root.
    pub directory: &'a str,
    /// Explicit Go package identity within the selected closed context.
    pub package_path: &'a str,
    /// Go language version, independently selected for this observation.
    pub go_version: &'a str,
    /// Exact selected target operating system.
    pub target_os: &'a str,
    /// Exact selected target architecture.
    pub target_arch: &'a str,
}

/// Observes one exact Go source directory through an explicit trusted host.
///
/// The host must verify and supervise the selected executable outside the
/// repository. Return stdout only after successful bounded process exit under
/// the exact supplied pin. This boundary does no implicit execution and grants
/// no reuse, finding, conformance, or certification authority.
///
/// # Errors
/// Refuses unsafe, unsupported, oversized, or changed inputs and any process
/// response that does not match the admitted source and wire identities.
pub fn observe_go_native(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<GoNativeObservation, GoObservationError> {
    let directory = DirectoryIdentity::capture(project_root).map_err(source_failure)?;
    let source = capture(project_root)?;
    let (source_fingerprint, authority_digest) =
        bind_go_observation_source(&source).map_err(source_failure)?;
    if !directory.matches(project_root).map_err(source_failure)? {
        return Err(GoObservationError::SourceChanged);
    }
    let admitted = admit_go(
        ExactClosedPackage {
            source: &source,
            source_fingerprint: &source_fingerprint,
            authority_digest: &authority_digest,
            actual: true,
            directory: selection.directory,
            package_path: selection.package_path,
            go_version: selection.go_version,
            target_os: selection.target_os,
            target_arch: selection.target_arch,
        },
        collector,
    )?;
    let output = launch(admitted.request_bytes())?;
    let observation = admitted.verify(collector, &output)?;
    if capture(project_root)? != source
        || !directory.matches(project_root).map_err(source_failure)?
    {
        return Err(GoObservationError::SourceChanged);
    }
    Ok(observation)
}

fn capture(project_root: &Path) -> Result<SourceView, GoObservationError> {
    assert_no_incomplete_migration(project_root).map_err(source_failure)?;
    let source = observe_candidate_source(project_root).map_err(source_failure)?;
    assert_no_incomplete_migration(project_root).map_err(source_failure)?;
    Ok(source)
}

fn source_failure(error: impl std::fmt::Display) -> GoObservationError {
    GoObservationError::SourceUnavailable(error.to_string())
}
