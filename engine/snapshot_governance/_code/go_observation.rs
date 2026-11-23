//! Explicit actual-state Go observation supervision owned by Snapshot Governance.

use std::path::Path;

use crate::native_observation::{NativeSource, NativeSourceError};
use crate::program_semantics::go_observation::{ExactClosedPackage, admit_go, admit_go_build};

pub use crate::program_semantics::go_observation::{
    GoBuildContext, GoBuildTestMode, GoCollectorPin, GoNativeBuildObservation, GoNativeObservation,
    GoObservationError,
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
    observe_exact(project_root, selection, |source| {
        let admitted = admit_go(source, collector)?;
        let output = launch(admitted.request_bytes())?;
        admitted.verify(collector, &output)
    })
}

/// Observes the build-selected content of one closed Go source directory.
///
/// The caller must independently select and verify the v2 classifier, its
/// target build context and process environment. The receipt is standalone
/// native observation, without PSM, runtime or certification authority.
///
/// # Errors
/// Refuses nonexact inputs and any v2 classifier response that fails admission.
pub fn observe_go_native_build(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    build_context: GoBuildContext,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<GoNativeBuildObservation, GoObservationError> {
    observe_exact(project_root, selection, |source| {
        let admitted = admit_go_build(source, collector, build_context)?;
        let output = launch(admitted.request_bytes())?;
        admitted.verify(collector, &output)
    })
}

fn observe_exact<T>(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    operation: impl FnOnce(ExactClosedPackage<'_>) -> Result<T, GoObservationError>,
) -> Result<T, GoObservationError> {
    let source = NativeSource::capture(project_root, "Go").map_err(source_failure)?;
    let observation = operation(ExactClosedPackage {
        source: &source.view,
        source_fingerprint: &source.binding.source_fingerprint,
        authority_digest: &source.binding.authority_digest,
        actual: true,
        directory: selection.directory,
        package_path: selection.package_path,
        go_version: selection.go_version,
        target_os: selection.target_os,
        target_arch: selection.target_arch,
    })?;
    source.revalidate().map_err(source_failure)?;
    Ok(observation)
}

fn source_failure(error: NativeSourceError) -> GoObservationError {
    match error {
        NativeSourceError::Unavailable(detail) => GoObservationError::SourceUnavailable(detail),
        NativeSourceError::Changed => GoObservationError::SourceChanged,
    }
}
