//! Explicit actual-state Go observation supervision owned by Snapshot Governance.

use std::path::Path;

use serde::Serialize;

use crate::implementation_observation::{NativeDependencyContext, SourceOwnershipDiagnostic};
use crate::information_flow::NativeScalarFlowObservation;
use crate::native_observation::{NativeSource, NativeSourceError};
use crate::program_semantics::go_observation::{
    ExactClosedPackage, admit_go, admit_go_build, admit_go_module, admit_go_tests,
};

#[path = "go_body_domains.rs"]
mod body_domains;

#[path = "go_fs_observation.rs"]
mod filesystem;
pub use body_domains::ActualGoNativeBodyObservation;
pub use filesystem::{
    ActualGoFilesystemEffectObservation, GoFilesystemHost, observe_go_filesystem_effects,
};

#[path = "go_callable.rs"]
mod callable;
pub use callable::{
    GoCallableHost, GoCallableSelection, observe_go_authored_native_return,
    observe_go_linked_callable,
};

pub use crate::program_semantics::go_observation::GoFilesystemLibraryPin;
pub use crate::program_semantics::go_observation::{
    GoBuildContext, GoBuildTestMode, GoCollectorPin, GoModuleSelection, GoNativeBuildObservation,
    GoNativeModuleObservation, GoNativeObservation, GoNativeTestObservation, GoObservationError,
    GoTypeComparison, GoTypeSelector,
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

/// Observes exact selected Go test declarations through a separately pinned worker.
///
/// Test declarations and file-selection evidence are compile-free observations.
/// The original physical source and governing authority are revalidated before
/// publication. No execution, coverage or verification relationship follows.
///
/// # Errors
/// Refuses unsafe, stale, unsupported or oversized inputs and mismatched worker output.
pub fn observe_go_native_tests(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    build_context: GoBuildContext,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<GoNativeTestObservation, GoObservationError> {
    observe_exact(project_root, selection, |source| {
        let admitted = admit_go_tests(source, collector, build_context)?;
        let output = launch(admitted.request_bytes())?;
        admitted.verify_tests(collector, &output)
    })
}

/// Observes an exact module and reachable ordinary local libraries through a pinned worker.
///
/// # Errors
/// Refuses unsupported or changed actual source, unclosed module inputs, and
/// malformed, stale, or incompatible worker output.
pub fn observe_go_native_module(
    project_root: &Path,
    selected: GoModuleSelection<'_>,
    build_context: GoBuildContext,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<GoNativeModuleObservation, GoObservationError> {
    observe_exact(project_root, module_entry(selected), |source| {
        let admitted = admit_go_module(source, selected, collector, build_context)?;
        let output = launch(admitted.request_bytes())?;
        admitted.verify(collector, &output)
    })
}

/// Projects the exact Go module's verified imports through authored Module ownership.
///
/// The same pinned Go v3 worker observes the same physical inputs. Only its
/// admitted selected package files can support positive source observations.
/// Runtime behavior and assessment remain outside this report.
///
/// # Errors
/// Refuses invalid source or host context, source drift, invalid output, or a
/// result over the bounded report limit.
pub fn observe_go_module_dependencies(
    project_root: &Path,
    selected: GoModuleSelection<'_>,
    build_context: GoBuildContext,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<Vec<u8>, GoObservationError> {
    let source =
        NativeSource::capture_for_dependencies(project_root, "Go").map_err(source_failure)?;
    let admitted = admit_go_module(
        closed_package(&source, module_entry(selected)),
        selected,
        collector,
        build_context,
    )?;
    let output = launch(admitted.request_bytes())?;
    let receipt = admitted.verify(collector, &output)?;
    let (input, diagnostics) = source
        .dependency_input(admitted.dependency_paths())
        .map_err(source_failure)?;
    let context = NativeDependencyContext {
        snapshot_fingerprint: &source.binding.source_fingerprint,
        source_view_sha256: source.view.digest(),
        authority_sha256: &source.binding.authority_digest,
        context_sha256: admitted.dependency_context(),
    };
    let dependencies = admitted.project_dependencies(&input, context, &receipt)?;
    let report = GoDependencyInspection {
        schema: "urn:fortress:derived:v1:go-source-dependency-inspection",
        schema_version: 1,
        source_manifest_sha256: &source.binding.source_manifest_digest,
        scope: "SCOPED_SOURCE_OBSERVATION",
        native_receipt: &receipt,
        ownership_diagnostics: diagnostics,
        dependencies,
    };

    let report = serde_json::to_value(report).map_err(|_| GoObservationError::WireEncoding)?;
    let bytes =
        crate::portable::canonical(&report).map_err(|_| GoObservationError::WireEncoding)?;
    if bytes.len() > 2 << 20 {
        return Err(GoObservationError::ResourceLimit);
    }
    source.revalidate().map_err(source_failure)?;
    Ok(bytes)
}

#[derive(Serialize)]
struct GoDependencyInspection<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    source_manifest_sha256: &'a str,
    scope: &'static str,
    native_receipt: &'a GoNativeModuleObservation,
    ownership_diagnostics: &'a [SourceOwnershipDiagnostic],
    dependencies: Option<serde_json::Value>,
}

fn module_entry(selected: GoModuleSelection<'_>) -> GoPackageSelection<'_> {
    GoPackageSelection {
        directory: selected.directory,
        package_path: selected.entry_path,
        go_version: "go1.22",
        target_os: selected.target_os,
        target_arch: selected.target_arch,
    }
}

/// Admits bounded native Go scalar bodies under the exact original closed context.
///
/// The host must independently select and supervise the body collector. This
/// observation provides standalone source-bound body nodes with conservative
/// result value domains for the admitted scalar input scope.
///
/// # Errors
/// Refuses changed original source, unsupported contexts and mismatched responses.
pub fn observe_go_native_body(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<ActualGoNativeBodyObservation, GoObservationError> {
    observe_go_body_with(project_root, selection, collector, launch, |_| ())
        .map(|(observation, ())| observation)
}

/// Produces scoped flow evidence for one exact occurrence in an admitted Go body report.
///
/// The occurrence must match the selected source, context and producer exchange.
/// Physical source is revalidated after interpretation.
///
/// # Errors
/// Refuses a malformed occurrence reference, changed source or incompatible worker output.
pub fn observe_go_native_body_flow(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    collector: &GoCollectorPin<'_>,
    occurrence: &str,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<
    (
        ActualGoNativeBodyObservation,
        Option<NativeScalarFlowObservation>,
    ),
    GoObservationError,
> {
    let suffix = occurrence
        .strip_prefix("native_body_occurrence:v1:sha256:")
        .ok_or(GoObservationError::InvalidTrustedBinding)?;
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GoObservationError::InvalidTrustedBinding);
    }
    observe_go_body_with(project_root, selection, collector, launch, |result| {
        result.inspect_flow(occurrence)
    })
}

fn observe_go_body_with<T>(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
    project: impl FnOnce(&ActualGoNativeBodyObservation) -> T,
) -> Result<(ActualGoNativeBodyObservation, T), GoObservationError> {
    observe_bound_exact(project_root, selection, |source, manifest| {
        let admitted = admit_go(source, collector)?;
        let output = launch(admitted.request_bytes())?;
        let observation = admitted.verify_bodies(collector, manifest, &output)?;
        let actual = ActualGoNativeBodyObservation::derive(observation);
        let projected = project(&actual);
        Ok((actual, projected))
    })
}

fn observe_exact<T>(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    operation: impl FnOnce(ExactClosedPackage<'_>) -> Result<T, GoObservationError>,
) -> Result<T, GoObservationError> {
    observe_bound_exact(project_root, selection, |source, _| operation(source))
}

fn observe_bound_exact<T>(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    operation: impl FnOnce(ExactClosedPackage<'_>, &str) -> Result<T, GoObservationError>,
) -> Result<T, GoObservationError> {
    let source = NativeSource::capture(project_root, "Go").map_err(source_failure)?;
    let observation = operation(
        closed_package(&source, selection),
        &source.binding.source_manifest_digest,
    )?;
    source.revalidate().map_err(source_failure)?;
    Ok(observation)
}

fn closed_package<'a>(
    source: &'a NativeSource<'_>,
    selection: GoPackageSelection<'a>,
) -> ExactClosedPackage<'a> {
    ExactClosedPackage {
        source: &source.view,
        source_fingerprint: &source.binding.source_fingerprint,
        authority_digest: &source.binding.authority_digest,
        logical_contracts: &source.binding.logical_contracts,
        actual: true,
        directory: selection.directory,
        package_path: selection.package_path,
        go_version: selection.go_version,
        target_os: selection.target_os,
        target_arch: selection.target_arch,
    }
}

fn source_failure(error: NativeSourceError) -> GoObservationError {
    match error {
        NativeSourceError::Unavailable(detail) => GoObservationError::SourceUnavailable(detail),
        NativeSourceError::Changed => GoObservationError::SourceChanged,
    }
}
