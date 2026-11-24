//! Actual-state orchestration for a source-bound Go callable link.

use std::path::Path;

use super::{
    GoBuildContext, GoCollectorPin, GoModuleSelection, GoObservationError, admit_go_module,
    closed_package, module_entry, source_failure,
};
use crate::audit::NativeAuthorityScope;
use crate::native_observation::NativeSource;
use crate::native_return_observation::{
    AuthoredNativeReturnObservation, compare_captured_native_return,
};
use crate::program_semantics::native_callable::NativeCallableOutcome;

/// Independently selected Go callable within one closed native module.
#[derive(Clone, Copy)]
pub struct GoCallableSelection<'a> {
    /// Exact native module and package under the bounded build context.
    pub module: GoModuleSelection<'a>,
    /// Exact name of the free function to link.
    pub function: &'a str,
}

/// Separately chosen trusted native workers for a module and body exchange.
#[derive(Clone, Copy)]
pub struct GoCallableHost<'a> {
    /// Pinned executable and supervisor for native module observation v3.
    pub module: &'a GoCollectorPin<'a>,
    /// Pinned executable and supervisor for the first-order scalar body.
    pub body: &'a GoCollectorPin<'a>,
}

/// Links one exact Go free function in an admitted single-package module scope.
///
/// Both pinned process callbacks receive bounded payloads from the same
/// physical snapshot. The first-order body receives exactly the ordinary
/// source files selected by the verified module receipt. Neither callback
/// gains write authority or chooses the original governing authority.
///
/// # Errors
/// Refuses unsafe, stale or incomplete original input, mismatched trusted
/// toolchain identities, and invalid replies. Scope and link limitations stay
/// explicitly unavailable and carry no runtime or certification interpretation.
pub fn observe_go_linked_callable(
    project_root: &Path,
    selected: GoCallableSelection<'_>,
    context: GoBuildContext,
    host: GoCallableHost<'_>,
    launch_module: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
    launch_body: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<NativeCallableOutcome, GoObservationError> {
    let source =
        NativeSource::capture_for_dependencies(project_root, "Go").map_err(source_failure)?;
    let linked = link(&source, selected, context, host, launch_module, launch_body)?;
    source.revalidate().map_err(source_failure)?;
    Ok(linked)
}

/// Observes an explicit original-authority Boolean requirement and exact Go body.
///
/// The trusted host selects the original closed package and both producers.
/// The authored document is read from the same immutable capture as the body.
///
/// # Errors
/// Refuses an incomplete original state, mismatched exchanges or source drift.
pub fn observe_go_authored_native_return(
    project_root: &Path,
    selected: GoCallableSelection<'_>,
    context: GoBuildContext,
    host: GoCallableHost<'_>,
    launch_module: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
    launch_body: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<AuthoredNativeReturnObservation, GoObservationError> {
    let source =
        NativeSource::capture_with(project_root, "Go", NativeAuthorityScope::AuthoredReturn)
            .map_err(source_failure)?;
    let linked = link(&source, selected, context, host, launch_module, launch_body)?;
    let report = compare_captured_native_return(&source, linked);
    source.revalidate().map_err(source_failure)?;
    Ok(report)
}

fn link(
    source: &NativeSource<'_>,
    selected: GoCallableSelection<'_>,
    context: GoBuildContext,
    host: GoCallableHost<'_>,
    launch_module: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
    launch_body: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<NativeCallableOutcome, GoObservationError> {
    let original = closed_package(source, module_entry(selected.module));
    let admitted = admit_go_module(original, selected.module, host.module, context)?;
    let module = admitted.verify(host.module, &launch_module(admitted.request_bytes())?)?;
    let mut linked = admitted.link_callable(
        original,
        &module,
        host.body,
        selected.function,
        &source.binding.source_manifest_digest,
        launch_body,
    )?;
    if let NativeCallableOutcome::Linked(subject) = &mut linked {
        let owner = source
            .original_declared_owner(subject.source_path())
            .map_err(source_failure)?;
        subject.record_original_owner(owner);
    }
    Ok(linked)
}
