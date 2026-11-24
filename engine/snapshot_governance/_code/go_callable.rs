//! Actual-state orchestration for a source-bound Go callable link.

use std::path::Path;

use super::{
    GoBuildContext, GoCollectorPin, GoModuleSelection, GoObservationError, admit_go_module,
    closed_package, module_entry, source_failure,
};
use crate::native_observation::NativeSource;
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
    let original = closed_package(&source, module_entry(selected.module));
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
    source.revalidate().map_err(source_failure)?;
    Ok(linked)
}
