//! Explicit actual-state Go observation supervision owned by Snapshot Governance.

use std::path::Path;

use serde::Serialize;

use crate::audit::{NativeAuthorityScope, NativeObservationBinding};
use crate::candidate::{
    CandidateWorkspace, HypotheticalNativeBodyInspection, NativeCandidateBody,
    NativeCandidateCalls, NativeCandidateSelection, NativeCandidateSubject,
    inspect_hypothetical_native_body, inspect_hypothetical_native_call_boundaries,
    inspect_hypothetical_native_calls, native_error,
};
use crate::implementation_observation::{NativeDependencyContext, SourceOwnershipDiagnostic};
use crate::information_flow::NativeScalarFlowObservation;
use crate::migration_governance::MigrationError;
use crate::native_observation::{
    NativeSource, NativeSourceError, project_native_call_ownership,
    project_native_call_sensitivity, project_native_call_topology,
};
use crate::observation::SourceView;
use crate::program_semantics::go_observation::{
    ExactClosedPackage, GoNativeBodyObservation, admit_go, admit_go_build, admit_go_module,
    admit_go_tests,
};
use crate::program_semantics::native_body::{
    NativeCallTopology, NativeScalarBody, inspect_native_call_topology,
};
use crate::semantic_analysis::{NativeBooleanSensitivity, analyze_native_boolean_calls};

#[path = "go_body_domains.rs"]
mod body_domains;

#[path = "go_fs_observation.rs"]
mod filesystem;
pub use body_domains::ActualGoNativeBodyObservation;
pub use filesystem::{
    ActualGoFilesystemEffectObservation, ActualGoFilesystemPolicyObservation, GoFilesystemHost,
    observe_go_filesystem_effects, observe_go_filesystem_policy,
};

#[path = "go_callable.rs"]
mod callable;
pub use callable::{
    GoCallableHost, GoCallableSelection, observe_go_authored_call_return,
    observe_go_authored_native_return, observe_go_linked_callable,
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
    collect_go_module_dependencies(
        project_root,
        selected,
        build_context,
        collector,
        launch,
        false,
    )
}

/// Compares admitted positive Go Module edges with the exact original CCG.
/// The report does not authorize changes or establish any missing edge.
///
/// # Errors
/// Returns the same source, transport, and output errors as dependency inspection.
pub fn observe_go_module_dependency_intent(
    project_root: &Path,
    selected: GoModuleSelection<'_>,
    build_context: GoBuildContext,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<Vec<u8>, GoObservationError> {
    collect_go_module_dependencies(
        project_root,
        selected,
        build_context,
        collector,
        launch,
        true,
    )
}

fn collect_go_module_dependencies(
    project_root: &Path,
    selected: GoModuleSelection<'_>,
    build_context: GoBuildContext,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
    with_intent: bool,
) -> Result<Vec<u8>, GoObservationError> {
    let scope = if with_intent {
        NativeAuthorityScope::DependenciesWithIntent
    } else {
        NativeAuthorityScope::Dependencies
    };
    let source = NativeSource::capture_with(project_root, "Go", scope).map_err(source_failure)?;
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
    let mut intent = None;
    let dependencies = admitted.project_dependencies(&input, context, &receipt, |observed| {
        if with_intent {
            intent = Some(
                source
                    .compare_dependency_intent(Some(observed))
                    .map_err(|_| GoObservationError::WireEncoding)?,
            );
        }
        Ok(())
    })?;
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
    let report = if with_intent {
        let comparison = match intent {
            Some(result) => result,
            None => source
                .compare_dependency_intent(None)
                .map_err(|_| GoObservationError::WireEncoding)?,
        };
        serde_json::json!({
            "$schema": "urn:fortress:derived:v1:native-source-dependency-intent",
            "schema_version": 1,
            "scope": "OBSERVED_EDGES_ONLY",
            "evidence": report,
            "comparison": comparison,
        })
    } else {
        report
    };
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
    validate_body_occurrence(occurrence)?;
    observe_go_body_with(project_root, selection, collector, launch, |result| {
        result.inspect_flow(occurrence)
    })
}

/// Compares finite Boolean return values for one original admitted Go occurrence.
///
/// The comparison retains the exact body receipt and qualified input model.
/// Physical source is revalidated after interpreting the selected body.
///
/// # Errors
/// Refuses malformed occurrence references, source drift, or incompatible replies.
pub fn observe_go_native_body_sensitivity(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    collector: &GoCollectorPin<'_>,
    occurrence: &str,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<
    (
        ActualGoNativeBodyObservation,
        Option<NativeBooleanSensitivity>,
    ),
    GoObservationError,
> {
    validate_body_occurrence(occurrence)?;
    observe_go_body_with(project_root, selection, collector, launch, |result| {
        result.inspect_sensitivity(occurrence)
    })
}

/// Observes exact typed call targets from a closed Go package.
///
/// The body producer has an independent, incompatible response mode. An admitted
/// call relates exact declarations in the same captured package and grants no
/// evaluation, effect, runtime execution, or certification authority.
///
/// # Errors
/// Refuses unsafe or stale source and incomplete, untrusted, or mismatched replies.
pub fn observe_go_native_bound_calls(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<serde_json::Value, GoObservationError> {
    observe_bound_exact(project_root, selection, |source, manifest| {
        let admitted = admit_go(source, collector)?;
        let output = launch(admitted.request_bytes())?;
        admitted.verify_call_bodies(collector, manifest, &output)
    })
}

/// Composes a selected exact Go call graph under a finite Boolean model.
///
/// All reached declarations must have supported bodies and complete returns for
/// every admitted input. Cycles and limits yield an explicit unavailable result.
/// The result is derived inspection under static premises.
///
/// # Errors
/// Refuses unsafe or stale source and incomplete, untrusted, or mismatched replies.
pub fn observe_go_native_call_return(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    occurrence: &str,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<serde_json::Value, GoObservationError> {
    validate_body_occurrence(occurrence)?;
    observe_verified_go_calls(project_root, selection, collector, launch, |observed| {
        let targets = observed.call_targets()?;
        let result = match exact_call_body(&observed, occurrence) {
            Some(body) => serde_json::to_value(analyze_native_boolean_calls(body, &targets))
                .map_err(|_| GoObservationError::WireEncoding)?,
            None => serde_json::json!({
                "status": "UNAVAILABLE",
                "occurrence": occurrence,
                "reason": "MISSING_EXACT_OCCURRENCE",
            }),
        };
        Ok(serde_json::json!({
            "$schema": "urn:fortress:derived:v1:go-native-call-return",
            "schema_version": 1,
            "scope": "BOUNDED_CLOSED_BOOLEAN_CALL_RETURN",
            "observation": observed.call_evidence(),
            "evaluation": result,
        }))
    })
}

/// Compares paired Boolean inputs across an exact, supported Go call closure.
///
/// The comparison covers returned values only. Its result retains all modeled
/// dependency occurrences and makes no claim about execution or external effects.
///
/// # Errors
/// Refuses unsafe or stale source, invalid selectors and incompatible producer replies.
pub fn observe_go_native_call_sensitivity(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    occurrence: &str,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<serde_json::Value, GoObservationError> {
    validate_body_occurrence(occurrence)?;
    observe_verified_go_calls(project_root, selection, collector, launch, |observed| {
        let sensitivity = if let Some(body) = exact_call_body(&observed, occurrence) {
            let targets = observed.call_targets()?;
            serde_json::to_value(analyze_native_boolean_calls(body, &targets).into_sensitivity())
                .map_err(|_| GoObservationError::WireEncoding)?
        } else {
            serde_json::json!({
                "status": "UNAVAILABLE",
                "occurrence": occurrence,
                "reason": "MISSING_EXACT_OCCURRENCE",
            })
        };
        Ok(project_native_call_sensitivity(
            "go",
            &observed.call_evidence(),
            &sensitivity,
        ))
    })
}

/// Inspects the source-bound static call topology for one admitted Go body occurrence.
///
/// The result projects admitted call relationships and explicitly records targets
/// with unavailable bodies. Structural reachability and recursion are scoped to
/// these edges. The operation performs no target execution.
///
/// # Errors
/// Refuses unsafe or stale source, invalid selectors and incompatible producer replies.
pub fn observe_go_native_call_topology(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    occurrence: &str,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<serde_json::Value, GoObservationError> {
    validate_body_occurrence(occurrence)?;
    observe_verified_go_calls(project_root, selection, collector, launch, |observed| {
        let graph = go_call_topology(&observed, occurrence)?;
        Ok(project_native_call_topology(
            "go",
            &observed.call_evidence(),
            &graph,
        ))
    })
}

/// Reconciles exact admitted Go calls with the independently selected original
/// logical Module owners and original CCG.
///
/// The result provides positive source-level observations within the selected
/// closure. Runtime execution, missing edges, or certification require separate
/// evidence.
///
/// # Errors
/// Refuses stale source or authority, invalid selectors, and incompatible worker replies.
pub fn observe_go_native_call_module_boundaries(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    occurrence: &str,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<serde_json::Value, GoObservationError> {
    validate_body_occurrence(occurrence)?;
    let source = NativeSource::capture_with(
        project_root,
        "Go",
        NativeAuthorityScope::DependenciesWithIntent,
    )
    .map_err(source_failure)?;
    let observed = verified_go_calls(&source, selection, collector, launch)?;
    let graph = go_call_topology(&observed, occurrence)?;
    let report = project_native_call_ownership(
        &source.view,
        &source.binding,
        &source.binding,
        "go",
        &observed.call_evidence(),
        &graph,
    )
    .map_err(source_failure)?;
    source.revalidate().map_err(source_failure)?;
    Ok(report)
}

fn go_call_topology<'a>(
    observed: &'a GoNativeBodyObservation,
    occurrence: &str,
) -> Result<NativeCallTopology<'a>, GoObservationError> {
    match exact_call_body(observed, occurrence) {
        Some(body) => Ok(inspect_native_call_topology(
            body,
            &observed.call_targets()?,
        )),
        None => Ok(NativeCallTopology::unavailable(
            Some(occurrence),
            "MISSING_EXACT_OCCURRENCE",
        )),
    }
}

fn exact_call_body<'a>(
    observed: &'a GoNativeBodyObservation,
    occurrence: &str,
) -> Option<&'a NativeScalarBody> {
    let mut matching = observed
        .lowered_bodies()
        .flatten()
        .filter(|body| body.binding() == occurrence);
    matching.next().filter(|_| matching.next().is_none())
}

fn observe_verified_go_calls<T>(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
    inspect: impl FnOnce(GoNativeBodyObservation) -> Result<T, GoObservationError>,
) -> Result<T, GoObservationError> {
    let source = NativeSource::capture(project_root, "Go").map_err(source_failure)?;
    let result = inspect(verified_go_calls(&source, selection, collector, launch)?)?;
    source.revalidate().map_err(source_failure)?;
    Ok(result)
}

fn verified_go_calls(
    source: &NativeSource<'_>,
    selection: GoPackageSelection<'_>,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<GoNativeBodyObservation, GoObservationError> {
    let admitted = admit_go(closed_package(source, selection), collector)?;
    let output = launch(admitted.request_bytes())?;
    admitted.verify_bound_bodies(collector, &source.binding.source_manifest_digest, &output)
}

/// Inspects a retained candidate's exact closed Go function under the Boolean model.
///
/// Only an explicit host supplies the compiler process. The candidate remains
/// unapplied and the result carries separate original and target identities.
///
/// # Errors
/// Refuses missing, stale or cancelled candidates and incompatible native replies.
pub fn observe_go_candidate_sensitivity(
    workspace: &CandidateWorkspace,
    retained: NativeCandidateSelection<'_>,
    package: GoPackageSelection<'_>,
    subject: NativeCandidateSubject<'_>,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<HypotheticalNativeBodyInspection, MigrationError> {
    inspect_hypothetical_native_body(workspace, retained, subject, "go", |view, binding, _| {
        let source = scoped_package(view, binding, package, false);
        let admitted = admit_go(source, collector).map_err(native_error)?;
        let output = launch(admitted.request_bytes()).map_err(native_error)?;
        let observed = admitted
            .verify_bodies(collector, &binding.source_manifest_digest, &output)
            .map_err(native_error)?;
        let (evaluation_key, response_ref, body) =
            observed.into_selected_body(subject.source_path, subject.function);
        Ok(NativeCandidateBody::analyzed(
            evaluation_key,
            response_ref,
            body.as_deref(),
        ))
    })
}

/// Compose exact Go calls from a retained unapplied candidate postimage.
///
/// The selected native compiler context and source are independently bound.
/// The result remains an inspection of the candidate's finite return model.
///
/// # Errors
/// Refuses stale or cancelled candidates, unsafe inputs, and mismatched native receipts.
pub fn observe_go_candidate_call_return(
    workspace: &CandidateWorkspace,
    retained: NativeCandidateSelection<'_>,
    package: GoPackageSelection<'_>,
    subject: NativeCandidateSubject<'_>,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<HypotheticalNativeBodyInspection, MigrationError> {
    inspect_hypothetical_native_calls(workspace, retained, subject, "go", |view, binding| {
        let source = scoped_package(view, binding, package, false);
        let admitted = admit_go(source, collector).map_err(native_error)?;
        let output = launch(admitted.request_bytes()).map_err(native_error)?;
        let observed = admitted
            .verify_bound_bodies(collector, &binding.source_manifest_digest, &output)
            .map_err(native_error)?;
        let targets = observed.call_targets().map_err(native_error)?;
        let result = observed
            .selected_call_body(subject.source_path, subject.function)
            .map(|body| analyze_native_boolean_calls(body, &targets));
        let (evaluation, response) = observed.call_identity();
        Ok(NativeCandidateCalls {
            evaluation_key: evaluation.clone(),
            response_ref: response.into(),
            limitation: result
                .is_none()
                .then(|| "SELECTED_DECLARATION_OR_BODY_UNAVAILABLE".into()),
            result,
        })
    })
}

/// Evaluates admitted call dependencies in a retained exact Go candidate.
/// The original CCG supplies dependency intent after unchanged authority and
/// graph bindings have been established.
///
/// # Errors
/// Refuses stale or cancelled candidates, unsafe inputs, and mismatched native replies.
pub fn observe_go_candidate_call_module_boundaries(
    workspace: &CandidateWorkspace,
    retained: NativeCandidateSelection<'_>,
    package: GoPackageSelection<'_>,
    subject: NativeCandidateSubject<'_>,
    collector: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<HypotheticalNativeBodyInspection, MigrationError> {
    inspect_hypothetical_native_call_boundaries(
        workspace,
        retained,
        subject,
        "go",
        |view, original, candidate| {
            let source = scoped_package(view, candidate, package, false);
            let admitted = admit_go(source, collector).map_err(native_error)?;
            let output = launch(admitted.request_bytes()).map_err(native_error)?;
            let observed = admitted
                .verify_bound_bodies(collector, &candidate.source_manifest_digest, &output)
                .map_err(native_error)?;
            let graph = match observed.selected_call_body(subject.source_path, subject.function) {
                Some(body) => inspect_native_call_topology(
                    body,
                    &observed.call_targets().map_err(native_error)?,
                ),
                None => NativeCallTopology::unavailable(
                    None,
                    "SELECTED_DECLARATION_OR_BODY_UNAVAILABLE",
                ),
            };
            project_native_call_ownership(
                view,
                candidate,
                original,
                "go",
                &observed.call_evidence(),
                &graph,
            )
            .map_err(|failure| native_error(source_failure(failure)))
        },
    )
}

fn validate_body_occurrence(occurrence: &str) -> Result<(), GoObservationError> {
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
    Ok(())
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
    scoped_package(&source.view, &source.binding, selection, true)
}

fn scoped_package<'a>(
    source: &'a SourceView,
    binding: &'a NativeObservationBinding,
    selection: GoPackageSelection<'a>,
    actual: bool,
) -> ExactClosedPackage<'a> {
    ExactClosedPackage {
        source,
        source_fingerprint: &binding.source_fingerprint,
        authority_digest: &binding.authority_digest,
        logical_contracts: &binding.logical_contracts,
        actual,
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
