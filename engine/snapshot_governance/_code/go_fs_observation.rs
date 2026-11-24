//! Explicit original-source Go filesystem observations over trusted compiler evidence.

use std::path::Path;

use serde::Serialize;
use serde_json::{Value, json};

use super::{
    GoCollectorPin, GoObservationError, GoPackageSelection, closed_package, observe_bound_exact,
    source_failure,
};
use crate::audit::NativeAuthorityScope;
use crate::implementation_observation::SourceOwnership;
use crate::native_observation::NativeSource;
use crate::portable::{canonical, digest};
use crate::program_semantics::ContextKnowledge;
use crate::program_semantics::go_observation::{
    ExactClosedPackage, GoFilesystemCallResolution, GoFilesystemDisposition,
    GoFilesystemLibraryPin, GoNativeFilesystemObservation, admit_go_filesystem,
};
use crate::project::EvaluationKey;
use crate::semantic_conformance::{
    NativeFilesystemPolicyProjection, project_native_filesystem_policy,
};
use crate::state_effect_analysis::{
    NativeFilesystemBatch, NativeFilesystemBinding, NativeFilesystemCall, NativeFilesystemCallee,
    NativeFilesystemLanguage, NativeFilesystemOperation, NativeFilesystemProjection,
    SummaryContext, native_filesystem_catalog_source_ref, project_native_filesystem_effects,
};

/// Independently selected process and packaged standard-library tool context.
///
/// The host verifies the observed executable and its installed export data
/// against the reviewed local standard-library preparation for this platform.
/// In particular the selected recipe builds the standard library without cgo.
/// Untrusted source or a retained receipt cannot create this process premise.
#[derive(Clone, Copy)]
pub struct GoFilesystemHost<'a> {
    /// Exact native executable and bounded independent supervisor selection.
    pub collector: &'a GoCollectorPin<'a>,
    /// Exact independently selected standard package and export-set digests.
    pub library: GoFilesystemLibraryPin<'a>,
}

/// A source-bound native observation and separate scoped lower effect facts.
#[derive(Serialize)]
pub struct ActualGoFilesystemEffectObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    runtime_execution: &'static str,
    canonical_finding_or_certificate: &'static str,
    evaluation_key: EvaluationKey,
    native: GoNativeFilesystemObservation,
    effects: Option<Value>,
}

/// Observes explicit standard filesystem operation sites in one closed Go file.
///
/// This uses the original physical capture, the pinned native worker, and the
/// existing Operation Summary catalog. It never runs the observed project.
/// Missing or unsupported native context, unknown upper bounds, and actual
/// execution remain separate. The scoped observation issues no findings,
/// approval, or certificate.
///
/// # Errors
/// Refuses invalid trusted input, malformed producer output and source changes
/// before publication.
pub fn observe_go_filesystem_effects(
    project_root: &Path,
    selection: GoPackageSelection<'_>,
    host: GoFilesystemHost<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<ActualGoFilesystemEffectObservation, GoObservationError> {
    if !qualified_sdk(selection, host) {
        return Err(GoObservationError::UnsupportedContext);
    }
    observe_bound_exact(project_root, selection, |source, manifest| {
        let result = collect_effects(source, manifest, selection, host, None, launch, |_| ())?;
        Ok(result.receipt)
    })
}

/// One exact original Module selection attached to independently observed effects.
#[derive(Serialize)]
pub struct ActualGoFilesystemPolicyObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    source_path: String,
    scope: &'static str,
    canonical_conformance: &'static str,
    runtime_reachability: &'static str,
    ownership: Option<SourceOwnership>,
    original_contract_path: Option<String>,
    original_contract_digest: Option<String>,
    authored_policy: Option<NativeFilesystemPolicyProjection>,
    native_receipt: ActualGoFilesystemEffectObservation,
}

/// Appraises applicable original authored policy at the observed Go source sites.
///
/// It captures one immutable original source and authority for the explicitly
/// selected file. Mechanical or ambiguous ownership does not supply a policy.
/// The result preserves the original effect receipt and reports policy
/// declarations without deriving an execution premise or conformance verdict.
///
/// # Errors
/// Refuses missing or changed original source, mismatched selected path, and
/// invalid trusted compiler context or observations.
pub fn observe_go_filesystem_policy(
    project_root: &Path,
    source_path: &str,
    selection: GoPackageSelection<'_>,
    host: GoFilesystemHost<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<ActualGoFilesystemPolicyObservation, GoObservationError> {
    if !qualified_sdk(selection, host) {
        return Err(GoObservationError::UnsupportedContext);
    }
    let source = NativeSource::capture_with(
        project_root,
        "Go",
        NativeAuthorityScope::AuthoredEffect(source_path),
    )
    .map_err(source_failure)?;
    let owner = source.binding.native_effect_policy.as_ref();
    let result = collect_effects(
        closed_package(&source, selection),
        &source.binding.source_manifest_digest,
        selection,
        host,
        Some(source_path),
        launch,
        |effect| {
            owner.map(|binding| project_native_filesystem_policy(effect, binding.policy.as_ref()))
        },
    )?;
    source.revalidate().map_err(source_failure)?;
    Ok(ActualGoFilesystemPolicyObservation {
        schema: "urn:fortress:derived:v1:go-filesystem-policy",
        schema_version: 1,
        source_path: source_path.to_owned(),
        scope: "EXACT_ORIGINAL_DECLARED_MODULE",
        canonical_conformance: "NOT_EVALUATED",
        runtime_reachability: "UNKNOWN",
        ownership: owner.map(|binding| binding.ownership.clone()),
        original_contract_path: owner.map(|binding| binding.contract_path.clone()),
        original_contract_digest: owner.map(|binding| binding.contract_digest.clone()),
        authored_policy: result.projection.flatten(),
        native_receipt: result.receipt,
    })
}

struct GoEffectCapture<T> {
    receipt: ActualGoFilesystemEffectObservation,
    projection: Option<T>,
}

fn collect_effects<T>(
    source: ExactClosedPackage<'_>,
    manifest: &str,
    selection: GoPackageSelection<'_>,
    host: GoFilesystemHost<'_>,
    expected_source_path: Option<&str>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
    inspect: impl FnOnce(&NativeFilesystemProjection<'_>) -> T,
) -> Result<GoEffectCapture<T>, GoObservationError> {
    let plan = admit_go_filesystem(source, host.collector, host.library)?;
    if expected_source_path.is_some_and(|path| path != plan.source_path()) {
        return Err(GoObservationError::UnsupportedContext);
    }
    let native = plan.verify(host.collector, &launch(plan.request_bytes())?)?;
    let effect_context = canonical(&json!([
        "fortress-go-filesystem-effect-v1",
        native.binding_ref(),
        native_filesystem_catalog_source_ref(),
    ]))
    .map_err(|_| GoObservationError::WireEncoding)?;
    let evaluation_key =
        EvaluationKey::new(manifest, digest(&effect_context), source.authority_digest);
    let (effects, projection) = if native.disposition() == GoFilesystemDisposition::Observed {
        let bytes = source
            .source
            .bytes(native.source_path())
            .ok_or(GoObservationError::InvalidResponse)?;
        let evaluation_ref = evaluation_key.digest();
        let binding = NativeFilesystemBinding {
            snapshot_fingerprint: source.source_fingerprint,
            source_view_sha256: source.source.digest(),
            authority_sha256: source.authority_digest,
            evaluation_sha256: &evaluation_ref,
            source_path: native.source_path(),
            source_sha256: native.source_ref(),
        };
        let (effects, projected) =
            project_sites(&native, bytes, binding, selection, host, inspect)?;
        (Some(effects), Some(projected))
    } else {
        (None, None)
    };
    Ok(GoEffectCapture {
        receipt: ActualGoFilesystemEffectObservation {
            schema: "urn:fortress:derived:v1:go-filesystem-effects",
            schema_version: 1,
            runtime_execution: "NOT_RUN",
            canonical_finding_or_certificate: "NOT_ISSUED",
            evaluation_key,
            native,
            effects,
        },
        projection,
    })
}

// These are the independently qualified standard package sources and the
// matching embedded gc export sets. A valid digest supplied by the host does
// not extend the supported Operation Summary execution context.
fn qualified_sdk(selection: GoPackageSelection<'_>, host: GoFilesystemHost<'_>) -> bool {
    let (source, exports) = match (
        selection.target_os,
        selection.target_arch,
        host.collector.go_toolchain,
    ) {
        ("linux", "amd64", "go1.22.2") => (
            "sha256:f303ff6f8d3d1c289200cd4ec875383db41fa256582cf573e9e24cd02043523f",
            "sha256:ad593385ff54ba4a158d464bc9d9ef87bf9a13f3ad26d63f5f5f26c2452aa377",
        ),
        ("windows", "amd64", "go1.22.12") => (
            "sha256:8f61ebb242bc4c60ebcaf6a96015ff67d0ac84d3441da63bd6c185eda13fc226",
            "sha256:4ff2871ac521be941d7da0eaef51d1a90a6e30a504774a8b043a03943e1798bc",
        ),
        _ => return false,
    };
    source == host.library.package_source_ref && exports == host.library.export_set_ref
}

fn project_sites<T>(
    native: &GoNativeFilesystemObservation,
    bytes: &[u8],
    binding: NativeFilesystemBinding<'_>,
    selection: GoPackageSelection<'_>,
    host: GoFilesystemHost<'_>,
    inspect: impl FnOnce(&NativeFilesystemProjection<'_>) -> T,
) -> Result<(Value, T), GoObservationError> {
    let declaration_sha256 = native
        .declaration_ref()
        .ok_or(GoObservationError::InvalidResponse)?;
    let context = SummaryContext {
        source_digest: ContextKnowledge::Known(host.library.package_source_ref.into()),
        version: ContextKnowledge::Known(host.collector.go_toolchain.into()),
        target: ContextKnowledge::Known(format!(
            "{}/{}",
            selection.target_os, selection.target_arch
        )),
        features: ContextKnowledge::Known(vec!["cgo-disabled".into(), "local-stdlib".into()]),
        type_bindings: ContextKnowledge::Known(Vec::new()),
    };
    let calls: Vec<_> = native
        .calls()
        .iter()
        .map(|site| {
            let callee = match site.resolution() {
                GoFilesystemCallResolution::ResolvedStandardLibrary => {
                    NativeFilesystemCallee::ResolvedStandardLibrary {
                        operation: NativeFilesystemOperation::GoOsWriteFile,
                        declaration_sha256,
                        summary_context: &context,
                    }
                }
                GoFilesystemCallResolution::LocalOrShadowed => {
                    NativeFilesystemCallee::LocalOrShadowed
                }
                GoFilesystemCallResolution::Unresolved => NativeFilesystemCallee::Unresolved,
            };
            NativeFilesystemCall {
                start_byte: site.start_byte(),
                end_byte: site.end_byte(),
                callee,
            }
        })
        .collect();
    let batch = NativeFilesystemBatch {
        language: NativeFilesystemLanguage::Go,
        binding,
        observation_sha256: native.response_ref(),
        calls: &calls,
    };
    let projection = project_native_filesystem_effects(binding, bytes, &batch)
        .map_err(|failure| GoObservationError::Execution(failure.to_string()))?;
    let inspected = inspect(&projection);
    let serialized =
        serde_json::to_value(projection).map_err(|_| GoObservationError::WireEncoding)?;
    Ok((serialized, inspected))
}
