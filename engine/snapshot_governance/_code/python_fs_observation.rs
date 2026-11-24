//! Scoped original-source inspection for a conditional Python filesystem operation.

use std::path::Path;

use serde::Serialize;
use serde_json::{Value, json};

use super::{
    PythonFilesystemOutcome, PythonFilesystemProfile, PythonFilesystemRequest, PythonImportScope,
    PythonObservationError, PythonScalarProducer, PythonScalarSubject,
};
use crate::audit::NativeAuthorityScope;
use crate::implementation_observation::SourceOwnership;
use crate::native_observation::NativeSource;
use crate::portable::{canonical, digest};
use crate::program_semantics::ContextKnowledge;
use crate::project::EvaluationKey;
use crate::semantic_conformance::{
    HypotheticalPythonFilesystemPolicyProjection, project_hypothetical_python_filesystem_policy,
};
use crate::source_architecture::python_lexical::python_static_imports::UniquePythonModule;
use crate::state_effect_analysis::{
    HypotheticalPythonFilesystemCall, HypotheticalPythonFilesystemProjection,
    NativeFilesystemBinding, SummaryContext, native_filesystem_catalog_source_ref,
    project_hypothetical_python_filesystem,
};

/// Reviewed isolated worker that observes an installed import spec without loading it.
pub const PYTHON_ORIGIN_WORKER: &[u8] =
    include_bytes!("../../source_architecture/_code/python_origin_worker.py");

/// Independently selected exact runtime and the supervised execution context.
#[derive(Clone, Copy)]
pub struct PythonFilesystemHost<'a> {
    /// Pinned filesystem worker, admitted bootstrap, and installed runtime.
    pub producer: &'a PythonScalarProducer,
    /// One qualified isolated runtime profile.
    pub profile: PythonFilesystemProfile,
    /// Exact independently established executable, supervisor, and registration context.
    pub supervisor_ref: &'a str,
}

/// The original input identities and the conditional effect, where established.
#[derive(Serialize)]
pub struct HypotheticalPythonFilesystemObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    scope: &'static str,
    evaluation_key: EvaluationKey,
    source_scope_ref: String,
    source_path: String,
    source_ref: String,
    source_shape: Option<PythonFilesystemOutcome>,
    observation_ref: Option<String>,
    ready_ref: Option<String>,
    installed_origin_ref: Option<String>,
    runtime_execution: &'static str,
    canonical_finding_or_certificate: &'static str,
    status: &'static str,
    actual_project_binding: &'static str,
    effect: Option<Value>,
}

impl HypotheticalPythonFilesystemObservation {
    fn new(
        evaluation_key: EvaluationKey,
        scope: &PythonImportScope,
        subject: &PythonScalarSubject,
    ) -> Self {
        Self {
            schema: "urn:fortress:derived:v1:python-hypothetical-filesystem",
            schema_version: 1,
            scope: "HYPOTHETICAL_CLOSED_REFERENCE_ONLY",
            evaluation_key,
            source_scope_ref: scope.scope_ref().into(),
            source_path: subject.source_path.clone(),
            source_ref: subject.source_ref.clone(),
            source_shape: None,
            observation_ref: None,
            ready_ref: None,
            installed_origin_ref: None,
            runtime_execution: "NOT_RUN",
            canonical_finding_or_certificate: "NOT_ISSUED",
            status: "UNAVAILABLE",
            actual_project_binding: "UNESTABLISHED",
            effect: None,
        }
    }
}

/// Inspects a conditional operation over one original Python source artifact.
///
/// The independently selected host must provide two live bounded exchanges.
/// The compile-only worker receives the selected immutable source bytes after
/// readiness. A separate isolated import-origin process receives no project
/// input. A local alternative or incomplete original root inventory cannot
/// produce an effect. The result depends on the selected closed startup model
/// and carries no actual application runtime or authorization conclusion.
///
/// # Errors
/// Refuses invalid original bindings, unsupported trusted host input, failed
/// or malformed process exchanges, and source drift before publication.
pub fn observe_hypothetical_python_filesystem(
    project_root: &Path,
    subject: &PythonScalarSubject,
    scope: &PythonImportScope,
    host: PythonFilesystemHost<'_>,
    compile: impl FnOnce(&[u8], &[u8]) -> Result<Vec<u8>, PythonObservationError>,
    origin: impl FnOnce() -> Result<Vec<u8>, PythonObservationError>,
) -> Result<HypotheticalPythonFilesystemObservation, PythonObservationError> {
    let source = capture(project_root, host, NativeAuthorityScope::Observation)?;
    observe_captured(&source, subject, scope, host, compile, origin, |_| {})
}

/// Original authored policy viewed against a conditional closed reference.
#[derive(Serialize)]
pub struct HypotheticalPythonFilesystemPolicyObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    scope: &'static str,
    canonical_conformance: &'static str,
    runtime_reachability: &'static str,
    ownership: Option<SourceOwnership>,
    original_contract_path: Option<String>,
    original_contract_digest: Option<String>,
    authored_policy: Option<HypotheticalPythonFilesystemPolicyProjection>,
    hypothetical_receipt: HypotheticalPythonFilesystemObservation,
}

/// Inspects the original Module's declared policy under the closed Python model.
///
/// Original ownership and the operation premises share a single capture. The
/// policy is displayed only for a modeled conditional operation. It establishes
/// no actual project binding, reachability, conformance, or authorization.
///
/// # Errors
/// Refuses unsafe or stale input, invalid host context, and malformed exchanges.
pub fn observe_hypothetical_python_filesystem_policy(
    project_root: &Path,
    subject: &PythonScalarSubject,
    scope: &PythonImportScope,
    host: PythonFilesystemHost<'_>,
    compile: impl FnOnce(&[u8], &[u8]) -> Result<Vec<u8>, PythonObservationError>,
    origin: impl FnOnce() -> Result<Vec<u8>, PythonObservationError>,
) -> Result<HypotheticalPythonFilesystemPolicyObservation, PythonObservationError> {
    let source = capture(
        project_root,
        host,
        NativeAuthorityScope::AuthoredEffect(&subject.source_path),
    )?;
    let owner = source.binding.native_effect_policy.as_ref();
    let mut authored_policy = None;
    let hypothetical_receipt =
        observe_captured(&source, subject, scope, host, compile, origin, |effect| {
            authored_policy = owner.and_then(|binding| {
                project_hypothetical_python_filesystem_policy(effect, binding.policy.as_ref())
            });
        })?;
    Ok(HypotheticalPythonFilesystemPolicyObservation {
        schema: "urn:fortress:derived:v1:python-hypothetical-filesystem-policy",
        schema_version: 1,
        scope: "HYPOTHETICAL_CLOSED_REFERENCE_ONLY",
        canonical_conformance: "NOT_EVALUATED",
        runtime_reachability: "UNKNOWN",
        ownership: owner.map(|binding| binding.ownership.clone()),
        original_contract_path: owner.map(|binding| binding.contract_path.clone()),
        original_contract_digest: owner.map(|binding| binding.contract_digest.clone()),
        authored_policy,
        hypothetical_receipt,
    })
}

fn capture<'a>(
    project_root: &'a Path,
    host: PythonFilesystemHost<'_>,
    authority: NativeAuthorityScope<'_>,
) -> Result<NativeSource<'a>, PythonObservationError> {
    if !trusted_digest(host.supervisor_ref) {
        return Err(PythonObservationError::HostUnavailable);
    }
    NativeSource::capture_with(project_root, "Python", authority).map_err(Into::into)
}

fn observe_captured(
    source: &NativeSource<'_>,
    subject: &PythonScalarSubject,
    scope: &PythonImportScope,
    host: PythonFilesystemHost<'_>,
    compile: impl FnOnce(&[u8], &[u8]) -> Result<Vec<u8>, PythonObservationError>,
    origin: impl FnOnce() -> Result<Vec<u8>, PythonObservationError>,
    inspect: impl FnOnce(&HypotheticalPythonFilesystemProjection<'_>),
) -> Result<HypotheticalPythonFilesystemObservation, PythonObservationError> {
    if !subject.exact_bool_parameters.is_empty()
        || !scope.contains_source_path(&subject.source_path)
    {
        return Err(PythonObservationError::SubjectIdentityMismatch);
    }
    let context = context_ref(&json!([
        "fortress-python-closed-filesystem-context-v1",
        subject,
        scope.scope_ref(),
        host.producer,
        host.profile.runtime_ref(),
        digest(expected_origin(host.profile)),
        host.supervisor_ref,
        native_filesystem_catalog_source_ref(),
    ]))?;
    let key = EvaluationKey::new(
        &source.binding.source_manifest_digest,
        context,
        &source.binding.authority_digest,
    );
    let request = PythonFilesystemRequest::bind(
        &source.view,
        &key,
        &subject.source_path,
        &subject.function,
        host.producer,
        host.profile,
    )?;
    if request.source_ref() != subject.source_ref {
        return Err(PythonObservationError::SubjectIdentityMismatch);
    }
    let mut report = HypotheticalPythonFilesystemObservation::new(key, scope, subject);
    if !matches!(
        scope.unique_regular_module(&source.view, "pathlib")?,
        UniquePythonModule::Missing
    ) {
        report.status = "LOCAL_IMPORT_OR_SCOPE_UNRESOLVED";
        source.revalidate()?;
        return Ok(report);
    }
    let payload = request.worker_payload(&source.view, &report.evaluation_key)?;
    let ready = request.expected_ready()?;
    let frame = compile(&payload, &ready)?;
    let observed = request.admit(&source.view, &report.evaluation_key, &ready, &frame)?;
    report.source_shape = Some(*observed.outcome());
    report.observation_ref = Some(observed.response_ref().into());
    report.ready_ref = Some(observed.ready_ref().into());
    report.status = match observed.outcome() {
        PythonFilesystemOutcome::ClosedLiteralShape { site } => {
            let live = origin()?;
            if live.as_slice() != expected_origin(host.profile) {
                return Err(PythonObservationError::HostUnavailable);
            }
            let origin_ref = digest(&live);
            let receiver = observed.installed_receiver();
            report.effect = Some(project_closed(
                source,
                &report,
                host,
                &receiver,
                &origin_ref,
                [site.start_byte, site.end_byte],
                inspect,
            )?);
            report.installed_origin_ref = Some(origin_ref);
            "CONDITIONAL"
        }
        PythonFilesystemOutcome::LocalOrShadowed { .. } => "LOCAL_OR_SHADOWED",
        PythonFilesystemOutcome::Unresolved { .. } => "UNRESOLVED",
        PythonFilesystemOutcome::Unavailable { .. } => "UNAVAILABLE",
    };
    source.revalidate()?;
    Ok(report)
}

fn expected_origin(profile: PythonFilesystemProfile) -> &'static [u8] {
    match profile {
        PythonFilesystemProfile::WindowsX64 => {
            include_bytes!("../_data/python_origin_windows_v1.json")
        }
        PythonFilesystemProfile::LinuxX64 => include_bytes!("../_data/python_origin_linux_v1.json"),
    }
}

fn project_closed(
    source: &NativeSource<'_>,
    report: &HypotheticalPythonFilesystemObservation,
    host: PythonFilesystemHost<'_>,
    receiver: &super::PythonInstalledFilesystemReceiver,
    origin_ref: &str,
    site: [usize; 2],
    inspect: impl FnOnce(&HypotheticalPythonFilesystemProjection<'_>),
) -> Result<Value, PythonObservationError> {
    let observation_ref = report
        .observation_ref
        .as_deref()
        .ok_or(PythonObservationError::HostUnavailable)?;
    let model_ref = context_ref(&json!([
        "fortress-python-isolated-closed-startup-v1",
        host.profile.runtime_ref(),
        host.supervisor_ref,
        origin_ref,
        "EXACT_INSTALLED_MODULE_RECEIVER_AND_METHOD_UNCHANGED",
        "NO_IMPORT_OR_AUDIT_INTERPOSITION",
        "EXACT_FUNCTION_INVOKED_AND_CALL_REACHED",
    ]))?;
    let evaluation_ref = report.evaluation_key.digest();
    let binding = NativeFilesystemBinding {
        snapshot_fingerprint: &source.binding.source_fingerprint,
        source_view_sha256: source.view.digest(),
        authority_sha256: &source.binding.authority_digest,
        evaluation_sha256: &evaluation_ref,
        source_path: &report.source_path,
        source_sha256: &report.source_ref,
    };
    let declaration_ref = context_ref(&json!([
        "fortress-python-pathlib-receiver-v1",
        receiver.context_ref,
        receiver.entry_ref,
        receiver.receiver,
        origin_ref,
    ]))?;
    let context = SummaryContext {
        source_digest: ContextKnowledge::Known(receiver.context_ref.into()),
        version: ContextKnowledge::Known(receiver.version.into()),
        target: ContextKnowledge::Known(receiver.target.into()),
        features: ContextKnowledge::Known(vec!["isolated".into(), "no-site".into()]),
        type_bindings: ContextKnowledge::Known(vec![receiver.receiver.into()]),
    };
    let proposed = HypotheticalPythonFilesystemCall {
        binding,
        source_observation_sha256: observation_ref,
        source_scope_sha256: &report.source_scope_ref,
        installed_origin_sha256: origin_ref,
        startup_assumptions_sha256: &model_ref,
        declaration_sha256: &declaration_ref,
        summary_context: &context,
        site,
    };
    let bytes = source
        .view
        .bytes(&report.source_path)
        .ok_or(PythonObservationError::SubjectIdentityMismatch)?;
    let effect = project_hypothetical_python_filesystem(binding, bytes, &proposed)
        .map_err(PythonObservationError::FilesystemEffect)?;
    inspect(&effect);
    serde_json::to_value(effect).map_err(PythonObservationError::FilesystemJson)
}

fn trusted_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn context_ref(value: &Value) -> Result<String, PythonObservationError> {
    Ok(digest(
        &canonical(value).map_err(PythonObservationError::FilesystemCanonical)?,
    ))
}
