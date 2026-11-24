//! Original-source linkage of a Python lexical module to its scalar declaration.

use std::path::Path;

use super::{
    PythonImportScope, PythonObservationError, PythonScalarError, PythonScalarProducer,
    PythonScalarSubject, bind_scalar_request,
};
use crate::affected_analysis::sha256;
use crate::audit::NativeAuthorityScope;
use crate::native_observation::NativeSource;
use crate::native_return_observation::{
    AuthoredNativeCallReturnObservation, AuthoredNativeReturnObservation,
    compare_captured_native_call_return, compare_captured_native_return,
};
use crate::program_semantics::native_body::{NativeBodyLanguage, NativeBodyOutcome};
use crate::program_semantics::native_callable::{
    NativeCallableLimitation as Limit, NativeCallableOutcome, VerifiedCallableLink,
};
use crate::project::EvaluationKey;
use crate::semantic_analysis::{NativeBooleanCallEvaluation, analyze_native_boolean_calls};
use crate::source_architecture::python_lexical::python_static_imports::UniquePythonModule;

/// Independently selected lexical Python subject. Initial support is a
/// zero-argument function in a uniquely admitted top-level source module.
#[derive(Clone, Copy)]
pub struct PythonCallableSelection<'a> {
    /// Exact module name under the independently selected scope.
    pub module: &'a str,
    /// Exact name of the top-level function declaration.
    pub function: &'a str,
}

/// Links one uniquely selected regular Python source module to an admitted body.
///
/// Both use the same complete physical view. The caller supervises the exact
/// external scalar worker. The result remains lexical and establishes no
/// runtime binding, execution, or assessment.
///
/// # Errors
/// Refuses malformed selection, untrusted replies, unsafe inputs, and physical
/// source drift. Unsupported modules, ambiguity and opaque bodies stay explicit.
pub fn observe_python_linked_callable(
    project_root: &Path,
    selected: PythonCallableSelection<'_>,
    scope: &PythonImportScope,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<NativeCallableOutcome, PythonObservationError> {
    let source = NativeSource::capture_for_dependencies(project_root, "Python")?;
    let (linked, _) = link_with_owner(&source, selected, scope, producer, false, exchange)?;
    source.revalidate()?;
    Ok(linked)
}

/// Observes an explicit original-authority Boolean requirement and exact Python body.
///
/// Both the authored document and the linked source are retained from the same
/// original physical capture. Runtime binding and execution remain unestablished.
///
/// # Errors
/// Refuses incomplete original governance, an incompatible reply, or source drift.
pub fn observe_python_authored_native_return(
    project_root: &Path,
    selected: PythonCallableSelection<'_>,
    scope: &PythonImportScope,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<AuthoredNativeReturnObservation, PythonObservationError> {
    let (source, linked, _) =
        observe_authored(project_root, selected, scope, producer, false, exchange)?;
    let result = compare_captured_native_return(&source, linked);
    source.revalidate()?;
    Ok(result)
}

/// Compare an original Python Boolean requirement using an exact local call closure.
///
/// # Errors
/// Refuses incomplete original governance, an incompatible reply, or source drift.
pub fn observe_python_authored_call_return(
    project_root: &Path,
    selected: PythonCallableSelection<'_>,
    scope: &PythonImportScope,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<AuthoredNativeCallReturnObservation, PythonObservationError> {
    let (source, linked, observed) =
        observe_authored(project_root, selected, scope, producer, true, exchange)?;
    let result = compare_captured_native_call_return(&source, linked, observed);
    source.revalidate()?;
    Ok(result)
}

fn observe_authored<'a>(
    project_root: &'a Path,
    selected: PythonCallableSelection<'_>,
    scope: &PythonImportScope,
    producer: &PythonScalarProducer,
    call_returns: bool,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<
    (
        NativeSource<'a>,
        NativeCallableOutcome,
        Option<NativeBooleanCallEvaluation>,
    ),
    PythonObservationError,
> {
    let source =
        NativeSource::capture_with(project_root, "Python", NativeAuthorityScope::AuthoredReturn)?;
    let (linked, observed) =
        link_with_owner(&source, selected, scope, producer, call_returns, exchange)?;
    Ok((source, linked, observed))
}

fn link_with_owner(
    source: &NativeSource<'_>,
    selected: PythonCallableSelection<'_>,
    scope: &PythonImportScope,
    producer: &PythonScalarProducer,
    call_returns: bool,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<(NativeCallableOutcome, Option<NativeBooleanCallEvaluation>), PythonObservationError> {
    let (mut result, observed) = link(source, selected, scope, producer, call_returns, exchange)?;
    if let NativeCallableOutcome::Linked(subject) = &mut result {
        let owner = source.original_declared_owner(subject.source_path())?;
        subject.record_original_owner(owner);
    }
    Ok((result, observed))
}

fn link(
    source: &NativeSource<'_>,
    selected: PythonCallableSelection<'_>,
    scope: &PythonImportScope,
    producer: &PythonScalarProducer,
    call_returns: bool,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<(NativeCallableOutcome, Option<NativeBooleanCallEvaluation>), PythonObservationError> {
    let origin = match scope.unique_regular_module(&source.view, selected.module)? {
        UniquePythonModule::File { path, source_ref } => (path, source_ref),
        UniquePythonModule::Missing => {
            return Ok((
                NativeCallableOutcome::Unavailable(Limit::MissingSubject),
                None,
            ));
        }
        UniquePythonModule::Ambiguous => {
            return Ok((
                NativeCallableOutcome::Unavailable(Limit::AmbiguousSubject),
                None,
            ));
        }
        UniquePythonModule::Unsupported => {
            return Ok((
                NativeCallableOutcome::Unavailable(Limit::UnsupportedScope),
                None,
            ));
        }
    };
    let subject = PythonScalarSubject {
        source_path: origin.0.into(),
        source_ref: origin.1,
        function: selected.function.into(),
        exact_bool_parameters: Vec::new(),
    };
    let context = serde_json_canonicalizer::to_vec(&(
        "fortress-python-lexical-callable-v1",
        scope.scope_ref(),
        source.view.digest(),
        selected.module,
        &subject,
        producer,
    ))
    .map_err(PythonScalarError::Json)?;
    let context_ref = sha256(&context);
    let evaluation = EvaluationKey::new(
        &source.binding.source_manifest_digest,
        &context_ref,
        &source.binding.authority_digest,
    );
    let request = bind_scalar_request(&source.view, &subject, producer, &evaluation)?;
    let request = if call_returns {
        request.into_lexical_calls()?
    } else {
        request
    };
    let reply = exchange(request.worker_payload(&source.view, &evaluation)?)?;
    let (outcome, observed) = if call_returns {
        let observed = request.admit_lexical_calls(&source.view, &evaluation, &reply)?;
        let value = match &observed.root {
            NativeBodyOutcome::Lowered(body) => {
                Some(analyze_native_boolean_calls(body, &observed.targets()?))
            }
            NativeBodyOutcome::Unavailable(_) => None,
        };
        (observed.root, value)
    } else {
        (request.admit(&source.view, &evaluation, &reply)?, None)
    };
    let NativeBodyOutcome::Lowered(body) = outcome else {
        return Ok((
            NativeCallableOutcome::Unavailable(Limit::BodyUnavailable),
            None,
        ));
    };
    let link = VerifiedCallableLink {
        language: NativeBodyLanguage::Python,
        namespace: selected.module,
        function: selected.function,
        source_path: &subject.source_path,
        source_ref: &subject.source_ref,
        origin_ref: &context_ref,
        exchange_ref: &sha256(&reply),
    };
    Ok((link.attach(evaluation, body), observed))
}
