//! Explicit actual-state Python lexical observation owned by Snapshot Governance.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

use crate::affected_analysis::sha256;
use crate::information_flow::{NativeScalarFlowObservation, observe_native_scalar_flow};
use crate::native_observation::{NativeSource, NativeSourceError};
pub use crate::program_semantics::native_body::NativeBodyOutcome;
use crate::project::EvaluationKey;
use crate::semantic_analysis::{SemanticDomain, infer_native_scalar_output};

pub use crate::program_semantics::python_scalar::{
    PythonScalarError, PythonScalarProducer, PythonScalarRequest,
};

pub use crate::source_architecture::python_lexical::{
    PYTHON_LEXICAL_WORKER, PYTHON_SCALAR_WORKER, PythonGrammar, PythonLexicalError,
    PythonLexicalMode, PythonLexicalObservation, PythonLexicalOutcome, PythonLexicalProducer,
    PythonLexicalRequest,
};

pub use crate::source_architecture::python_lexical::python_static_imports::{
    PythonImportScope, PythonStaticImportError, PythonStaticImportObservation,
};

#[path = "python_dependencies.rs"]
mod python_dependencies;
pub use python_dependencies::{
    ActualPythonStaticDependencyObservation, PythonStaticDependencyOutcome,
    observe_python_static_dependencies,
};

const PYTHON_LEXICAL_CONTEXT: &str = "fortress-python-lexical-context-v1";

/// A lexical observation bound to revalidated original physical source and authority.
///
/// Contents are compile-only observations. They do not enter the Program
/// Semantic Model or contribute to assessment, findings, or certification.
#[derive(Debug)]
pub struct ActualPythonLexicalObservation {
    evaluation_key: EvaluationKey,
    observation: PythonLexicalObservation,
}

impl ActualPythonLexicalObservation {
    /// Returns the exact manifest, scoped context and original authority identities.
    #[must_use]
    pub const fn evaluation_key(&self) -> &EvaluationKey {
        &self.evaluation_key
    }

    /// Returns the admitted bounded lexical observation.
    #[must_use]
    pub const fn observation(&self) -> &PythonLexicalObservation {
        &self.observation
    }
}

/// Observes one exact original source entry through an explicit trusted host.
///
/// The host independently verifies and supervises the selected compiler and
/// worker. It receives the immutable selected bytes and request binding. The
/// caller must return a response from that exact bounded exchange. The library
/// opens no process, imports no project code, and accepts no candidate view.
/// Publication rechecks all captured bytes and the native directory identity.
/// These checks do not establish a filesystem-wide lock against later writes.
///
/// # Errors
/// Refuses unavailable authority, unsafe or changed physical source, invalid
/// lexical replies, and failure of the explicitly selected host.
pub fn observe_python_lexical(
    project_root: &Path,
    source_path: &str,
    mode: PythonLexicalMode,
    producer: &PythonLexicalProducer,
    receive: impl FnOnce(&PythonLexicalRequest, &[u8]) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<ActualPythonLexicalObservation, PythonObservationError> {
    let source = NativeSource::capture(project_root, "Python")?;
    let context =
        serde_json_canonicalizer::to_vec(&(PYTHON_LEXICAL_CONTEXT, source_path, mode, producer))
            .map_err(PythonLexicalError::Encoding)?;
    let evaluation_key = EvaluationKey::new(
        &source.binding.source_manifest_digest,
        sha256(&context),
        &source.binding.authority_digest,
    );
    let observation = collect_lexical(
        &source,
        &evaluation_key,
        source_path,
        mode,
        producer,
        receive,
    )?;
    source.revalidate()?;
    Ok(ActualPythonLexicalObservation {
        evaluation_key,
        observation,
    })
}

fn collect_lexical(
    source: &NativeSource<'_>,
    evaluation: &EvaluationKey,
    source_path: &str,
    mode: PythonLexicalMode,
    producer: &PythonLexicalProducer,
    receive: impl FnOnce(&PythonLexicalRequest, &[u8]) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<PythonLexicalObservation, PythonObservationError> {
    let request = PythonLexicalRequest::for_source(
        &source.view,
        evaluation,
        source_path,
        mode,
        producer.clone(),
    )?;
    let selected = source
        .view
        .bytes(source_path)
        .ok_or(PythonLexicalError::MissingSource)?;
    let response = receive(&request, selected)?;
    Ok(PythonLexicalObservation::admit(
        &request,
        &source.view,
        evaluation,
        &response,
    )?)
}

/// Failure at the actual-state Python observation boundary.
#[derive(Debug)]
pub enum PythonObservationError {
    /// Physical source or the original governing inputs could not be captured.
    SourceUnavailable(String),
    /// The physical source or directory changed before publication.
    SourceChanged,
    /// The independently selected host could not complete the exchange.
    HostUnavailable,
    /// The lexical selection or reply failed bounded exact-source admission.
    Lexical(PythonLexicalError),
    /// The independent scoped import request or observation failed admission.
    StaticImports(PythonStaticImportError),
    /// The admitted native dependency evidence could not be bound to original inputs.
    StaticDependencies(crate::implementation_observation::NativeDependencyAdapterError),
    /// The selected source differs from the trusted exact subject.
    SubjectIdentityMismatch,
    /// The scoped scalar request or response failed admission.
    Scalar(PythonScalarError),
}

impl Display for PythonObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceUnavailable(detail) => formatter.write_str(detail),
            Self::SourceChanged => formatter
                .write_str("physical source or authority changed during Python observation"),
            Self::HostUnavailable => {
                formatter.write_str("trusted Python observation host is unavailable")
            }
            Self::Lexical(error) => Display::fmt(error, formatter),
            Self::StaticImports(error) => Display::fmt(error, formatter),
            Self::StaticDependencies(error) => Display::fmt(error, formatter),
            Self::SubjectIdentityMismatch => {
                formatter.write_str("selected Python source differs from the trusted subject pin")
            }
            Self::Scalar(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for PythonObservationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Lexical(error) => Some(error),
            Self::StaticImports(error) => Some(error),
            Self::StaticDependencies(error) => Some(error),
            Self::Scalar(error) => Some(error),
            _ => None,
        }
    }
}

impl From<NativeSourceError> for PythonObservationError {
    fn from(error: NativeSourceError) -> Self {
        match error {
            NativeSourceError::Unavailable(detail) => Self::SourceUnavailable(detail),
            NativeSourceError::Changed => Self::SourceChanged,
        }
    }
}

impl From<PythonLexicalError> for PythonObservationError {
    fn from(error: PythonLexicalError) -> Self {
        Self::Lexical(error)
    }
}

/// Exact actual-state lexical facts and static source-only lookup outcomes.
#[derive(Debug)]
pub struct ActualPythonStaticImportObservation {
    evaluation_key: EvaluationKey,
    lexical: PythonLexicalObservation,
    outcome: PythonStaticImportOutcome,
}

impl ActualPythonStaticImportObservation {
    /// Returns the complete physical source, selected profile and authority binding.
    #[must_use]
    pub const fn evaluation_key(&self) -> &EvaluationKey {
        &self.evaluation_key
    }

    /// Returns the compiler report even when static import lookup was unavailable.
    #[must_use]
    pub const fn lexical(&self) -> &PythonLexicalObservation {
        &self.lexical
    }

    /// Returns exact static import candidates or the limiting premise.
    #[must_use]
    pub const fn outcome(&self) -> &PythonStaticImportOutcome {
        &self.outcome
    }
}

/// Disposition of one explicit source-only Python import lookup.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PythonStaticImportOutcome {
    /// The lexical imports were evaluated in the bounded observed roots.
    Observed {
        /// The exact import observations and root and lexical provenance.
        observation: Box<PythonStaticImportObservation>,
    },
    /// A required compiler or inventory premise was unavailable.
    Unavailable {
        /// The scoped reason for abstaining from resolution.
        reason: PythonStaticImportLimitation,
    },
}

/// Unavailable static import lookup with retained preceding lexical evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PythonStaticImportLimitation {
    /// The lexical worker could not establish import occurrence facts.
    LexicalUnavailable,
    /// An independently selected root had no represented source inventory.
    RootUnavailable,
    /// A selected root included content outside the admitted file policy.
    UnsupportedRootContent,
    /// The selected root inventory had ambiguous supported path spellings.
    AmbiguousInventory,
    /// The bounded import evaluation exceeded its resource profile.
    ResourceLimit,
}

/// Observes static import candidates through the already trusted lexical host.
///
/// Root scope, producer, exact original manifest and original authority all
/// enter the context. This operation observes actual physical source and uses
/// the same compile-only lexical request. No synthetic candidate is selected.
/// Original physical inputs are revalidated after evaluation.
///
/// # Errors
/// Rejects stale original bindings, unsafe source, or invalid worker replies.
/// Compiler and scoped inventory limitations are retained in the observation.
pub fn observe_python_static_imports(
    project_root: &Path,
    source_path: &str,
    producer: &PythonLexicalProducer,
    scope: &PythonImportScope,
    receive: impl FnOnce(&PythonLexicalRequest, &[u8]) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<ActualPythonStaticImportObservation, PythonObservationError> {
    let source = NativeSource::capture(project_root, "Python")?;
    let result = collect_static_imports(&source, source_path, producer, scope, receive)?;
    source.revalidate()?;
    Ok(result)
}

fn collect_static_imports(
    source: &NativeSource<'_>,
    source_path: &str,
    producer: &PythonLexicalProducer,
    scope: &PythonImportScope,
    receive: impl FnOnce(&PythonLexicalRequest, &[u8]) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<ActualPythonStaticImportObservation, PythonObservationError> {
    let context = serde_json_canonicalizer::to_vec(&(
        "fortress-python-static-import-context-v1",
        source_path,
        producer,
        scope.scope_ref(),
    ))
    .map_err(PythonLexicalError::Encoding)?;
    let evaluation_key = EvaluationKey::new(
        &source.binding.source_manifest_digest,
        sha256(&context),
        &source.binding.authority_digest,
    );
    let roots = scope.bind(&source.view, &evaluation_key)?;
    let lexical = collect_lexical(
        source,
        &evaluation_key,
        source_path,
        PythonLexicalMode::Lexical,
        producer,
        receive,
    )?;
    let outcome = match PythonStaticImportObservation::evaluate(
        &lexical,
        &source.view,
        &evaluation_key,
        &roots,
    ) {
        Ok(observation) => PythonStaticImportOutcome::Observed {
            observation: Box::new(observation),
        },
        Err(error) => PythonStaticImportOutcome::Unavailable {
            reason: scoped_import_limitation(error)?,
        },
    };
    Ok(ActualPythonStaticImportObservation {
        evaluation_key,
        lexical,
        outcome,
    })
}

fn scoped_import_limitation(
    error: PythonStaticImportError,
) -> Result<PythonStaticImportLimitation, PythonObservationError> {
    Ok(match error {
        PythonStaticImportError::LexicalUnavailable => {
            PythonStaticImportLimitation::LexicalUnavailable
        }
        PythonStaticImportError::RootUnavailable => PythonStaticImportLimitation::RootUnavailable,
        PythonStaticImportError::UnsupportedRootContent => {
            PythonStaticImportLimitation::UnsupportedRootContent
        }
        PythonStaticImportError::AmbiguousInventory => {
            PythonStaticImportLimitation::AmbiguousInventory
        }
        PythonStaticImportError::ResourceLimit => PythonStaticImportLimitation::ResourceLimit,
        other => return Err(other.into()),
    })
}

impl From<PythonStaticImportError> for PythonObservationError {
    fn from(error: PythonStaticImportError) -> Self {
        Self::StaticImports(error)
    }
}

/// Independently selected exact subject and scalar input assumptions.
///
/// A trusted caller selects these premises outside subject repository content.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct PythonScalarSubject {
    /// Canonical physical source path relative to the selected repository.
    pub source_path: String,
    /// Expected SHA-256 of the exact selected subject bytes.
    pub source_ref: String,
    /// Selected function name.
    pub function: String,
    /// Exact boolean parameter names in declaration order.
    pub exact_bool_parameters: Vec<String>,
}

/// A scoped native body and optional conservative output bound at an actual state.
#[derive(Debug)]
pub struct ActualPythonScalarObservation {
    evaluation_key: EvaluationKey,
    request: PythonScalarRequest,
    outcome: NativeBodyOutcome,
    inferred_output: Option<SemanticDomain>,
}

impl ActualPythonScalarObservation {
    /// Returns the exact source, independent context, and original authority identities.
    #[must_use]
    pub const fn evaluation_key(&self) -> &EvaluationKey {
        &self.evaluation_key
    }

    /// Returns the exact source and producer exchange binding.
    #[must_use]
    pub const fn request(&self) -> &PythonScalarRequest {
        &self.request
    }

    /// Returns the admitted body or supported limitation.
    #[must_use]
    pub const fn outcome(&self) -> &NativeBodyOutcome {
        &self.outcome
    }

    /// Returns an upper bound under the selected scalar premises, when available.
    #[must_use]
    pub const fn inferred_output(&self) -> Option<&SemanticDomain> {
        self.inferred_output.as_ref()
    }
}

/// Observes an exact physical Python source through an independently trusted host.
///
/// The provided exchange receives one bounded worker request. Program Semantics
/// admits typed body facts. Semantic Analysis may infer an output bound under
/// the selected premises. Original physical inputs are revalidated after both.
///
/// # Errors
/// Refuses wrong source pins, unavailable authority, stale physical source,
/// untrusted host operations, and incompatible worker output.
pub fn observe_python_scalar(
    project_root: &Path,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<ActualPythonScalarObservation, PythonObservationError> {
    observe_scalar_with(project_root, subject, producer, exchange, |_| ())
        .map(|(observation, ())| observation)
}

/// Observes scoped direct data movement for the exact admitted Python scalar subject.
///
/// The independently selected subject, host and compile-only profile retain
/// their original bindings. Physical source is revalidated after projection.
///
/// # Errors
/// Refuses unavailable authority, stale physical source or incompatible worker output.
pub fn observe_python_scalar_flow(
    project_root: &Path,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<(ActualPythonScalarObservation, NativeScalarFlowObservation), PythonObservationError> {
    observe_scalar_with(
        project_root,
        subject,
        producer,
        exchange,
        observe_native_scalar_flow,
    )
}

fn observe_scalar_with<T>(
    project_root: &Path,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
    project: impl FnOnce(&NativeBodyOutcome) -> T,
) -> Result<(ActualPythonScalarObservation, T), PythonObservationError> {
    let source = NativeSource::capture(project_root, "Python")?;
    let context =
        serde_json_canonicalizer::to_vec(&("fortress-python-scalar-context-v1", subject, producer))
            .map_err(PythonScalarError::Json)?;
    let evaluation_key = EvaluationKey::new(
        &source.binding.source_manifest_digest,
        sha256(&context),
        &source.binding.authority_digest,
    );
    let parameters = subject
        .exact_bool_parameters
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let request = PythonScalarRequest::bind(
        &source.view,
        &evaluation_key,
        &subject.source_path,
        &subject.function,
        &parameters,
        producer,
    )?;
    if request.source_ref() != subject.source_ref {
        return Err(PythonObservationError::SubjectIdentityMismatch);
    }
    let payload = request.worker_payload(&source.view, &evaluation_key)?;
    let response = exchange(payload)?;
    let outcome = request.admit(&source.view, &evaluation_key, &response)?;
    let inferred_output = match &outcome {
        NativeBodyOutcome::Lowered(body) => infer_native_scalar_output(body),
        NativeBodyOutcome::Unavailable(_) => None,
    };
    let projected = project(&outcome);
    source.revalidate()?;
    Ok((
        ActualPythonScalarObservation {
            evaluation_key,
            request,
            outcome,
            inferred_output,
        },
        projected,
    ))
}

impl From<PythonScalarError> for PythonObservationError {
    fn from(error: PythonScalarError) -> Self {
        Self::Scalar(error)
    }
}
