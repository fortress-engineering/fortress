//! Explicit actual-state Python lexical observation owned by Snapshot Governance.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

use crate::affected_analysis::sha256;
use crate::audit::NativeAuthorityScope;
use crate::audit::NativeObservationBinding;
use crate::candidate::{
    CandidateWorkspace, HypotheticalNativeBodyInspection, NativeCandidateBody,
    NativeCandidateCalls, NativeCandidateSelection, NativeCandidateSubject,
    inspect_hypothetical_native_body, inspect_hypothetical_native_call_boundaries,
    inspect_hypothetical_native_calls, native_error,
};
use crate::information_flow::{NativeScalarFlowObservation, observe_native_scalar_flow};
use crate::migration_governance::MigrationError;
use crate::native_observation::{
    NativeOwnershipProjectionKind, NativeSource, NativeSourceError, project_native_call_ownership,
    project_native_call_sensitivity, project_native_call_topology,
};
use crate::observation::SourceView;
pub use crate::program_semantics::native_body::NativeBodyOutcome;
use crate::program_semantics::native_body::{NativeCallTopology, inspect_native_call_topology};
use crate::program_semantics::python_scalar::PythonLexicalCalls;
pub use crate::program_semantics::python_scalar::python_filesystem::{
    PythonFilesystemError, PythonFilesystemOutcome, PythonFilesystemProfile,
    PythonFilesystemRequest, PythonInstalledFilesystemReceiver,
};
use crate::project::EvaluationKey;
use crate::semantic_analysis::{
    NativeBooleanSensitivity, SemanticDomain, analyze_native_boolean_calls,
    infer_native_scalar_output, inspect_native_boolean_sensitivity,
};

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
    observe_python_static_dependencies, observe_python_static_dependency_intent,
};

#[path = "python_callable.rs"]
mod callable;
pub use callable::{
    PythonCallableSelection, observe_python_authored_call_return,
    observe_python_authored_native_return, observe_python_linked_callable,
};

#[path = "python_fs_observation.rs"]
mod filesystem;
pub use crate::source_architecture::python_lexical::PYTHON_FILESYSTEM_WORKER;
pub use filesystem::{
    HypotheticalPythonFilesystemObservation, HypotheticalPythonFilesystemPolicyObservation,
    PYTHON_ORIGIN_WORKER, PythonFilesystemHost, observe_hypothetical_python_filesystem,
    observe_hypothetical_python_filesystem_policy, python_filesystem_origin_manifest,
};

/// Registered schema for declaration-only Python test observations.
pub const PYTHON_TEST_OBSERVATION_SCHEMA: &str =
    include_str!("../_data/python_test_schema_v1.json");

/// Registered schema for source-bound Python filesystem observations.
pub const PYTHON_FILESYSTEM_OBSERVATION_SCHEMA: &str =
    include_str!("../_data/python_fs_schema_v1.json");

/// Registered schema for the separately scoped Python filesystem policy view.
pub const PYTHON_FILESYSTEM_POLICY_SCHEMA: &str = include_str!("../_data/python_fs_policy_v1.json");

const PYTHON_LEXICAL_CONTEXT: &str = "fortress-python-lexical-context-v1";

#[path = "python_test_observation.rs"]
mod test_observation;
pub use test_observation::{ActualPythonTestObservation, observe_python_tests};

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
    /// Exact scoped filesystem worker request or reply failed admission.
    Filesystem(PythonFilesystemError),
    /// The admitted hypothetical operation could not enter the scoped catalog.
    FilesystemEffect(crate::state_effect_analysis::NativeFilesystemError),
    /// A bounded hypothetical effect report could not be serialized.
    FilesystemJson(serde_json::Error),
    /// The scoped effect context could not be represented canonically.
    FilesystemCanonical(crate::portable::PortableError),
    /// Test roots are unsafe, overlap, or select an ordinary file.
    InvalidTestRoots,
    /// The selected test scope exceeds its pre-dispatch resource budget.
    TestScopeLimit,
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
            Self::Filesystem(error) => Display::fmt(error, formatter),
            Self::FilesystemEffect(error) => Display::fmt(error, formatter),
            Self::FilesystemJson(error) => Display::fmt(error, formatter),
            Self::FilesystemCanonical(error) => Display::fmt(error, formatter),
            Self::InvalidTestRoots => formatter.write_str(
                "Python test roots must be distinct, nonoverlapping canonical directories",
            ),
            Self::TestScopeLimit => {
                formatter.write_str("Python test declaration scope exceeds its bounded inventory")
            }
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
            Self::Filesystem(error) => Some(error),
            Self::FilesystemEffect(error) => Some(error),
            Self::FilesystemJson(error) => Some(error),
            Self::FilesystemCanonical(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PythonFilesystemError> for PythonObservationError {
    fn from(error: PythonFilesystemError) -> Self {
        Self::Filesystem(error)
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

/// Compares finite Boolean returns for the exact original Python scalar subject.
///
/// The inputs are the exact ordered Boolean parameters selected by the trusted
/// host. The comparison describes the admitted compile-only model. Physical
/// source is revalidated after interpreting the selected body.
///
/// # Errors
/// Refuses unavailable original bindings, source drift, or incompatible replies.
pub fn observe_python_scalar_sensitivity(
    project_root: &Path,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<
    (
        ActualPythonScalarObservation,
        Option<NativeBooleanSensitivity>,
    ),
    PythonObservationError,
> {
    observe_scalar_with(
        project_root,
        subject,
        producer,
        exchange,
        |outcome| match outcome {
            NativeBodyOutcome::Lowered(body) => Some(inspect_native_boolean_sensitivity(body)),
            NativeBodyOutcome::Unavailable(_) => None,
        },
    )
}

/// Composes exact local Python calls in the compile-only Boolean model.
///
/// The trusted host selects the exact source and ordered root argument premises.
/// The admitted closure has deterministic local bindings and no captured values.
/// Revalidates the complete original source and selected authority after analysis.
///
/// # Errors
/// Refuses source drift, unresolved authority and incompatible host replies.
pub fn observe_python_native_call_return(
    project_root: &Path,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<serde_json::Value, PythonObservationError> {
    let source = NativeSource::capture(project_root, "Python")?;
    let (evaluation_key, request, response_ref, observation) =
        inspect_lexical_calls(&source.view, &source.binding, subject, producer, exchange)?;
    let targets = observation.targets()?;
    let (evaluation, diagnostic, calls) = match &observation.root {
        NativeBodyOutcome::Lowered(body) => (
            Some(analyze_native_boolean_calls(body, &targets)),
            None,
            body.bound_calls(),
        ),
        NativeBodyOutcome::Unavailable(limitation) => (
            None,
            Some(serde_json::json!({"code":limitation.code(), "location":limitation.location()})),
            &[][..],
        ),
    };
    source.revalidate()?;
    Ok(serde_json::json!({
        "$schema":"urn:fortress:derived:v1:python-native-call-return",
        "schema_version":1,
        "scope":"BOUNDED_LEXICAL_BOOLEAN_CALL_RETURN",
        "target_execution":"NOT_RUN",
        "evaluation_key":evaluation_key,
        "exchange_sha256":request.exchange_ref(),
        "response_sha256":response_ref,
        "source_path":subject.source_path,
        "source_ref":request.source_ref(),
        "producer":producer,
        "calls":calls,
        "evaluation":evaluation,
        "diagnostic":diagnostic,
    }))
}

/// Compares paired Boolean inputs across an exact supported Python lexical closure.
///
/// The result concerns returned values under the selected premises. It retains
/// the modeled dependency occurrences and does not establish runtime binding.
///
/// # Errors
/// Refuses stale source, unresolved authority and incompatible host replies.
pub fn observe_python_native_call_sensitivity(
    project_root: &Path,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<serde_json::Value, PythonObservationError> {
    let source = NativeSource::capture(project_root, "Python")?;
    let (evaluation_key, request, response_ref, observation) =
        inspect_lexical_calls(&source.view, &source.binding, subject, producer, exchange)?;
    let sensitivity = match &observation.root {
        NativeBodyOutcome::Lowered(body) => serde_json::json!(
            analyze_native_boolean_calls(body, &observation.targets()?).into_sensitivity()
        ),
        NativeBodyOutcome::Unavailable(limitation) => serde_json::json!({
            "status": "UNAVAILABLE",
            "occurrence": null,
            "reason": limitation.code(),
        }),
    };
    source.revalidate()?;
    Ok(project_native_call_sensitivity(
        "python",
        &serde_json::json!({
            "evaluation_key": evaluation_key,
            "exchange_sha256": request.exchange_ref(),
            "response_sha256": response_ref,
            "source_path": subject.source_path,
            "source_ref": request.source_ref(),
            "producer": producer,
        }),
        &sensitivity,
    ))
}

/// Inspects exact local Python call topology from the pinned lexical worker.
///
/// A declaration reported as unavailable remains explicit. The graph records
/// only its admitted static edges in the captured lexical scope.
///
/// # Errors
/// Refuses stale source, unresolved authority and incompatible host replies.
pub fn observe_python_native_call_topology(
    project_root: &Path,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<serde_json::Value, PythonObservationError> {
    let source = NativeSource::capture(project_root, "Python")?;
    let (evaluation_key, request, response_ref, observation) =
        inspect_lexical_calls(&source.view, &source.binding, subject, producer, exchange)?;
    let graph = match &observation.root {
        NativeBodyOutcome::Lowered(body) => {
            inspect_native_call_topology(body, &observation.targets()?)
        }
        NativeBodyOutcome::Unavailable(limitation) => {
            NativeCallTopology::unavailable(None, limitation.code())
        }
    };
    source.revalidate()?;
    Ok(project_native_call_topology(
        "python",
        &serde_json::json!({
            "evaluation_key": evaluation_key,
            "exchange_sha256": request.exchange_ref(),
            "response_sha256": response_ref,
            "source_path": subject.source_path,
            "source_ref": request.source_ref(),
            "producer": producer,
        }),
        &graph,
    ))
}

/// Reconciles exact Python lexical call sites with captured original logical
/// Module ownership and the original CCG.
///
/// The supported lexical worker resolves local declarations. The result retains
/// their physical provenance and leaves runtime binding unestablished.
///
/// # Errors
/// Refuses stale source or authority and incompatible host replies.
pub fn observe_python_native_call_module_boundaries(
    project_root: &Path,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<serde_json::Value, PythonObservationError> {
    let source = NativeSource::capture_with(
        project_root,
        "Python",
        NativeAuthorityScope::DependenciesWithIntent,
    )?;
    let (evaluation_key, request, response_ref, observation) =
        inspect_lexical_calls(&source.view, &source.binding, subject, producer, exchange)?;
    let graph = match &observation.root {
        NativeBodyOutcome::Lowered(body) => {
            inspect_native_call_topology(body, &observation.targets()?)
        }
        NativeBodyOutcome::Unavailable(limitation) => {
            NativeCallTopology::unavailable(None, limitation.code())
        }
    };
    let report = project_native_call_ownership(
        &source.view,
        &source.binding,
        &source.binding,
        NativeOwnershipProjectionKind::Actual,
        "python",
        &serde_json::json!({
            "evaluation_key": evaluation_key,
            "exchange_sha256": request.exchange_ref(),
            "response_sha256": response_ref,
            "source_path": subject.source_path,
            "source_ref": request.source_ref(),
            "producer": producer,
        }),
        &graph,
    )?;
    source.revalidate()?;
    Ok(report)
}

/// Compose source-bound Python lexical calls in a retained candidate.
///
/// Reads the already admitted proposal through immutable source views.
///
/// # Errors
/// Refuses stale or cancelled candidates, unsafe inputs, and mismatched native receipts.
pub fn observe_python_candidate_call_return(
    workspace: &CandidateWorkspace,
    retained: NativeCandidateSelection<'_>,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<HypotheticalNativeBodyInspection, MigrationError> {
    let selected = NativeCandidateSubject {
        source_path: &subject.source_path,
        source_ref: &subject.source_ref,
        function: &subject.function,
    };
    inspect_hypothetical_native_calls(workspace, retained, selected, "python", |view, binding| {
        let (evaluation_key, _, response_ref, observation) =
            inspect_lexical_calls(view, binding, subject, producer, exchange)
                .map_err(native_error)?;
        let targets = observation.targets().map_err(native_error)?;
        let (result, limitation) = match &observation.root {
            NativeBodyOutcome::Lowered(body) => {
                (Some(analyze_native_boolean_calls(body, &targets)), None)
            }
            NativeBodyOutcome::Unavailable(diagnostic) => (None, Some(diagnostic.code().into())),
        };
        Ok(NativeCandidateCalls {
            evaluation_key,
            response_ref,
            result,
            limitation,
        })
    })
}

/// Evaluates exact local Python lexical call dependencies in a retained candidate.
/// The projection carries original dependency intent and exact postimage observations.
///
/// # Errors
/// Refuses stale or cancelled candidates, unsafe inputs, and mismatched native replies.
pub fn observe_python_candidate_call_module_boundaries(
    workspace: &CandidateWorkspace,
    retained: NativeCandidateSelection<'_>,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<HypotheticalNativeBodyInspection, MigrationError> {
    let selected = NativeCandidateSubject {
        source_path: &subject.source_path,
        source_ref: &subject.source_ref,
        function: &subject.function,
    };
    inspect_hypothetical_native_call_boundaries(
        workspace,
        retained,
        selected,
        "python",
        |view, original, candidate| {
            let (evaluation_key, request, response_ref, observation) =
                inspect_lexical_calls(view, candidate, subject, producer, exchange)
                    .map_err(native_error)?;
            let graph = match &observation.root {
                NativeBodyOutcome::Lowered(body) => inspect_native_call_topology(
                    body,
                    &observation.targets().map_err(native_error)?,
                ),
                NativeBodyOutcome::Unavailable(diagnostic) => {
                    NativeCallTopology::unavailable(None, diagnostic.code())
                }
            };
            let evidence = serde_json::json!({
                "evaluation_key": evaluation_key,
                "exchange_sha256": request.exchange_ref(),
                "response_sha256": response_ref,
                "source_path": subject.source_path,
                "source_ref": request.source_ref(),
                "producer": producer,
            });
            project_native_call_ownership(
                view,
                candidate,
                original,
                NativeOwnershipProjectionKind::Hypothetical,
                "python",
                &evidence,
                &graph,
            )
            .map_err(|failure| native_error(PythonObservationError::from(failure)))
        },
    )
}

fn inspect_lexical_calls(
    view: &SourceView,
    binding: &NativeObservationBinding,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<
    (
        EvaluationKey,
        PythonScalarRequest,
        String,
        PythonLexicalCalls,
    ),
    PythonObservationError,
> {
    let context = serde_json_canonicalizer::to_vec(&(
        "fortress-python-lexical-call-context-v1",
        subject,
        producer,
    ))
    .map_err(PythonScalarError::Json)?;
    let evaluation_key = EvaluationKey::new(
        &binding.source_manifest_digest,
        sha256(&context),
        &binding.authority_digest,
    );
    let request =
        bind_scalar_request(view, subject, producer, &evaluation_key)?.into_lexical_calls()?;
    let response = exchange(request.worker_payload(view, &evaluation_key)?)?;
    let observation = request.admit_lexical_calls(view, &evaluation_key, &response)?;
    Ok((evaluation_key, request, sha256(&response), observation))
}

/// Inspects an exact Python postimage from a retained unapplied candidate.
///
/// The compile-only worker uses the independently selected argument model.
/// Original authority and the candidate context remain separately recorded.
///
/// # Errors
/// Refuses missing, stale or cancelled candidates and incompatible native replies.
pub fn observe_python_candidate_sensitivity(
    workspace: &CandidateWorkspace,
    retained: NativeCandidateSelection<'_>,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<HypotheticalNativeBodyInspection, MigrationError> {
    let selection = NativeCandidateSubject {
        source_path: &subject.source_path,
        source_ref: &subject.source_ref,
        function: &subject.function,
    };
    inspect_hypothetical_native_body(
        workspace,
        retained,
        selection,
        "python",
        |view, binding, proposal| {
            let context = serde_json_canonicalizer::to_vec(&(
                "fortress-python-candidate-scalar-context-v1",
                proposal.evaluation_ref(),
                proposal.context_ref(),
                subject,
                producer,
            ))
            .map_err(native_error)?;
            let key = EvaluationKey::new(
                &binding.source_manifest_digest,
                sha256(&context),
                &binding.authority_digest,
            );
            let request =
                bind_scalar_request(view, subject, producer, &key).map_err(native_error)?;
            let payload = request.worker_payload(view, &key).map_err(native_error)?;
            let response = exchange(payload).map_err(native_error)?;
            let outcome = request.admit(view, &key, &response).map_err(native_error)?;
            let body = match &outcome {
                NativeBodyOutcome::Lowered(body) => Some(body),
                NativeBodyOutcome::Unavailable(_) => None,
            };
            Ok(NativeCandidateBody::analyzed(
                key,
                sha256(&response),
                body.map(Box::as_ref),
            ))
        },
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
    let request = bind_scalar_request(&source.view, subject, producer, &evaluation_key)?;
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

fn bind_scalar_request(
    source: &SourceView,
    subject: &PythonScalarSubject,
    producer: &PythonScalarProducer,
    evaluation_key: &EvaluationKey,
) -> Result<PythonScalarRequest, PythonObservationError> {
    let parameters = subject
        .exact_bool_parameters
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let request = PythonScalarRequest::bind(
        source,
        evaluation_key,
        &subject.source_path,
        &subject.function,
        &parameters,
        producer,
    )?;
    if request.source_ref() != subject.source_ref {
        return Err(PythonObservationError::SubjectIdentityMismatch);
    }
    Ok(request)
}

impl From<PythonScalarError> for PythonObservationError {
    fn from(error: PythonScalarError) -> Self {
        Self::Scalar(error)
    }
}
