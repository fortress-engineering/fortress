//! Explicit actual-state Python lexical observation owned by Snapshot Governance.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

use crate::affected_analysis::sha256;
use crate::native_observation::{NativeSource, NativeSourceError};
use crate::project::EvaluationKey;

pub use crate::source_architecture::python_lexical::{
    PYTHON_LEXICAL_WORKER, PythonGrammar, PythonLexicalError, PythonLexicalMode,
    PythonLexicalObservation, PythonLexicalOutcome, PythonLexicalProducer, PythonLexicalRequest,
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
    let request = PythonLexicalRequest::for_source(
        &source.view,
        &evaluation_key,
        source_path,
        mode,
        producer.clone(),
    )?;
    let selected = source
        .view
        .bytes(source_path)
        .ok_or(PythonLexicalError::MissingSource)?;
    let response = receive(&request, selected)?;
    let observation =
        PythonLexicalObservation::admit(&request, &source.view, &evaluation_key, &response)?;
    source.revalidate()?;
    Ok(ActualPythonLexicalObservation {
        evaluation_key,
        observation,
    })
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
        }
    }
}

impl Error for PythonObservationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Lexical(error) => Some(error),
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
