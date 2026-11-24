//! Exact physical bindings for explicitly selected Python project metadata.

use std::path::Path;

use serde::Serialize;

use crate::affected_analysis::sha256;
use crate::native_observation::{NativeSource, NativeSourceError};
use crate::observation::is_canonical_relative_path;
use crate::source_architecture::python_project_metadata::{
    PythonProjectMetadata, inspect_pyproject,
};

const SCHEMA: &str = "urn:fortress:derived:v1:python-project-metadata";
const FILE_NAME: &str = "pyproject.toml";
const MAX_SELECTED_PATH_BYTES: usize = 4096;

#[derive(Serialize)]
struct MetadataFile {
    path: String,
    sha256: String,
}

/// Static declarations and named metadata files in one exact observed source generation.
#[derive(Serialize)]
pub struct PythonProjectObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    scope: &'static str,
    source_fingerprint: String,
    source_view_digest: String,
    source_manifest_digest: String,
    authority_digest: String,
    manifest_path: String,
    manifest_sha256: Option<String>,
    metadata: PythonProjectMetadata,
    lock_files: Vec<MetadataFile>,
    environment_marker: Option<MetadataFile>,
    runtime_selection: &'static str,
}

/// Inability to produce an exact physical metadata observation.
#[derive(Debug)]
pub enum PythonProjectObservationError {
    /// The selected path was outside the portable pyproject.toml scope.
    InvalidManifestPath,
    /// The physical inventory or original project authority was unavailable.
    SourceUnavailable(String),
    /// The physical source or directory changed during inspection.
    SourceChanged,
}

impl std::fmt::Display for PythonProjectObservationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidManifestPath => {
                formatter.write_str("INVALID_PYTHON_PROJECT_MANIFEST_PATH")
            }
            Self::SourceUnavailable(detail) => {
                write!(formatter, "PYTHON_PROJECT_SOURCE_UNAVAILABLE: {detail}")
            }
            Self::SourceChanged => formatter.write_str("PYTHON_PROJECT_SOURCE_CHANGED"),
        }
    }
}

impl std::error::Error for PythonProjectObservationError {}

impl From<NativeSourceError> for PythonProjectObservationError {
    fn from(error: NativeSourceError) -> Self {
        match error {
            NativeSourceError::Unavailable(detail) => Self::SourceUnavailable(detail),
            NativeSourceError::Changed => Self::SourceChanged,
        }
    }
}

/// Describes source declarations without evaluating a build backend or selecting a runtime.
///
/// The selected manifest may be absent. Conventional sibling lock files and a
/// colocated .venv/pyvenv.cfg are reported only as exact ordinary source bytes.
/// No lock resolution, backend execution, runtime activation, or application
/// authority follows from the presence of a declaration or file.
///
/// # Errors
/// Refuses nonportable manifest paths, unavailable original governance or physical
/// observation, and a source change before publication.
pub fn observe_python_project_metadata(
    root: &Path,
    manifest_path: &str,
) -> Result<PythonProjectObservation, PythonProjectObservationError> {
    let manifest_directory = selected_directory(manifest_path)?;
    let source = NativeSource::capture(root, "Python")?;
    let bytes = source.view.bytes(manifest_path);
    let file = |name: &str| {
        let path = format!("{manifest_directory}{name}");
        source.view.bytes(&path).map(|bytes| MetadataFile {
            path,
            sha256: sha256(bytes),
        })
    };
    let observation = PythonProjectObservation {
        schema: SCHEMA,
        schema_version: 1,
        scope: "STATIC_DECLARATIONS_ONLY",
        source_fingerprint: source.binding.source_fingerprint.clone(),
        source_view_digest: source.view.digest().to_owned(),
        source_manifest_digest: source.binding.source_manifest_digest.clone(),
        authority_digest: source.binding.authority_digest.clone(),
        manifest_path: manifest_path.to_owned(),
        manifest_sha256: bytes.map(sha256),
        metadata: inspect_pyproject(bytes),
        lock_files: [
            "Pipfile.lock",
            "pdm.lock",
            "poetry.lock",
            "pylock.toml",
            "uv.lock",
        ]
        .into_iter()
        .filter_map(file)
        .collect(),
        environment_marker: file(".venv/pyvenv.cfg"),
        runtime_selection: "UNESTABLISHED",
    };
    source.revalidate()?;
    Ok(observation)
}

fn selected_directory(path: &str) -> Result<&str, PythonProjectObservationError> {
    path.strip_suffix(FILE_NAME)
        .filter(|directory| directory.is_empty() || directory.ends_with('/'))
        .filter(|_| path.len() <= MAX_SELECTED_PATH_BYTES && is_canonical_relative_path(path))
        .ok_or(PythonProjectObservationError::InvalidManifestPath)
}
