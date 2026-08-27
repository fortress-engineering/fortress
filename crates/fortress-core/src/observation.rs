//! Deterministic universal repository file observation.
//!
//! This module emits repository-relative observed facts. It does not infer or
//! ratify architecture, ownership, language semantics, or certification state.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, DirEntry, File};
use std::io::{self, BufReader, Read};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Current supported repository observation schema family.
pub const OBSERVATION_SCHEMA_VERSION: u16 = 1;

/// Explicit caller policy for repository paths omitted from observation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObservationPolicy {
    excluded_prefixes: Vec<String>,
}

impl ObservationPolicy {
    /// Creates a policy from canonical repository-relative prefixes.
    ///
    /// A prefix excludes the exact path and all descendants. Prefixes use
    /// forward slashes and may not be empty, absolute, dot-relative, or contain
    /// parent traversal.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationError::InvalidExcludedPrefix`] for an unsafe or
    /// non-canonical prefix.
    pub fn new<I, S>(prefixes: I) -> Result<Self, ObservationError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut excluded_prefixes: Vec<String> = prefixes.into_iter().map(Into::into).collect();
        for prefix in &excluded_prefixes {
            if !is_canonical_relative_path(prefix) {
                return Err(ObservationError::InvalidExcludedPrefix(
                    prefix.clone().into(),
                ));
            }
        }
        excluded_prefixes.sort_unstable();
        excluded_prefixes.dedup();
        Ok(Self { excluded_prefixes })
    }

    /// Returns canonical excluded prefixes in deterministic order.
    #[must_use]
    pub fn excluded_prefixes(&self) -> &[String] {
        &self.excluded_prefixes
    }

    fn excludes(&self, path: &str) -> bool {
        self.excluded_prefixes.iter().any(|prefix| {
            path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
    }
}

/// Deterministic facts observed from one repository file tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RepositoryObservation {
    schema_version: u16,
    knowledge_state: KnowledgeState,
    files: Vec<ObservedFile>,
}

impl RepositoryObservation {
    /// Returns the observation schema family.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the explicit knowledge state of all contained facts.
    #[must_use]
    pub const fn knowledge_state(&self) -> KnowledgeState {
        self.knowledge_state
    }

    /// Returns observed files in canonical path order.
    #[must_use]
    pub fn files(&self) -> &[ObservedFile] {
        &self.files
    }

    /// Serializes the observation as deterministic pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns the serialization error if the current data model cannot be
    /// represented as JSON.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Confidence/authority state assigned to repository observation facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KnowledgeState {
    /// Directly read from the supplied repository tree without ratification.
    Observed,
}

/// Content facts observed for one ordinary file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObservedFile {
    path: String,
    size: u64,
    sha256: String,
}

impl ObservedFile {
    /// Returns the canonical repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the number of bytes read from the file.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the lowercase content identity prefixed with `sha256:`.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Observes ordinary files beneath a repository root.
///
/// Output contains no absolute root, wall-clock time, or filesystem enumeration
/// order. Symbolic links are not followed.
///
/// # Errors
///
/// Returns [`ObservationError`] when the root is not a directory, a path cannot
/// be represented canonically, an unsupported entry is encountered, or a
/// filesystem read fails.
pub fn observe_repository(
    root: impl AsRef<Path>,
    policy: &ObservationPolicy,
) -> Result<RepositoryObservation, ObservationError> {
    let root = root.as_ref();
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| ObservationError::io("inspect root", root, source))?;
    if !metadata.file_type().is_dir() {
        return Err(ObservationError::RootNotDirectory(root.to_path_buf()));
    }

    let mut files = Vec::new();
    visit_directory(root, root, policy, &mut files)?;
    files.sort_unstable_by(|left, right| left.path.cmp(&right.path));

    Ok(RepositoryObservation {
        schema_version: OBSERVATION_SCHEMA_VERSION,
        knowledge_state: KnowledgeState::Observed,
        files,
    })
}

/// Explains why repository observation could not produce trustworthy facts.
#[derive(Debug)]
pub enum ObservationError {
    /// The supplied root is not an ordinary directory.
    RootNotDirectory(PathBuf),
    /// An exclusion prefix is unsafe or non-canonical.
    InvalidExcludedPrefix(Box<str>),
    /// A repository-relative path contains non-Unicode platform data.
    NonUnicodePath(PathBuf),
    /// A path escaped or failed to remain relative to the supplied root.
    PathOutsideRoot(PathBuf),
    /// A symbolic link or another unsupported filesystem entry was encountered.
    UnsupportedEntry(PathBuf),
    /// Byte counting exceeded the supported `u64` observation size.
    FileSizeOverflow(PathBuf),
    /// A filesystem operation failed.
    Io {
        /// Stable operation description.
        operation: &'static str,
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Operating-system error.
        source: io::Error,
    },
}

impl ObservationError {
    fn io(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl Display for ObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootNotDirectory(path) => {
                write!(
                    formatter,
                    "observation root is not a directory: {}",
                    path.display()
                )
            }
            Self::InvalidExcludedPrefix(prefix) => {
                write!(
                    formatter,
                    "excluded prefix `{prefix}` is not a canonical relative path"
                )
            }
            Self::NonUnicodePath(path) => {
                write!(
                    formatter,
                    "repository path is not valid Unicode: {}",
                    path.display()
                )
            }
            Self::PathOutsideRoot(path) => {
                write!(
                    formatter,
                    "repository path escaped the observation root: {}",
                    path.display()
                )
            }
            Self::UnsupportedEntry(path) => {
                write!(
                    formatter,
                    "repository entry type is unsupported: {}",
                    path.display()
                )
            }
            Self::FileSizeOverflow(path) => {
                write!(
                    formatter,
                    "observed file size exceeded u64: {}",
                    path.display()
                )
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "could not {operation} at {}: {source}",
                path.display()
            ),
        }
    }
}

impl Error for ObservationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn visit_directory(
    root: &Path,
    directory: &Path,
    policy: &ObservationPolicy,
    files: &mut Vec<ObservedFile>,
) -> Result<(), ObservationError> {
    let entries = fs::read_dir(directory)
        .map_err(|source| ObservationError::io("read directory", directory, source))?;
    let mut ordered_entries: Vec<(String, DirEntry)> = Vec::new();

    for entry in entries {
        let entry = entry
            .map_err(|source| ObservationError::io("read directory entry", directory, source))?;
        let relative_path = relative_path(root, &entry.path())?;
        ordered_entries.push((relative_path, entry));
    }
    ordered_entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    for (relative_path, entry) in ordered_entries {
        if policy.excludes(&relative_path) {
            continue;
        }
        let absolute_path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|source| ObservationError::io("inspect entry type", &absolute_path, source))?;
        if file_type.is_dir() {
            visit_directory(root, &absolute_path, policy, files)?;
        } else if file_type.is_file() {
            files.push(observe_file(relative_path, &absolute_path)?);
        } else {
            return Err(ObservationError::UnsupportedEntry(absolute_path));
        }
    }
    Ok(())
}

fn observe_file(
    relative_path: String,
    absolute_path: &Path,
) -> Result<ObservedFile, ObservationError> {
    let file = File::open(absolute_path)
        .map_err(|source| ObservationError::io("open file", absolute_path, source))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| ObservationError::io("read file", absolute_path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        let read = u64::try_from(read)
            .map_err(|_| ObservationError::FileSizeOverflow(absolute_path.to_path_buf()))?;
        size = size
            .checked_add(read)
            .ok_or_else(|| ObservationError::FileSizeOverflow(absolute_path.to_path_buf()))?;
    }

    Ok(ObservedFile {
        path: relative_path,
        size,
        sha256: format!("sha256:{:x}", hasher.finalize()),
    })
}

fn relative_path(root: &Path, path: &Path) -> Result<String, ObservationError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ObservationError::PathOutsideRoot(path.to_path_buf()))?;
    let mut segments = Vec::new();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(ObservationError::PathOutsideRoot(path.to_path_buf()));
        };
        let segment = segment
            .to_str()
            .ok_or_else(|| ObservationError::NonUnicodePath(path.to_path_buf()))?;
        segments.push(segment);
    }
    if segments.is_empty() {
        return Err(ObservationError::PathOutsideRoot(path.to_path_buf()));
    }
    Ok(segments.join("/"))
}

fn is_canonical_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && !value.starts_with('/')
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[cfg(test)]
mod tests {
    use super::{ObservationError, ObservationPolicy};

    /// `T-AF-REPOSITORY-OBSERVATION-0001-R02-001`
    #[test]
    fn exclusion_policy_rejects_parent_traversal() {
        let result = ObservationPolicy::new(["../outside"]);
        assert!(matches!(
            result,
            Err(ObservationError::InvalidExcludedPrefix(_))
        ));
    }

    /// `T-AF-REPOSITORY-OBSERVATION-0001-R02-002`
    #[test]
    fn exclusion_policy_is_sorted_and_deduplicated() {
        let policy = ObservationPolicy::new(["target", ".git", "target"])
            .expect("canonical exclusions are valid");
        assert_eq!(policy.excluded_prefixes(), [".git", "target"]);
    }
}
