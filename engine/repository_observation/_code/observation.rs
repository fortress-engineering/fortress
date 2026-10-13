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

#[path = "input_retention.rs"]
pub(crate) mod input_retention;
#[path = "source_manifest.rs"]
mod source_manifest;
#[path = "source_view.rs"]
mod source_view;

pub use source_manifest::{SourceEntry, SourceExclusion, SourceManifest, observe_source_manifest};
pub use source_view::{CandidateChangeSet, ChangeOperation, SourceView, SourceViewError};

/// Current supported repository observation schema family.
pub const OBSERVATION_SCHEMA_VERSION: u16 = 1;

/// Operational admission quotas for one repository observation pass.
///
/// These quotas constrain retained inventory and bytes read without changing
/// the successful observation facts. Excluded directory descendants are never
/// visited; their directory entry still counts toward entry and path quotas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationLimits {
    /// Maximum number of included ordinary files.
    pub max_files: usize,
    /// Maximum number of enumerated descendant entries, including directories.
    pub max_entries: usize,
    /// Maximum total content bytes across included files.
    pub max_source_bytes: u64,
    /// Maximum total UTF-8 bytes of enumerated repository-relative paths.
    pub max_path_bytes: usize,
}

/// Explicit caller policy for repository paths omitted from observation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
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
        path == ".git"
            || path.starts_with(".git/")
            || self.excluded_prefixes.iter().any(|prefix| {
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
    /// Projects an immutable supplied byte inventory into canonical content facts.
    ///
    /// This performs no filesystem discovery. The caller retains whether the
    /// supplied inventory represents actual or hypothetical source bytes.
    pub(crate) fn from_source_view(
        view: &SourceView,
        policy: &ObservationPolicy,
    ) -> Result<Self, ObservationError> {
        let mut files = Vec::new();
        for (path, bytes) in view {
            if policy.excludes(path) {
                continue;
            }
            let size = u64::try_from(bytes.len())
                .map_err(|_| ObservationError::FileSizeOverflow(path.into()))?;
            files.push(ObservedFile {
                path: path.clone(),
                size,
                sha256: format!("sha256:{:x}", Sha256::digest(bytes)),
            });
        }
        Ok(Self {
            schema_version: OBSERVATION_SCHEMA_VERSION,
            knowledge_state: KnowledgeState::Observed,
            files,
        })
    }

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

/// Observes the same ordinary file facts with preallocation admission quotas.
///
/// Entry and path quotas apply before retaining each enumeration entry. File
/// metadata is checked before content hashing, and content growth during reads
/// cannot exceed the byte quota. Traversal uses bounded explicit frames rather
/// than a recursive directory stack. The root itself is not a descendant entry.
///
/// # Errors
///
/// Returns the ordinary observation errors, or
/// [`ObservationError::ResourceLimit`] without a partial observation when an
/// admission quota would be exceeded.
pub fn observe_repository_bounded(
    root: impl AsRef<Path>,
    policy: &ObservationPolicy,
    limits: &ObservationLimits,
) -> Result<RepositoryObservation, ObservationError> {
    let root = root.as_ref();
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| ObservationError::io("inspect root", root, source))?;
    if !metadata.file_type().is_dir() {
        return Err(ObservationError::RootNotDirectory(root.to_path_buf()));
    }
    let mut budget = ObservationBudget::new(limits);
    let mut frames = vec![bounded_directory_entries(root, root, &mut budget)?.into_iter()];
    let mut files = Vec::new();
    while let Some(frame) = frames.last_mut() {
        let Some((relative, entry)) = frame.next() else {
            frames.pop();
            continue;
        };
        if policy.excludes(&relative) {
            continue;
        }
        let absolute = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|source| ObservationError::io("inspect entry type", &absolute, source))?;
        if file_type.is_dir() {
            frames.push(bounded_directory_entries(root, &absolute, &mut budget)?.into_iter());
        } else if file_type.is_file() {
            admit_inventory("files", &mut budget.files, limits.max_files, 1)?;
            let file = observe_file_with_limit(
                relative,
                &absolute,
                Some((budget.source_bytes, limits.max_source_bytes)),
            )?;
            budget.source_bytes += file.size;
            files.push(file);
        } else {
            return Err(ObservationError::UnsupportedEntry(absolute));
        }
    }
    files.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    Ok(RepositoryObservation {
        schema_version: OBSERVATION_SCHEMA_VERSION,
        knowledge_state: KnowledgeState::Observed,
        files,
    })
}

struct ObservationBudget<'a> {
    limits: &'a ObservationLimits,
    entries: usize,
    path_bytes: usize,
    files: usize,
    source_bytes: u64,
}

impl<'a> ObservationBudget<'a> {
    const fn new(limits: &'a ObservationLimits) -> Self {
        Self {
            limits,
            entries: 0,
            path_bytes: 0,
            files: 0,
            source_bytes: 0,
        }
    }
}

fn admit_inventory(
    resource: &'static str,
    used: &mut usize,
    maximum: usize,
    amount: usize,
) -> Result<(), ObservationError> {
    let observed = used
        .checked_add(amount)
        .ok_or(ObservationError::ResourceLimit {
            resource,
            maximum: u64::try_from(maximum).unwrap_or(u64::MAX),
            observed: u64::MAX,
        })?;
    if observed > maximum {
        return Err(ObservationError::ResourceLimit {
            resource,
            maximum: u64::try_from(maximum).unwrap_or(u64::MAX),
            observed: u64::try_from(observed).unwrap_or(u64::MAX),
        });
    }
    *used = observed;
    Ok(())
}

fn bounded_directory_entries(
    root: &Path,
    directory: &Path,
    budget: &mut ObservationBudget<'_>,
) -> Result<Vec<(String, DirEntry)>, ObservationError> {
    let entries = fs::read_dir(directory)
        .map_err(|source| ObservationError::io("read directory", directory, source))?;
    let mut ordered = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|source| ObservationError::io("read directory entry", directory, source))?;
        admit_inventory("entries", &mut budget.entries, budget.limits.max_entries, 1)?;
        let filename = entry.file_name();
        let filename = filename
            .to_str()
            .ok_or_else(|| ObservationError::NonUnicodePath(entry.path()))?;
        let parent_bytes = if directory == root {
            0
        } else {
            relative_path_bytes(root, directory)?
        };
        let path_bytes = parent_bytes
            .saturating_add(usize::from(parent_bytes != 0))
            .saturating_add(filename.len());
        admit_inventory(
            "path_bytes",
            &mut budget.path_bytes,
            budget.limits.max_path_bytes,
            path_bytes,
        )?;
        let absolute = entry.path();
        ordered.push((relative_path(root, &absolute)?, entry));
    }
    ordered.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(ordered)
}

fn relative_path_bytes(root: &Path, path: &Path) -> Result<usize, ObservationError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ObservationError::PathOutsideRoot(path.to_path_buf()))?;
    let mut bytes = 0_usize;
    let mut count = 0_usize;
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(ObservationError::PathOutsideRoot(path.to_path_buf()));
        };
        let segment = segment
            .to_str()
            .ok_or_else(|| ObservationError::NonUnicodePath(path.to_path_buf()))?;
        bytes = bytes
            .saturating_add(segment.len())
            .saturating_add(usize::from(count != 0));
        count += 1;
    }
    if count == 0 {
        return Err(ObservationError::PathOutsideRoot(path.to_path_buf()));
    }
    Ok(bytes)
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
    /// An operational quota prevented a complete observation.
    ResourceLimit {
        /// Stable quota name: `files`, `entries`, `source_bytes`, or `path_bytes`.
        resource: &'static str,
        /// Configured maximum for this observation pass.
        maximum: u64,
        /// Requested total, or `u64::MAX` if counting overflowed.
        observed: u64,
    },
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
            Self::ResourceLimit {
                resource,
                maximum,
                observed,
            } => write!(
                formatter,
                "observation {resource} quota exceeded: {observed} requested, maximum {maximum}"
            ),
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
    observe_file_with_limit(relative_path, absolute_path, None)
}

fn observe_file_with_limit(
    relative_path: String,
    absolute_path: &Path,
    source_limit: Option<(u64, u64)>,
) -> Result<ObservedFile, ObservationError> {
    let file = File::open(absolute_path)
        .map_err(|source| ObservationError::io("open file", absolute_path, source))?;
    if let Some((already_read, maximum)) = source_limit {
        let metadata = file
            .metadata()
            .map_err(|source| ObservationError::io("inspect file", absolute_path, source))?;
        admit_source_bytes(already_read, metadata.len(), maximum)?;
    }
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
        let read_bytes = u64::try_from(read)
            .map_err(|_| ObservationError::FileSizeOverflow(absolute_path.to_path_buf()))?;
        size = size
            .checked_add(read_bytes)
            .ok_or_else(|| ObservationError::FileSizeOverflow(absolute_path.to_path_buf()))?;
        if let Some((already_read, maximum)) = source_limit {
            admit_source_bytes(already_read, size, maximum)?;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(ObservedFile {
        path: relative_path,
        size,
        sha256: format!("sha256:{:x}", hasher.finalize()),
    })
}

fn admit_source_bytes(already_read: u64, size: u64, maximum: u64) -> Result<(), ObservationError> {
    let observed = already_read
        .checked_add(size)
        .ok_or(ObservationError::ResourceLimit {
            resource: "source_bytes",
            maximum,
            observed: u64::MAX,
        })?;
    if observed > maximum {
        return Err(ObservationError::ResourceLimit {
            resource: "source_bytes",
            maximum,
            observed,
        });
    }
    Ok(())
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

/// Returns whether a path follows the portable repository-relative grammar.
#[must_use]
pub fn is_canonical_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && !value.starts_with('/')
        && !value
            .chars()
            .any(|character| character.is_control() || "<>:\"|?*".contains(character))
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment.ends_with(' ')
                && !segment.ends_with('.')
                && !matches!(
                    segment
                        .split('.')
                        .next()
                        .unwrap_or_default()
                        .to_ascii_uppercase()
                        .as_str(),
                    "CON"
                        | "PRN"
                        | "AUX"
                        | "NUL"
                        | "COM1"
                        | "COM2"
                        | "COM3"
                        | "COM4"
                        | "COM5"
                        | "COM6"
                        | "COM7"
                        | "COM8"
                        | "COM9"
                        | "LPT1"
                        | "LPT2"
                        | "LPT3"
                        | "LPT4"
                        | "LPT5"
                        | "LPT6"
                        | "LPT7"
                        | "LPT8"
                        | "LPT9"
                )
        })
}
