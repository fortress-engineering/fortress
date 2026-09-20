//! Portable source-entry inventory, including explicit observation barriers.

use std::fs::{self, DirEntry};
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    ObservationError, ObservationPolicy, RepositoryObservation, observe_file, relative_path,
};

/// One explicitly excluded source selector and its caller authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceExclusion {
    selector: String,
    authority_ref: String,
    reason: String,
}

impl SourceExclusion {
    /// Returns the excluded canonical repository path prefix.
    #[must_use]
    pub fn selector(&self) -> &str {
        &self.selector
    }
}

/// One portable source path and either observed bytes or a limitation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceEntry {
    repository_relative_path: String,
    entry_kind: String,
    content_digest: Option<String>,
    byte_count: Option<u64>,
    executable: Option<bool>,
    link_target: Option<String>,
    handling: String,
    limitation_ref: Option<String>,
}

impl SourceEntry {
    /// Returns the normalized repository-relative entry path.
    #[must_use]
    pub fn repository_relative_path(&self) -> &str {
        &self.repository_relative_path
    }

    /// Returns an explicit limitation identifier when bytes were not observed.
    #[must_use]
    pub fn limitation_ref(&self) -> Option<&str> {
        self.limitation_ref.as_deref()
    }
}

/// Versioned source-entry manifest, independent of machine root location.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceManifest {
    version: u16,
    entries_digest: String,
    entries: Vec<SourceEntry>,
    exclusions: Vec<SourceExclusion>,
}

impl SourceManifest {
    /// Derives the same ordinary-entry manifest from one completed strict observation.
    ///
    /// # Errors
    /// Returns an error if an observed count cannot be represented exactly on the wire.
    pub fn from_observation(
        observation: &RepositoryObservation,
        policy: &ObservationPolicy,
    ) -> Result<Self, ObservationError> {
        let mut entries = Vec::with_capacity(observation.files().len());
        for file in observation.files() {
            if file.size() > 9_007_199_254_740_991 {
                return Err(ObservationError::FileSizeOverflow(file.path().into()));
            }
            entries.push(file_entry(
                file.path().into(),
                file.sha256().into(),
                file.size(),
            ));
        }
        Ok(finish(entries, exclusion_records(policy)))
    }

    /// Returns entries sorted by repository path.
    #[must_use]
    pub fn entries(&self) -> &[SourceEntry] {
        &self.entries
    }

    /// Returns exact exclusion selectors and their authority.
    #[must_use]
    pub fn exclusions(&self) -> &[SourceExclusion] {
        &self.exclusions
    }

    /// Returns the digest of entries and exclusions.
    #[must_use]
    pub fn entries_digest(&self) -> &str {
        &self.entries_digest
    }

    /// Serializes the deterministic manifest document.
    ///
    /// # Panics
    /// Panics only if the fixed in-memory manifest representation cannot be serialized.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut json = serde_json::to_string_pretty(self).expect("source manifest serializes");
        json.push('\n');
        json
    }
}

/// Inventories source entries without following links or executing repository code.
///
/// # Errors
/// Returns an error if the root or its names cannot be represented safely.
pub fn observe_source_manifest(
    root: impl AsRef<Path>,
    policy: &ObservationPolicy,
) -> Result<SourceManifest, ObservationError> {
    let root = root.as_ref();
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| ObservationError::io("inspect root", root, source))?;
    if !metadata.file_type().is_dir() {
        return Err(ObservationError::RootNotDirectory(root.to_path_buf()));
    }
    let exclusions = exclusion_records(policy);
    let mut entries = Vec::new();
    visit(root, root, &exclusions, &mut entries)?;
    Ok(finish(entries, exclusions))
}

fn exclusion_records(policy: &ObservationPolicy) -> Vec<SourceExclusion> {
    let mut exclusions = policy
        .excluded_prefixes()
        .iter()
        .map(|selector| SourceExclusion {
            selector: selector.clone(),
            authority_ref: "observation_policy".into(),
            reason: "caller_exclusion".into(),
        })
        .collect::<Vec<_>>();
    if !exclusions.iter().any(|item| item.selector == ".git") {
        exclusions.push(SourceExclusion {
            selector: ".git".into(),
            authority_ref: "repository_observation".into(),
            reason: "git_metadata".into(),
        });
    }
    exclusions.sort();
    exclusions
}

fn finish(mut entries: Vec<SourceEntry>, exclusions: Vec<SourceExclusion>) -> SourceManifest {
    entries.sort();
    let digest_bytes =
        serde_json::to_vec(&(1_u16, &entries, &exclusions)).expect("manifest identity serializes");
    SourceManifest {
        version: 1,
        entries_digest: format!("sha256:{:x}", Sha256::digest(digest_bytes)),
        entries,
        exclusions,
    }
}

fn file_entry(path: String, digest: String, size: u64) -> SourceEntry {
    SourceEntry {
        repository_relative_path: path,
        entry_kind: "FILE".into(),
        content_digest: Some(digest),
        byte_count: Some(size),
        executable: None,
        link_target: None,
        handling: "OBSERVED".into(),
        limitation_ref: None,
    }
}

#[allow(clippy::too_many_lines)]
fn visit(
    root: &Path,
    directory: &Path,
    exclusions: &[SourceExclusion],
    entries: &mut Vec<SourceEntry>,
) -> Result<(), ObservationError> {
    let read = fs::read_dir(directory)
        .map_err(|source| ObservationError::io("read directory", directory, source))?;
    let mut ordered = read
        .map(|entry| {
            let entry = entry.map_err(|source| {
                ObservationError::io("read directory entry", directory, source)
            })?;
            Ok((relative_path(root, &entry.path())?, entry))
        })
        .collect::<Result<Vec<(String, DirEntry)>, ObservationError>>()?;
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    for (path, entry) in ordered {
        if exclusions.iter().any(|item| {
            path == item.selector
                || path
                    .strip_prefix(&item.selector)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) {
            continue;
        }
        let absolute = entry.path();
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|source| ObservationError::io("inspect entry", &absolute, source))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() || is_reparse_point(&metadata) {
            let raw_target = fs::read_link(&absolute).ok();
            let target_readable = raw_target.is_some();
            let target_portable = raw_target
                .as_ref()
                .is_some_and(|target| target.to_str().is_some());
            let absolute_target = raw_target
                .as_ref()
                .is_some_and(|target| target.is_absolute());
            let target = raw_target.and_then(|target| {
                let spelling = target.to_str()?.replace('\\', "/");
                (!spelling.is_empty() && !Path::new(&spelling).is_absolute()).then_some(spelling)
            });
            let limitation = if !target_readable {
                "UNREADABLE_LINK_TARGET"
            } else if !target_portable {
                "NONPORTABLE_LINK_TARGET"
            } else if absolute_target {
                "SYMLINK_ABSOLUTE_TARGET"
            } else if target.as_deref() == Some(path.as_str()) {
                "SYMLINK_CYCLE"
            } else if target
                .as_deref()
                .is_some_and(|value| value.starts_with("../") || value == "..")
            {
                "SYMLINK_POTENTIAL_ESCAPE"
            } else if file_type.is_symlink() {
                "SYMLINK_UNFOLLOWED"
            } else {
                "REPARSE_POINT_UNFOLLOWED"
            };
            entries.push(SourceEntry {
                repository_relative_path: path,
                entry_kind: if file_type.is_symlink() {
                    "SYMLINK"
                } else {
                    "REPARSE_POINT"
                }
                .into(),
                content_digest: None,
                byte_count: None,
                executable: None,
                link_target: target,
                handling: "BARRIER".into(),
                limitation_ref: Some(limitation.into()),
            });
        } else if file_type.is_dir() {
            if let Err(error) = visit(root, &absolute, exclusions, entries) {
                if matches!(error, ObservationError::Io { .. }) {
                    entries.push(SourceEntry {
                        repository_relative_path: path,
                        entry_kind: "DIRECTORY".into(),
                        content_digest: None,
                        byte_count: None,
                        executable: None,
                        link_target: None,
                        handling: "BARRIER".into(),
                        limitation_ref: Some("UNREADABLE_DIRECTORY".into()),
                    });
                } else {
                    return Err(error);
                }
            }
        } else if file_type.is_file() {
            match observe_file(path.clone(), &absolute) {
                Ok(file) => {
                    if file.size() > 9_007_199_254_740_991 {
                        return Err(ObservationError::FileSizeOverflow(absolute));
                    }
                    entries.push(file_entry(path, file.sha256().into(), file.size()));
                }
                Err(ObservationError::Io { .. }) => entries.push(SourceEntry {
                    repository_relative_path: path,
                    entry_kind: "FILE".into(),
                    content_digest: None,
                    byte_count: None,
                    executable: None,
                    link_target: None,
                    handling: "BARRIER".into(),
                    limitation_ref: Some("UNREADABLE_FILE".into()),
                }),
                Err(error) => return Err(error),
            }
        } else {
            entries.push(SourceEntry {
                repository_relative_path: path,
                entry_kind: "NONREGULAR".into(),
                content_digest: None,
                byte_count: None,
                executable: None,
                link_target: None,
                handling: "BARRIER".into(),
                limitation_ref: Some("NONREGULAR_ENTRY".into()),
            });
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}
