//! Immutable observed and hypothetical source bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::is_canonical_relative_path;

/// Exact repository-relative bytes in one immutable input generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceView {
    files: Arc<BTreeMap<String, Vec<u8>>>,
    digest: String,
}

impl SourceView {
    /// Captures exact bytes, rejecting duplicate or nonportable paths.
    ///
    /// # Errors
    /// Returns an error for an invalid or duplicate path.
    pub fn from_bytes<I, S>(files: I) -> Result<Self, SourceViewError>
    where
        I: IntoIterator<Item = (S, Vec<u8>)>,
        S: Into<String>,
    {
        let mut ordered = BTreeMap::new();
        for (path, bytes) in files {
            let path = path.into();
            if !is_source_path(&path) {
                return Err(SourceViewError::InvalidPath(path));
            }
            if ordered.insert(path.clone(), bytes).is_some() {
                return Err(SourceViewError::DuplicatePath(path));
            }
        }
        Ok(Self::from_ordered(ordered))
    }

    fn from_ordered(files: BTreeMap<String, Vec<u8>>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"fortress-source-view-v1\0");
        for (path, bytes) in &files {
            update_part(&mut hasher, path.as_bytes());
            update_part(&mut hasher, bytes);
        }
        Self {
            files: Arc::new(files),
            digest: format!("sha256:{:x}", hasher.finalize()),
        }
    }

    /// Returns exact bytes for one path.
    #[must_use]
    pub fn bytes(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// Returns the exact byte and path inventory identity.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns all files in canonical path order.
    #[must_use]
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }
}

impl Deref for SourceView {
    type Target = BTreeMap<String, Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.files
    }
}

impl<'a> IntoIterator for &'a SourceView {
    type Item = (&'a String, &'a Vec<u8>);
    type IntoIter = std::collections::btree_map::Iter<'a, String, Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.files.iter()
    }
}

/// One proposed byte-level change. All preimages are exact base bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangeOperation {
    /// Create a new path.
    Create {
        /// New repository-relative path.
        path: String,
        /// Proposed content bytes.
        candidate_bytes: Vec<u8>,
    },
    /// Replace an existing path.
    Replace {
        /// Existing repository-relative path.
        path: String,
        /// Exact existing content bytes.
        base_bytes: Vec<u8>,
        /// Proposed replacement bytes.
        candidate_bytes: Vec<u8>,
    },
    /// Delete an existing path.
    Delete {
        /// Existing repository-relative path.
        path: String,
        /// Exact existing content bytes.
        base_bytes: Vec<u8>,
    },
    /// Move exact existing bytes to a previously absent path.
    Move {
        /// Existing source path.
        source: String,
        /// New destination path.
        destination: String,
        /// Exact bytes at the source path.
        base_bytes: Vec<u8>,
    },
}

/// An ordered, conflict-checked hypothetical view over exact base bytes.
#[derive(Clone, Debug)]
pub struct CandidateChangeSet {
    operations: Vec<ChangeOperation>,
    base_view_digest: String,
    context_digest: String,
    target_authority_digest: String,
    digest: String,
    view: SourceView,
}

impl CandidateChangeSet {
    /// Applies a simultaneous exact-byte transaction, including file-move permutations.
    /// Existing `new` ordering and v1 identities remain unchanged.
    ///
    /// # Errors
    /// Refuses duplicate consumption/production, stale preimages and overlapping
    /// non-move operations. An occupied move destination must itself be moved.
    pub fn new_simultaneous(
        base: &SourceView,
        context_digest: impl Into<String>,
        target_authority_digest: impl Into<String>,
        operations: impl IntoIterator<Item = ChangeOperation>,
    ) -> Result<Self, SourceViewError> {
        let context_digest = context_digest.into();
        let target_authority_digest = target_authority_digest.into();
        let operations = operations.into_iter().collect::<Vec<_>>();
        let consumed = validate_simultaneous(base, &operations)?;
        let mut files = base.files.as_ref().clone();
        for path in consumed {
            files.remove(&path);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"fortress-candidate-change-set-v2\0");
        update_part(&mut hasher, base.digest.as_bytes());
        update_part(&mut hasher, context_digest.as_bytes());
        update_part(&mut hasher, target_authority_digest.as_bytes());
        for operation in &operations {
            let (kind, path, destination, before, after) = match operation {
                ChangeOperation::Create {
                    path,
                    candidate_bytes,
                } => ("create", path, None, &[][..], candidate_bytes.as_slice()),
                ChangeOperation::Replace {
                    path,
                    base_bytes,
                    candidate_bytes,
                } => (
                    "replace",
                    path,
                    None,
                    base_bytes.as_slice(),
                    candidate_bytes.as_slice(),
                ),
                ChangeOperation::Delete { path, base_bytes } => {
                    ("delete", path, None, base_bytes.as_slice(), &[][..])
                }
                ChangeOperation::Move {
                    source,
                    destination,
                    base_bytes,
                } => (
                    "move",
                    source,
                    Some(destination),
                    base_bytes.as_slice(),
                    base_bytes.as_slice(),
                ),
            };
            for part in [
                kind.as_bytes(),
                path.as_bytes(),
                destination.map_or(&[][..], |p| p.as_bytes()),
                before,
                after,
            ] {
                update_part(&mut hasher, part);
            }
            match operation {
                ChangeOperation::Create {
                    path,
                    candidate_bytes,
                }
                | ChangeOperation::Replace {
                    path,
                    candidate_bytes,
                    ..
                } => {
                    files.insert(path.clone(), candidate_bytes.clone());
                }
                ChangeOperation::Move {
                    destination,
                    base_bytes,
                    ..
                } => {
                    files.insert(destination.clone(), base_bytes.clone());
                }
                ChangeOperation::Delete { .. } => {}
            }
        }
        let view = SourceView::from_ordered(files);
        update_part(&mut hasher, view.digest.as_bytes());
        Ok(Self {
            operations,
            base_view_digest: base.digest.clone(),
            context_digest,
            target_authority_digest,
            digest: format!("sha256:{:x}", hasher.finalize()),
            view,
        })
    }

    /// Applies operations only to a private copy of the base source view.
    ///
    /// # Errors
    /// Returns an error for nonportable, conflicting or stale operations.
    pub fn new(
        base: &SourceView,
        context_digest: impl Into<String>,
        target_authority_digest: impl Into<String>,
        operations: impl IntoIterator<Item = ChangeOperation>,
    ) -> Result<Self, SourceViewError> {
        let context_digest = context_digest.into();
        let target_authority_digest = target_authority_digest.into();
        let operations = operations.into_iter().collect::<Vec<_>>();
        let mut touched = BTreeSet::new();
        let mut files = base.files.as_ref().clone();
        let mut hasher = Sha256::new();
        hasher.update(b"fortress-candidate-change-set-v1\0");
        update_part(&mut hasher, base.digest.as_bytes());
        update_part(&mut hasher, context_digest.as_bytes());
        update_part(&mut hasher, target_authority_digest.as_bytes());
        for operation in &operations {
            match operation {
                ChangeOperation::Create {
                    path,
                    candidate_bytes,
                } => {
                    claim_path(path, &mut touched)?;
                    if files.contains_key(path) {
                        return Err(SourceViewError::PathExists(path.clone()));
                    }
                    files.insert(path.clone(), candidate_bytes.clone());
                    update_part(&mut hasher, b"create");
                    update_part(&mut hasher, path.as_bytes());
                    update_part(&mut hasher, candidate_bytes);
                }
                ChangeOperation::Replace {
                    path,
                    base_bytes,
                    candidate_bytes,
                } => {
                    claim_path(path, &mut touched)?;
                    check_preimage(&files, path, base_bytes)?;
                    files.insert(path.clone(), candidate_bytes.clone());
                    update_part(&mut hasher, b"replace");
                    update_part(&mut hasher, path.as_bytes());
                    update_part(&mut hasher, base_bytes);
                    update_part(&mut hasher, candidate_bytes);
                }
                ChangeOperation::Delete { path, base_bytes } => {
                    claim_path(path, &mut touched)?;
                    check_preimage(&files, path, base_bytes)?;
                    files.remove(path);
                    update_part(&mut hasher, b"delete");
                    update_part(&mut hasher, path.as_bytes());
                    update_part(&mut hasher, base_bytes);
                }
                ChangeOperation::Move {
                    source,
                    destination,
                    base_bytes,
                } => {
                    claim_path(source, &mut touched)?;
                    claim_path(destination, &mut touched)?;
                    check_preimage(&files, source, base_bytes)?;
                    if files.contains_key(destination) {
                        return Err(SourceViewError::PathExists(destination.clone()));
                    }
                    files.remove(source);
                    files.insert(destination.clone(), base_bytes.clone());
                    update_part(&mut hasher, b"move");
                    update_part(&mut hasher, source.as_bytes());
                    update_part(&mut hasher, destination.as_bytes());
                    update_part(&mut hasher, base_bytes);
                }
            }
        }
        let view = SourceView::from_ordered(files);
        update_part(&mut hasher, view.digest.as_bytes());
        Ok(Self {
            operations,
            base_view_digest: base.digest.clone(),
            context_digest,
            target_authority_digest,
            digest: format!("sha256:{:x}", hasher.finalize()),
            view,
        })
    }

    /// Returns the ordered proposed operations.
    #[must_use]
    pub fn operations(&self) -> &[ChangeOperation] {
        &self.operations
    }

    /// Returns the candidate source bytes; this is never actual-state evidence.
    #[must_use]
    pub const fn view(&self) -> &SourceView {
        &self.view
    }

    /// Returns the proposal identity binding both views, context and authority.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns the exact base identity.
    #[must_use]
    pub fn base_view_digest(&self) -> &str {
        &self.base_view_digest
    }

    /// Returns the context identity supplied by the evaluator.
    #[must_use]
    pub fn context_digest(&self) -> &str {
        &self.context_digest
    }

    /// Returns the target authority identity supplied by the evaluator.
    #[must_use]
    pub fn target_authority_digest(&self) -> &str {
        &self.target_authority_digest
    }
}

/// Why a source view or proposed change is not safe to construct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceViewError {
    /// A path violates the portable repository-relative grammar.
    InvalidPath(String),
    /// A source inventory contains the same path twice.
    DuplicatePath(String),
    /// A proposal touches one path more than once.
    ConflictingOperation(String),
    /// Creation would overwrite an existing path.
    PathExists(String),
    /// A preimage differs from the immutable base bytes.
    StalePreimage(String),
}

impl Display for SourceViewError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SourceViewError {}

fn claim_path(path: &str, touched: &mut BTreeSet<String>) -> Result<(), SourceViewError> {
    if !is_source_path(path) {
        return Err(SourceViewError::InvalidPath(path.into()));
    }
    if !touched.insert(path.into()) {
        return Err(SourceViewError::ConflictingOperation(path.into()));
    }
    Ok(())
}

fn is_source_path(path: &str) -> bool {
    is_canonical_relative_path(path) && path != ".git" && !path.starts_with(".git/")
}

fn check_preimage(
    files: &BTreeMap<String, Vec<u8>>,
    path: &str,
    expected: &[u8],
) -> Result<(), SourceViewError> {
    if files.get(path).map(Vec::as_slice) != Some(expected) {
        return Err(SourceViewError::StalePreimage(path.into()));
    }
    Ok(())
}

fn update_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn validate_simultaneous(
    base: &SourceView,
    operations: &[ChangeOperation],
) -> Result<BTreeSet<String>, SourceViewError> {
    let mut consumed = BTreeSet::new();
    let mut produced = BTreeSet::new();
    let mut move_sources = BTreeSet::new();
    let mut ordinary = BTreeSet::new();
    for operation in operations {
        match operation {
            ChangeOperation::Create { path, .. } => {
                claim_path(path, &mut produced)?;
                ordinary.insert(path.clone());
                if base.contains_key(path) {
                    return Err(SourceViewError::PathExists(path.clone()));
                }
            }
            ChangeOperation::Replace {
                path, base_bytes, ..
            } => {
                claim_path(path, &mut consumed)?;
                claim_path(path, &mut produced)?;
                check_preimage(base.files(), path, base_bytes)?;
                ordinary.insert(path.clone());
            }
            ChangeOperation::Delete { path, base_bytes } => {
                claim_path(path, &mut consumed)?;
                check_preimage(base.files(), path, base_bytes)?;
                ordinary.insert(path.clone());
            }
            ChangeOperation::Move {
                source,
                destination,
                base_bytes,
            } => {
                claim_path(source, &mut consumed)?;
                claim_path(destination, &mut produced)?;
                check_preimage(base.files(), source, base_bytes)?;
                move_sources.insert(source.clone());
            }
        }
    }
    for operation in operations {
        if let ChangeOperation::Move {
            source,
            destination,
            ..
        } = operation
        {
            if ordinary.contains(source) || ordinary.contains(destination) {
                return Err(SourceViewError::ConflictingOperation(source.clone()));
            }
            if base.contains_key(destination) && !move_sources.contains(destination) {
                return Err(SourceViewError::PathExists(destination.clone()));
            }
        }
    }
    Ok(consumed)
}
