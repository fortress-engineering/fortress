//! Bounded immutable migration operations and deterministic executable graphs.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::control_layout::{ControlLayout, ControlSourceBinding};
use crate::observation::{CandidateChangeSet, ChangeOperation, SourceView};

#[path = "journal.rs"]
mod journal;
#[path = "model.rs"]
mod model;
#[path = "paths.rs"]
mod paths;
#[path = "presentation.rs"]
mod presentation;
pub use presentation::export_reviewed_migration_plan;
#[path = "apply.rs"]
mod apply;
pub use apply::*;
pub use journal::{
    BoundaryPhase, MigrationResourceLease, MutationBoundary, MutationObserver, NoMutationFaults,
    ResourceLeasePort,
};
pub use model::*;

/// Maximum number of explicitly reviewed file operations.
pub const MAX_MIGRATION_OPERATIONS: usize = 1024;
/// Aggregate immutable input and operation payload admission.
pub const MAX_MIGRATION_BYTES: usize = 32 * 1024 * 1024;

/// Structured operational failure; no error is a semantic verdict or approval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationError {
    /// Stable machine-readable classification.
    pub code: String,
    /// Human-readable reason and affected input.
    pub message: String,
    /// Owned transaction requiring explicit recovery, where one was allocated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_ref: Option<String>,
}
impl Display for MigrationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message).and_then(|()| match &self.transaction_ref {
            Some(reference) => write!(f, " [retained transaction: {reference}]"),
            None => Ok(()),
        })
    }
}
impl std::error::Error for MigrationError {}
pub(crate) fn fail(code: &str, message: impl Into<String>) -> MigrationError {
    MigrationError {
        code: code.into(),
        message: message.into(),
        transaction_ref: None,
    }
}
pub(crate) fn content_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, MigrationError> {
    struct Bounded(Vec<u8>);
    impl std::io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .0
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n > MAX_MIGRATION_BYTES)
            {
                return Err(std::io::Error::other(
                    "migration serialization exceeds admission",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut bytes = Bounded(vec![]);
    serde_json::to_writer(&mut bytes, value).map_err(|e| fail("RESOURCE_LIMIT", e.to_string()))?;
    let text = std::str::from_utf8(&bytes.0).map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
    crate::wire::canonicalize_public_json(text).map_err(|e| fail("INVALID_INPUT", e.to_string()))
}

/// One exact regular-file edit, not permission to execute it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum MigrationOperation {
    /// Create an initially absent regular file.
    CreateFile {
        /// Portable repository-relative destination.
        path: String,
        /// Exact proposed bytes.
        postimage: Vec<u8>,
    },
    /// Replace exact original bytes without an in-place truncating write.
    ReplaceFile {
        /// Portable repository-relative input.
        path: String,
        /// Exact original bytes.
        preimage: Vec<u8>,
        /// Exact proposed bytes.
        postimage: Vec<u8>,
    },
    /// Relocate a regular file; trees use an explicit bounded set of file moves.
    MovePath {
        /// Portable repository-relative original path.
        source: String,
        /// Portable repository-relative destination.
        destination: String,
        /// Exact bytes retained by this relocation.
        preimage: Vec<u8>,
    },
    /// Remove a file only under a matching independently prepared ownership fact.
    DeleteOwnedFile {
        /// Portable repository-relative original path.
        path: String,
        /// Exact original bytes, retained for recovery.
        preimage: Vec<u8>,
        /// Expected canonical ownership identity; this assertion is not a grant.
        owner_ref: String,
    },
}
impl MigrationOperation {
    pub(crate) fn original(&self) -> Option<(&str, &[u8])> {
        match self {
            Self::CreateFile { .. } => None,
            Self::ReplaceFile { path, preimage, .. }
            | Self::DeleteOwnedFile { path, preimage, .. } => Some((path, preimage)),
            Self::MovePath {
                source, preimage, ..
            } => Some((source, preimage)),
        }
    }
    pub(crate) fn destination(&self) -> Option<(&str, &[u8])> {
        match self {
            Self::CreateFile { path, postimage }
            | Self::ReplaceFile {
                path, postimage, ..
            } => Some((path, postimage)),
            Self::MovePath {
                destination,
                preimage,
                ..
            } => Some((destination, preimage)),
            Self::DeleteOwnedFile { .. } => None,
        }
    }
    pub(crate) fn neutral(&self) -> ChangeOperation {
        match self {
            Self::CreateFile { path, postimage } => ChangeOperation::Create {
                path: path.clone(),
                candidate_bytes: postimage.clone(),
            },
            Self::ReplaceFile {
                path,
                preimage,
                postimage,
            } => ChangeOperation::Replace {
                path: path.clone(),
                base_bytes: preimage.clone(),
                candidate_bytes: postimage.clone(),
            },
            Self::MovePath {
                source,
                destination,
                preimage,
            } => ChangeOperation::Move {
                source: source.clone(),
                destination: destination.clone(),
                base_bytes: preimage.clone(),
            },
            Self::DeleteOwnedFile { path, preimage, .. } => ChangeOperation::Delete {
                path: path.clone(),
                base_bytes: preimage.clone(),
            },
        }
    }
}

/// Executable action relative to an exclusively leased external staging root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ExecutableAction {
    /// Claim and verify original bytes before any target installation.
    Evacuate {
        /// Original repository-relative path.
        path: String,
        /// Exclusively allocated staging file name, never a repository path.
        slot: String,
        /// Exact original content identity.
        digest: String,
    },
    /// Prepare immutable reviewed replacement content outside the repository.
    Stage {
        /// Exclusively allocated staging file name.
        slot: String,
        /// Exact reviewed content identity.
        digest: String,
    },
    /// Install a verified staging file only at an absent destination.
    Install {
        /// Portable repository-relative destination.
        path: String,
        /// Previously evacuated or staged content.
        slot: String,
        /// Exact installed content identity.
        digest: String,
    },
}

/// A node in an explicitly acyclic operation dependency graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableStep {
    /// Deterministic monotonically ordered node identifier.
    pub id: u32,
    /// Required predecessor identifiers.
    pub dependencies: Vec<u32>,
    /// Bounded file operation.
    pub action: ExecutableAction,
}

/// Prepared byte transformation and explicit execution graph; never actual-state evidence.
#[derive(Clone, Debug)]
pub struct OperationGraph {
    operations: Vec<MigrationOperation>,
    steps: Vec<ExecutableStep>,
    target: SourceView,
}
impl OperationGraph {
    /// Validates exact operations and lowers permutations through exclusive staging slots.
    ///
    /// # Errors
    /// Refuses stale bytes, unsafe paths, overlapping edits, ambiguous casing, unowned deletion
    /// and resource exhaustion. No filesystem operation is performed.
    pub fn compile(
        base: &SourceView,
        operations: Vec<MigrationOperation>,
        owners: &BTreeMap<String, String>,
    ) -> Result<Self, MigrationError> {
        if operations.len() > MAX_MIGRATION_OPERATIONS || base.len() > 50_000 {
            return Err(fail(
                "RESOURCE_LIMIT",
                "migration inventory exceeds admission",
            ));
        }
        let mut payload = base
            .iter()
            .try_fold(0usize, |n, (path, b)| {
                n.checked_add(b.len())?.checked_add(path.len())
            })
            .ok_or_else(|| fail("RESOURCE_LIMIT", "source byte accounting overflow"))?;
        if payload > MAX_MIGRATION_BYTES {
            return Err(fail(
                "RESOURCE_LIMIT",
                "source inventory exceeds migration admission",
            ));
        }
        let mut normalized = vec![];
        for op in operations {
            for (path, bytes) in op.original().into_iter().chain(op.destination()) {
                validate_path(path)?;
                payload = payload
                    .checked_add(bytes.len())
                    .and_then(|n| n.checked_add(path.len()))
                    .filter(|n| *n <= MAX_MIGRATION_BYTES)
                    .ok_or_else(|| fail("RESOURCE_LIMIT", "migration bytes exceed admission"))?;
            }
            if let Some((path, bytes)) = op.original()
                && base.bytes(path) != Some(bytes)
            {
                return Err(fail("STALE_PREIMAGE", path));
            }
            if let MigrationOperation::DeleteOwnedFile {
                path, owner_ref, ..
            } = &op
                && (owner_ref.is_empty() || owners.get(path) != Some(owner_ref))
            {
                return Err(fail("OWNERSHIP_MISMATCH", path));
            }
            if matches!(&op, MigrationOperation::MovePath { source, destination, .. } if source == destination)
                || matches!(&op, MigrationOperation::ReplaceFile { preimage, postimage, .. } if preimage == postimage)
            {
                continue;
            }
            normalized.push(op);
        }
        normalized.sort_by_cached_key(|op| {
            (
                op.original().map_or("", |(p, _)| p).to_owned(),
                op.destination().map_or("", |(p, _)| p).to_owned(),
            )
        });
        let neutral = normalized
            .iter()
            .map(MigrationOperation::neutral)
            .collect::<Vec<_>>();
        let changes = CandidateChangeSet::new_simultaneous(
            base,
            "migration-byte-preview-v1",
            "unbound-target-authority",
            neutral,
        )
        .map_err(|e| fail("OPERATION_CONFLICT", e.to_string()))?;
        validate_inventory(base)?;
        validate_inventory(changes.view())?;
        validate_operation_overlaps(&normalized)?;
        let steps = compile_steps(&normalized)?;
        let value = Self {
            operations: normalized,
            steps,
            target: changes.view().clone(),
        };
        value.digest()?;
        Ok(value)
    }
    /// Exact proposed file bytes, kept separate from current repository state.
    #[must_use]
    pub const fn target(&self) -> &SourceView {
        &self.target
    }
    /// Deterministically lowered acyclic executable graph.
    #[must_use]
    pub fn steps(&self) -> &[ExecutableStep] {
        &self.steps
    }
    /// Canonically ordered meaningful operations; exact no-ops are omitted.
    #[must_use]
    pub fn operations(&self) -> &[MigrationOperation] {
        &self.operations
    }
    /// Content identity of operations, dependency edges and proposed exact bytes.
    /// # Errors
    /// Refuses excessive canonical serialization.
    pub fn digest(&self) -> Result<String, MigrationError> {
        canonical(&(1, &self.operations, &self.steps, self.target.digest()))
            .map(|b| content_digest(&b))
    }
}

pub(crate) fn validate_path(path: &str) -> Result<(), MigrationError> {
    if !crate::observation::is_canonical_relative_path(path)
        || path.len() > 4096
        || path.split('/').any(|p| {
            p.eq_ignore_ascii_case(".git")
                || p.ends_with(['.', ' '])
                || p.chars().any(char::is_control)
                || reserved_component(p)
        })
    {
        return Err(fail("UNSAFE_PATH", path));
    }
    if ControlLayout::standard()
        .resolve(path)
        .is_some_and(|r| r.source_binding() != ControlSourceBinding::Required)
    {
        return Err(fail("PROTECTED_OUTPUT_PATH", path));
    }
    Ok(())
}
fn reserved_component(part: &str) -> bool {
    let stem = part
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
        || ["COM", "LPT"].iter().any(|p| {
            stem.strip_prefix(p)
                .is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
        })
}
fn validate_inventory(source: &SourceView) -> Result<(), MigrationError> {
    let mut folded = BTreeMap::new();
    let mut visits = 0usize;
    let mut retained = 0usize;
    for path in source.keys() {
        validate_path(path)?;
        for boundary in path
            .match_indices('/')
            .map(|(i, _)| i)
            .chain(std::iter::once(path.len()))
        {
            let prefix = &path[..boundary];
            visits += 1;
            if visits > 200_000 {
                return Err(fail("RESOURCE_LIMIT", "path comparison admission exceeded"));
            }
            for key in case_keys(prefix) {
                if let Some(prior) = folded.get(&key) {
                    if *prior != prefix {
                        return Err(fail("CASE_COLLISION", path));
                    }
                } else {
                    retained = retained
                        .checked_add(key.len())
                        .filter(|n| *n <= MAX_MIGRATION_BYTES)
                        .ok_or_else(|| fail("RESOURCE_LIMIT", "path index exceeds admission"))?;
                    folded.insert(key, prefix);
                }
            }
            if boundary != path.len() && source.contains_key(prefix) {
                return Err(fail("PATH_OVERLAP", path));
            }
        }
    }
    Ok(())
}
fn case_keys(path: &str) -> [String; 2] {
    [
        format!("fold:{}", unicase::UniCase::new(path).to_folded_case()),
        format!("upper:{}", path.to_uppercase()),
    ]
}

fn compile_steps(normalized: &[MigrationOperation]) -> Result<Vec<ExecutableStep>, MigrationError> {
    let mut originals = BTreeMap::new();
    let mut staged = BTreeMap::new();
    for (i, op) in normalized.iter().enumerate() {
        if let Some((path, bytes)) = op.original() {
            originals.insert(
                path.to_owned(),
                (format!("original-{i:04}"), content_digest(bytes)),
            );
        }
        if matches!(
            op,
            MigrationOperation::CreateFile { .. } | MigrationOperation::ReplaceFile { .. }
        ) {
            let (path, bytes) = op
                .destination()
                .expect("creating operation has destination");
            staged.insert(
                path.to_owned(),
                (format!("output-{i:04}"), content_digest(bytes)),
            );
        }
    }
    let mut steps = vec![];
    for (path, (slot, digest)) in &originals {
        steps.push(ExecutableStep {
            id: u32::try_from(steps.len())
                .map_err(|_| fail("RESOURCE_LIMIT", "operation graph identifiers exhausted"))?,
            dependencies: vec![],
            action: ExecutableAction::Evacuate {
                path: path.clone(),
                slot: slot.clone(),
                digest: digest.clone(),
            },
        });
    }
    for (slot, digest) in staged.values() {
        steps.push(ExecutableStep {
            id: u32::try_from(steps.len())
                .map_err(|_| fail("RESOURCE_LIMIT", "operation graph identifiers exhausted"))?,
            dependencies: vec![],
            action: ExecutableAction::Stage {
                slot: slot.clone(),
                digest: digest.clone(),
            },
        });
    }
    let prepared = steps.iter().map(|s| s.id).collect::<Vec<_>>();
    let mut installs = BTreeMap::new();
    for op in normalized {
        if let Some((path, bytes)) = op.destination() {
            let slot = match op {
                MigrationOperation::MovePath { source, .. } => originals
                    .get(source)
                    .ok_or_else(|| fail("INVALID_GRAPH", "move has no evacuated original"))?
                    .0
                    .clone(),
                _ => staged
                    .get(path)
                    .ok_or_else(|| fail("INVALID_GRAPH", "installation has no staged output"))?
                    .0
                    .clone(),
            };
            installs.insert(path.to_owned(), (slot, content_digest(bytes)));
        }
    }
    for (path, (slot, digest)) in installs {
        steps.push(ExecutableStep {
            id: u32::try_from(steps.len())
                .map_err(|_| fail("RESOURCE_LIMIT", "operation graph identifiers exhausted"))?,
            dependencies: prepared.clone(),
            action: ExecutableAction::Install { path, slot, digest },
        });
    }
    Ok(steps)
}

fn validate_operation_overlaps(normalized: &[MigrationOperation]) -> Result<(), MigrationError> {
    let endpoints = normalized
        .iter()
        .flat_map(|op| {
            op.original()
                .into_iter()
                .chain(op.destination())
                .map(|(p, _)| p)
        })
        .collect::<BTreeSet<_>>();
    let mut folded_endpoints = BTreeMap::new();
    for path in &endpoints {
        for key in case_keys(path) {
            if folded_endpoints
                .insert(key, *path)
                .is_some_and(|previous| previous != *path)
            {
                return Err(fail(
                    "CASE_COLLISION",
                    "operation endpoints have different spellings of the same portable path",
                ));
            }
        }
    }
    for path in &endpoints {
        for (offset, _) in path.match_indices('/') {
            let prefix = &path[..offset];
            if case_keys(prefix)
                .iter()
                .any(|key| folded_endpoints.contains_key(key))
            {
                return Err(fail(
                    "PATH_OVERLAP",
                    format!("{prefix} conflicts with {path}"),
                ));
            }
        }
    }
    Ok(())
}
