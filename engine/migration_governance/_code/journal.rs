//! Exclusively owned external write-ahead journals and injected OPS resource contracts.
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{MAX_MIGRATION_BYTES, MigrationError, canonical, content_digest, fail};

/// Existing OPS adapter supplies ownership, physical identity, leases and bounded retention.
pub trait ResourceLeasePort {
    /// One exclusively owned application/recovery lease.
    type Lease: MigrationResourceLease;
    /// Allocates same-volume external storage and checks disk headroom before source mutation.
    /// # Errors
    /// Refuses active/conflicting owners, unsupported volume identity and insufficient storage.
    fn acquire(
        &self,
        repository: &Path,
        plan_ref: &str,
        bytes: u64,
    ) -> Result<Self::Lease, MigrationError>;
    /// Reopens a marked inactive transaction without deleting its recovery material.
    /// # Errors
    /// Refuses active leases, ambiguous ownership and mismatched physical repositories.
    fn recover(
        &self,
        repository: &Path,
        transaction_ref: &str,
        plan_ref: &str,
    ) -> Result<Self::Lease, MigrationError>;
}

/// Non-serializable OPS lease; repository text cannot create this ownership capability.
pub trait MigrationResourceLease {
    /// Exclusively owned external run root on the repository's volume.
    fn root(&self) -> &Path;
    /// Unforgeable local transaction incarnation, independent of content identities.
    fn transaction_ref(&self) -> &str;
    /// Stable native physical repository identity.
    fn repository_identity(&self) -> &str;
    /// Revalidates pinned directory identity and same-volume ownership.
    /// # Errors
    /// Refuses replaced directories, reparse points and ownership ambiguity.
    fn verify(&self, repository: &Path) -> Result<(), MigrationError>;
    /// Checks existing OPS free-space and run-retention limits.
    /// # Errors
    /// Refuses insufficient headroom or exhausted bounded allocation.
    fn reserve(&self, bytes: u64) -> Result<(), MigrationError>;
    /// Reads native object identity through the existing OPS directory/file identity adapter.
    /// # Errors
    /// Refuses unsupported identities, links and inaccessible objects.
    fn object_identity(&self, path: &Path) -> Result<String, MigrationError>;
    /// Publishes a reader-visible APPLYING marker after the durable prepared header exists.
    /// # Errors
    /// Refuses a conflicting active transaction or failed durable publication.
    fn applying(&mut self, plan_ref: &str, journal: &Path) -> Result<(), MigrationError>;
    /// Retires active state only after independently verified application or rollback.
    /// Recovery bytes and journals remain outside disposable compiler targets.
    /// # Errors
    /// Refuses incomplete ownership or failed durable completion.
    fn finish(&mut self, outcome: &str, result_ref: &str) -> Result<(), MigrationError>;
}

/// Observable filesystem/journal mutation boundaries for deterministic fault controls.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MutationBoundary {
    /// An immutable plan, prepared output or staging directory is written.
    Preparation,
    /// Durable write-ahead intent is appended before a source mutation.
    JournalIntent,
    /// A known original object is moved to exclusive staging.
    Evacuate,
    /// A known staged directory becomes a required source parent.
    ParentInstall,
    /// A verified postimage is linked to an absent source destination.
    Install,
    /// Verified completion is appended after a mutation.
    JournalCompletion,
    /// Immutable completed receipt publication.
    ReceiptPublication,
    /// Durable active-state publication or retirement.
    ActiveState,
}
/// Before/after side of one mutation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryPhase {
    /// The mutation has not yet occurred; preconditions are checked afterward.
    Before,
    /// The mutation and required file synchronization have completed.
    After,
}
/// Fault/cancellation port; production defaults never fabricate success after an error.
pub trait MutationObserver {
    /// Called at every supported mutation boundary with a monotonic operational ordinal.
    /// # Errors
    /// Cancellation, resource exhaustion or injected crashes retain recoverable state.
    fn boundary(
        &self,
        ordinal: u64,
        boundary: MutationBoundary,
        phase: BoundaryPhase,
    ) -> Result<(), MigrationError>;
}
/// Normal execution with no synthetic fault injection.
pub struct NoMutationFaults;
impl MutationObserver for NoMutationFaults {
    fn boundary(
        &self,
        _: u64,
        _: MutationBoundary,
        _: BoundaryPhase,
    ) -> Result<(), MigrationError> {
        Ok(())
    }
}

/// One prepared object whose identity can establish exclusive postimage ownership after a crash.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedObject {
    pub slot: String,
    pub path: String,
    pub identity: String,
    pub digest: Option<String>,
    pub directory: bool,
}
/// Complete prepared transaction header, durable before active application begins.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JournalHeader {
    pub schema_version: u16,
    pub plan_ref: String,
    pub transaction_ref: String,
    pub repository_identity: String,
    pub objects: Vec<PreparedObject>,
}
/// Append-only intent/completion state, never a substitute for inspecting actual bytes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub(crate) enum JournalAction {
    PlanIntent,
    PlanComplete,
    PrepareIntent {
        slot: String,
        digest: Option<String>,
        directory: bool,
    },
    PrepareComplete {
        slot: String,
        identity: String,
    },
    ObjectsPrepared {
        digest: String,
    },
    StepIntent {
        id: u32,
    },
    StepComplete {
        id: u32,
    },
    ParentIntent {
        path: String,
        slot: String,
    },
    ParentComplete {
        path: String,
    },
    ValidationIntent,
    ValidationComplete {
        source_ref: String,
        state_ref: String,
    },
    ReceiptIntent {
        path: String,
        digest: String,
    },
    ReceiptComplete {
        path: String,
        digest: String,
    },
    RecoveryIntent {
        mode: String,
    },
    RecoveryStepIntent {
        path: String,
        action: String,
    },
    RecoveryStepComplete {
        path: String,
    },
    RecoveryComplete {
        outcome: String,
        source_ref: String,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    sequence: u64,
    previous: String,
    action: JournalAction,
}
pub(crate) struct Journal {
    path: PathBuf,
    sequence: u64,
    previous: String,
    anchor: String,
    length: u64,
    pub actions: Vec<JournalAction>,
}
impl Journal {
    pub fn create(
        root: &Path,
        header: &JournalHeader,
        mut boundary: impl FnMut(BoundaryPhase) -> Result<(), MigrationError>,
    ) -> Result<Self, MigrationError> {
        let bytes = canonical(header)?;
        boundary(BoundaryPhase::Before)?;
        write_new(&root.join("header.json"), &bytes)?;
        boundary(BoundaryPhase::After)?;
        let path = root.join("operations.jsonl");
        boundary(BoundaryPhase::Before)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        boundary(BoundaryPhase::After)?;
        Ok(Self {
            path,
            sequence: 0,
            previous: content_digest(&bytes),
            anchor: content_digest(&bytes),
            length: 0,
            actions: vec![],
        })
    }
    pub fn load(root: &Path, header: &JournalHeader) -> Result<Self, MigrationError> {
        let path = root.join("operations.jsonl");
        let bytes = read_regular(&path, MAX_MIGRATION_BYTES)?;
        let mut result = Self {
            path,
            sequence: 0,
            previous: content_digest(&canonical(header)?),
            anchor: content_digest(&canonical(header)?),
            length: bytes.len() as u64,
            actions: vec![],
        };
        if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
            return Err(fail(
                "JOURNAL_INCOMPLETE",
                "incomplete journal suffix retained; automatic mutation is refused",
            ));
        }
        if read_regular(&root.join("header.json"), MAX_MIGRATION_BYTES)? != canonical(header)? {
            return Err(fail("JOURNAL_CORRUPT", "prepared header is not canonical"));
        }
        for line in bytes
            .strip_suffix(b"\n")
            .unwrap_or(&bytes)
            .split(|b| *b == b'\n')
            .filter(|_| !bytes.is_empty())
        {
            if line.is_empty() {
                return Err(fail("JOURNAL_CORRUPT", "blank journal record"));
            }
            let entry: JournalEntry = crate::wire::parse_strict_json_bytes(line)
                .map_err(|e| fail("JOURNAL_CORRUPT", e.to_string()))?;
            if canonical(&entry)? != line
                || entry.sequence != result.sequence
                || entry.previous != result.previous
            {
                return Err(fail(
                    "JOURNAL_CORRUPT",
                    "journal hash-chain or sequence differs",
                ));
            }
            result.previous = content_digest(line);
            result.sequence += 1;
            if result.sequence > 65_536 {
                return Err(fail("RESOURCE_LIMIT", "journal event admission exceeded"));
            }
            result.actions.push(entry.action);
        }
        Ok(result)
    }
    pub fn append(&mut self, action: JournalAction) -> Result<(), MigrationError> {
        if self.sequence >= 65_536 {
            return Err(fail("RESOURCE_LIMIT", "journal event admission exceeded"));
        }
        let entry = JournalEntry {
            sequence: self.sequence,
            previous: self.previous.clone(),
            action: action.clone(),
        };
        let bytes = canonical(&entry)?;
        let metadata = fs::symlink_metadata(&self.path).map_err(io_error)?;
        if linked(&metadata) || !metadata.is_file() || metadata.len() != self.length {
            return Err(fail(
                "JOURNAL_CORRUPT",
                "journal location or length changed",
            ));
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(io_error)?;
        if file
            .metadata()
            .map_err(io_error)?
            .len()
            .saturating_add(bytes.len() as u64 + 1)
            > MAX_MIGRATION_BYTES as u64
        {
            return Err(fail("RESOURCE_LIMIT", "journal bytes exceed admission"));
        }
        file.write_all(&bytes).map_err(io_error)?;
        file.write_all(b"\n").map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        self.sequence += 1;
        self.length += bytes.len() as u64 + 1;
        self.previous = content_digest(&bytes);
        self.actions.push(action);
        Ok(())
    }
    pub fn verify_integrity(&self) -> Result<(), MigrationError> {
        let root = self
            .path
            .parent()
            .ok_or_else(|| fail("JOURNAL_CORRUPT", "journal has no owned root"))?;
        let header: JournalHeader = crate::wire::parse_strict_json_bytes(&read_regular(
            &root.join("header.json"),
            MAX_MIGRATION_BYTES,
        )?)
        .map_err(|e| fail("JOURNAL_CORRUPT", e.to_string()))?;
        let loaded = Self::load(root, &header)?;
        if loaded.anchor != self.anchor
            || loaded.sequence != self.sequence
            || loaded.previous != self.previous
            || loaded.length != self.length
        {
            return Err(fail(
                "JOURNAL_CORRUPT",
                "durable journal differs from observed intent/completion history",
            ));
        }
        Ok(())
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn require_capacity(&self, bytes: usize, events: usize) -> Result<(), MigrationError> {
        if fs::metadata(&self.path)
            .map_err(io_error)?
            .len()
            .saturating_add(bytes as u64)
            > MAX_MIGRATION_BYTES as u64
            || self.sequence.saturating_add(events as u64) > 65_536
        {
            return Err(fail(
                "RESOURCE_LIMIT",
                "insufficient journal capacity for application and recovery",
            ));
        }
        Ok(())
    }
}

pub(crate) fn io_error(error: impl std::fmt::Display) -> MigrationError {
    fail("IO_ERROR", error.to_string())
}
pub(crate) fn linked(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}
pub(crate) fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>, MigrationError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if linked(&metadata) || !metadata.is_file() {
        return Err(fail("UNSAFE_PATH_KIND", path.display().to_string()));
    }
    if metadata.len() > limit as u64 {
        return Err(fail("RESOURCE_LIMIT", "file exceeds admission"));
    }
    let mut file = crate::observation::physical::open_regular(path).map_err(io_error)?;
    let before = file.metadata().map_err(io_error)?;
    let mut bytes = vec![];
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > limit {
        return Err(fail("RESOURCE_LIMIT", "file grew beyond admission"));
    }
    crate::observation::physical::verify_regular(path, &file, &before).map_err(io_error)?;
    if bytes.len() as u64 != before.len() {
        return Err(fail("SOURCE_DRIFT", "file changed while reading"));
    }
    Ok(bytes)
}
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), MigrationError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}
