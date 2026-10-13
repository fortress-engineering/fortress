//! Machine-local storage supervision for installed Rust runtime jobs.
//!
//! This adapter owns operational leases and journals only. Callers keep
//! semantic records, policy authority, and publication pointers elsewhere.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::Disks;

use crate::heavy_admission::{DirectoryIdentity, HeavyAdmissionGuard};

const GIB: u64 = 1024 * 1024 * 1024;
const RETIREMENT_JOURNAL_LIMIT: usize = 64 * 1024;
const RETIREMENT_RECORD_LIMIT: usize = 1024 * 1024;
const RETIREMENT_DIRECTORY_LIMIT: usize = 64;

/// Local resource limits. None of these values enter semantic identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoragePolicy {
    /// Minimum free space that must remain after a reservation.
    pub reserve_bytes: u64,
    /// Maximum owned compiler-target bytes.
    pub compiler_budget_bytes: u64,
    /// Maximum owned projection-cache bytes.
    pub projection_budget_bytes: u64,
    /// Number of simultaneous heavy jobs per physical repository.
    pub max_heavy_jobs: u8,
    /// Keep the leased shared target for bounded reuse.
    pub retain_shared_compiler: bool,
}

impl Default for StoragePolicy {
    fn default() -> Self {
        Self {
            reserve_bytes: 10 * GIB,
            compiler_budget_bytes: 32 * GIB,
            projection_budget_bytes: 8 * GIB,
            max_heavy_jobs: 1,
            retain_shared_compiler: true,
        }
    }
}

/// Disk and lifecycle result retained outside disposable staging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageReport {
    /// Free space observed before job work.
    pub disk_free_before: u64,
    /// Free space observed after cleanup.
    pub disk_free_after: u64,
    /// Bytes removed from this job's staging directory.
    pub cleaned_bytes: u64,
    /// Bytes retained in the leased compiler target.
    pub retained_bytes: u64,
    /// Final lifecycle state.
    pub lifecycle: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct OwnedPath {
    path: PathBuf,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RunJournal {
    run_nonce: String,
    root_identity: String,
    owner_identity: String,
    lease_state: String,
    lifecycle: String,
    resource_kinds: Vec<String>,
    preexisting_files: Vec<OwnedPath>,
    owned: Vec<OwnedPath>,
    child_processes: Vec<u32>,
    publication_intent: Option<String>,
    run_root: PathBuf,
    disk_free_before: u64,
    disk_free_after: Option<u64>,
    cleaned_bytes: Option<u64>,
    retained_bytes: Option<u64>,
}

/// Explicit reconciliation of an interrupted journal, without reclaiming residue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmptyRunRetirement {
    /// Existing adapter journal whose exact preimage was supplied by the caller.
    pub journal_path: PathBuf,
    /// Immutable record preserving the original bytes and committed postimage.
    pub record_path: PathBuf,
    /// Always `EMPTY_RESIDUE_RETAINED`; this is not a cleanup or publication result.
    pub disposition: String,
    /// Zero: no directory or resource content is removed.
    pub cleaned_bytes: u64,
    /// Observed payload bytes in the empty residue, rather than a directory-removal claim.
    pub retained_bytes: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyRetirementRecord {
    version: u8,
    journal_path: PathBuf,
    compiler_path: PathBuf,
    original_journal: String,
    retired_journal: String,
    native_repository_identity: String,
    run_root_identity: String,
    staging_identity: String,
    target_identity: String,
    disposition: String,
}

struct DirectoryPins(Vec<(PathBuf, DirectoryIdentity)>);

impl DirectoryPins {
    fn capture(storage_root: &Path, paths: &[PathBuf]) -> io::Result<Self> {
        let mut pinned = Self(Vec::new());
        for ancestor in storage_root
            .ancestors()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            pinned.add(ancestor)?;
        }
        for path in paths {
            let relative = path
                .strip_prefix(storage_root)
                .map_err(|_| invalid("retirement directory escapes storage"))?;
            let mut component = storage_root.to_path_buf();
            pinned.add(&component)?;
            for next in relative.components() {
                if !matches!(next, std::path::Component::Normal(_)) {
                    return Err(invalid("invalid retirement directory component"));
                }
                component.push(next);
                pinned.add(&component)?;
            }
        }
        pinned.recheck()?;
        Ok(pinned)
    }

    fn add(&mut self, path: &Path) -> io::Result<()> {
        if self.0.iter().any(|(existing, _)| existing == path) {
            return Ok(());
        }
        if self.0.len() >= RETIREMENT_DIRECTORY_LIMIT {
            return Err(invalid("retirement directory identity bound exceeded"));
        }
        let metadata = fs::symlink_metadata(path)?;
        if linked(&metadata) || !metadata.is_dir() {
            return Err(invalid("retirement directory is not ordinary"));
        }
        self.0
            .push((path.to_path_buf(), DirectoryIdentity::pin(path)?));
        Ok(())
    }

    fn key(&self, path: &Path) -> io::Result<String> {
        self.0
            .iter()
            .find(|(pinned, _)| pinned == path)
            .map(|(_, identity)| identity.key().to_owned())
            .ok_or_else(|| invalid("missing retained directory identity"))
    }

    fn recheck(&self) -> io::Result<()> {
        for (path, identity) in &self.0 {
            let metadata = fs::symlink_metadata(path)?;
            if linked(&metadata) || !metadata.is_dir() || !identity.matches(path)? {
                return Err(io::Error::other("retirement directory identity changed"));
            }
        }
        Ok(())
    }
}

fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn ordinary_record(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if linked(&metadata) || !metadata.is_file() {
        return Err(invalid("retirement record is not ordinary"));
    }
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(u64::try_from(limit).map_err(io::Error::other)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit || u64::try_from(bytes.len()).map_err(io::Error::other)? != before.len()
    {
        return Err(invalid("retirement record exceeds its bound or changed"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut repeated = Vec::new();
    (&mut file)
        .take(u64::try_from(limit).map_err(io::Error::other)? + 1)
        .read_to_end(&mut repeated)?;
    let after = fs::symlink_metadata(path)?;
    let current = File::open(path)?;
    if linked(&after)
        || !after.is_file()
        || after.len() != before.len()
        || after.modified()? != before.modified()?
        || repeated != bytes
        || !crate::heavy_admission::same_file(&file, &current)?
    {
        return Err(io::Error::other("retirement record changed during capture"));
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn persist_retirement_record(path: &Path, bytes: &[u8], limit: usize) -> io::Result<()> {
    if bytes.len() > limit {
        return Err(invalid("retirement output exceeds its bound"));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {
            if ordinary_record(path, limit)? != bytes {
                return Err(io::Error::other(
                    "conflicting retirement output is retained",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        Err(error) => return Err(error),
    }
    if ordinary_record(path, limit)? != bytes {
        return Err(io::Error::other("retirement output readback differs"));
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()?;
    Ok(())
}

#[derive(Deserialize, Serialize)]
struct OwnerMarker {
    run_nonce: String,
    root_identity: String,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
struct TargetMarker {
    root_identity: String,
    namespace: String,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn identity(repository: &Path) -> String {
    format!(
        "{:x}",
        Sha256::digest(repository.as_os_str().as_encoded_bytes())
    )
}

fn nonce() -> io::Result<String> {
    let mut bytes = [0_u8; 12];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    let mut value = String::with_capacity(24);
    for byte in bytes {
        write!(value, "{byte:02x}").map_err(io::Error::other)?;
    }
    Ok(value)
}

fn free_bytes(root: &Path) -> io::Result<u64> {
    #[cfg(windows)]
    let root_text = root.to_string_lossy();
    #[cfg(windows)]
    let comparable_root = PathBuf::from(root_text.strip_prefix(r"\\?\").unwrap_or(&root_text));
    #[cfg(not(windows))]
    let comparable_root = root.to_path_buf();
    let disks = Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .filter(|disk| comparable_root.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(sysinfo::Disk::available_space)
        .ok_or_else(|| io::Error::other("execution storage disk was not observable"))
}

fn tree_bytes(root: &Path) -> io::Result<u64> {
    if !root.exists() {
        return Ok(0);
    }
    let mut total = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(invalid("symbolic link in owned execution storage"));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    Ok(total)
}

fn write_journal(path: &Path, journal: &RunJournal) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).map_err(io::Error::other)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()
}

/// Operational storage boundary for one installed repository.
pub struct RuntimeStorage {
    repository: PathBuf,
    storage_root: PathBuf,
    root_identity: String,
    policy: StoragePolicy,
}

impl RuntimeStorage {
    /// Validate a physical repository and an external local storage root.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid policy, inaccessible paths, or a storage
    /// root inside the repository.
    pub fn new(repository: &Path, storage_root: &Path, policy: StoragePolicy) -> io::Result<Self> {
        if policy.max_heavy_jobs != 1 {
            return Err(invalid("runtime currently requires one heavy job lease"));
        }
        let repository = repository.canonicalize()?;
        let storage_root = storage_root.canonicalize()?;
        if storage_root.starts_with(&repository) {
            return Err(invalid(
                "execution storage must remain outside the repository",
            ));
        }
        let root_identity = identity(&repository);
        Ok(Self {
            repository,
            storage_root,
            root_identity,
            policy,
        })
    }

    fn registry(&self) -> PathBuf {
        self.storage_root
            .join("rust")
            .join("x")
            .join(&self.root_identity[..16])
    }

    fn target(&self) -> PathBuf {
        self.storage_root
            .join("rust")
            .join("c")
            .join(&self.root_identity[..16])
    }

    fn lease(&self) -> io::Result<File> {
        fs::create_dir_all(self.registry())?;
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.registry().join("heavy.lock"))?;
        lease.try_lock()?;
        Ok(lease)
    }

    fn existing_lease(&self) -> io::Result<File> {
        let path = self.registry().join("heavy.lock");
        let metadata = fs::symlink_metadata(&path)?;
        if linked(&metadata) || !metadata.is_file() {
            return Err(invalid("existing runtime lease is uncertain"));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(3);
        }
        let lease = options.open(&path)?;
        lease.try_lock()?;
        Ok(lease)
    }

    fn retirable_journal(&self, run_nonce: &str, bytes: &[u8]) -> io::Result<RunJournal> {
        if bytes.len() > RETIREMENT_JOURNAL_LIMIT {
            return Err(invalid("retirement journal exceeds its bound"));
        }
        let journal: RunJournal =
            crate::wire::parse_strict_json_bytes(bytes).map_err(io::Error::other)?;
        let authored: serde_json::Value =
            crate::wire::parse_strict_json_bytes(bytes).map_err(io::Error::other)?;
        let known = serde_json::to_value(&journal).map_err(io::Error::other)?;
        if authored
            .as_object()
            .map(|object| object.keys().collect::<Vec<_>>())
            != known
                .as_object()
                .map(|object| object.keys().collect::<Vec<_>>())
            || journal.run_nonce != run_nonce
            || journal.root_identity != self.root_identity
            || journal.run_root
                != self
                    .storage_root
                    .join("rust/r")
                    .join(&self.root_identity[..16])
                    .join(run_nonce)
            || journal.lease_state != "ACTIVE"
            || !matches!(journal.lifecycle.as_str(), "VALIDATING" | "PUBLISHED")
            || !journal.child_processes.is_empty()
            || !journal.owned.is_empty()
            || !journal.preexisting_files.is_empty()
            || journal.resource_kinds != ["shared_compiler", "owned_staging"]
            || journal.disk_free_after.is_some()
            || journal.cleaned_bytes.is_some()
            || journal.retained_bytes.is_some()
            || journal
                .owner_identity
                .strip_prefix(&format!("{}:", self.repository.display()))
                .and_then(|owner| owner.parse::<u32>().ok())
                .is_none_or(|owner| owner == 0)
            || (journal.lifecycle == "PUBLISHED" && journal.publication_intent.is_none())
        {
            return Err(invalid("journal is not an eligible interrupted empty run"));
        }
        Ok(journal)
    }

    fn empty_residue(&self, run_root: &Path) -> io::Result<()> {
        let mut entries = fs::read_dir(run_root)?;
        let entry = entries
            .next()
            .transpose()?
            .ok_or_else(|| invalid("missing empty staging directory"))?;
        if entry.file_name() != "s"
            || entries.next().is_some()
            || fs::read_dir(run_root.join("s"))?.next().is_some()
            || fs::read_dir(self.target())?.next().is_some()
        {
            return Err(invalid("unmarked runtime residue is not exactly empty"));
        }
        Ok(())
    }

    fn retirement_record_from_bytes(
        &self,
        run_nonce: &str,
        expected_digest: &str,
        native_identity: &str,
        bytes: &[u8],
    ) -> io::Result<EmptyRetirementRecord> {
        let record: EmptyRetirementRecord =
            crate::wire::parse_strict_json_bytes(bytes).map_err(io::Error::other)?;
        let original = self.retirable_journal(run_nonce, record.original_journal.as_bytes())?;
        let retired: RunJournal =
            crate::wire::parse_strict_json_bytes(record.retired_journal.as_bytes())
                .map_err(io::Error::other)?;
        let mut expected = original;
        expected.lifecycle = "FAILED".into();
        expected.lease_state = "RELEASED".into();
        expected.cleaned_bytes = Some(0);
        expected.retained_bytes = Some(0);
        expected.disk_free_after = retired.disk_free_after;
        if record.version != 1
            || record.journal_path != self.registry().join(format!("{run_nonce}.json"))
            || record.compiler_path != self.target()
            || record.disposition != "EMPTY_RESIDUE_RETAINED"
            || record.native_repository_identity != native_identity
            || ![
                &record.run_root_identity,
                &record.staging_identity,
                &record.target_identity,
            ]
            .into_iter()
            .all(|key| lower_hex(key, 64))
            || digest(record.original_journal.as_bytes()) != expected_digest
            || retired != expected
            || retired.disk_free_after.is_none()
            || serde_json::to_vec_pretty(&retired).map_err(io::Error::other)?
                != record.retired_journal.as_bytes()
        {
            return Err(invalid("retirement record binding conflict"));
        }
        Ok(record)
    }

    fn new_retirement_record(
        &self,
        run_nonce: &str,
        expected_digest: &str,
        native_identity: &str,
        current: &[u8],
    ) -> io::Result<EmptyRetirementRecord> {
        if digest(current) != expected_digest {
            return Err(invalid("exact retirement journal digest differs"));
        }
        let original = self.retirable_journal(run_nonce, current)?;
        let pins = DirectoryPins::capture(
            &self.storage_root,
            &[
                original.run_root.clone(),
                original.run_root.join("s"),
                self.target(),
            ],
        )?;
        self.empty_residue(&original.run_root)?;
        let mut retired = original.clone();
        retired.lifecycle = "FAILED".into();
        retired.lease_state = "RELEASED".into();
        retired.cleaned_bytes = Some(0);
        retired.retained_bytes = Some(0);
        retired.disk_free_after = Some(free_bytes(&self.storage_root)?);
        let record = EmptyRetirementRecord {
            version: 1,
            journal_path: self.registry().join(format!("{run_nonce}.json")),
            compiler_path: self.target(),
            original_journal: String::from_utf8(current.to_vec()).map_err(io::Error::other)?,
            retired_journal: String::from_utf8(
                serde_json::to_vec_pretty(&retired).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?,
            native_repository_identity: native_identity.into(),
            run_root_identity: pins.key(&original.run_root)?,
            staging_identity: pins.key(&original.run_root.join("s"))?,
            target_identity: pins.key(&self.target())?,
            disposition: "EMPTY_RESIDUE_RETAINED".into(),
        };
        pins.recheck()?;
        self.empty_residue(&original.run_root)?;
        Ok(record)
    }

    fn recheck_retirement(
        &self,
        pins: &DirectoryPins,
        registry_pins: &DirectoryPins,
        admission: &HeavyAdmissionGuard,
        run_root: &Path,
    ) -> io::Result<()> {
        pins.recheck()?;
        registry_pins.recheck()?;
        if !admission.directory().matches(&self.repository)? {
            return Err(io::Error::other("retirement repository identity changed"));
        }
        self.empty_residue(run_root)
    }

    fn commit_empty_retirement(
        &self,
        record: &EmptyRetirementRecord,
        current: &[u8],
        registry_pins: &DirectoryPins,
        admission: &HeavyAdmissionGuard,
    ) -> io::Result<()> {
        let original: RunJournal =
            crate::wire::parse_strict_json_bytes(record.original_journal.as_bytes())
                .map_err(io::Error::other)?;
        let pins = DirectoryPins::capture(
            &self.storage_root,
            &[
                original.run_root.clone(),
                original.run_root.join("s"),
                self.target(),
            ],
        )?;
        if pins.key(&original.run_root)? != record.run_root_identity
            || pins.key(&original.run_root.join("s"))? != record.staging_identity
            || pins.key(&self.target())? != record.target_identity
        {
            return Err(io::Error::other(
                "empty runtime residue incarnation changed",
            ));
        }
        self.recheck_retirement(&pins, registry_pins, admission, &original.run_root)?;
        if current == record.retired_journal.as_bytes() {
            return Ok(());
        }
        if current != record.original_journal.as_bytes() {
            return Err(io::Error::other(
                "journal matches neither retirement preimage nor postimage",
            ));
        }
        let record_path = self
            .registry()
            .join(format!("{}.retained", original.run_nonce));
        let pending_path = self
            .registry()
            .join(format!("{}.retirement-pending", original.run_nonce));
        self.reserve(
            u64::try_from(RETIREMENT_RECORD_LIMIT + RETIREMENT_JOURNAL_LIMIT)
                .map_err(io::Error::other)?,
        )?;
        persist_retirement_record(
            &record_path,
            &serde_json::to_vec_pretty(record).map_err(io::Error::other)?,
            RETIREMENT_RECORD_LIMIT,
        )?;
        self.recheck_retirement(&pins, registry_pins, admission, &original.run_root)?;
        persist_retirement_record(
            &pending_path,
            record.retired_journal.as_bytes(),
            RETIREMENT_JOURNAL_LIMIT,
        )?;
        self.recheck_retirement(&pins, registry_pins, admission, &original.run_root)?;
        if ordinary_record(&record.journal_path, RETIREMENT_JOURNAL_LIMIT)?
            != record.original_journal.as_bytes()
        {
            return Err(io::Error::other(
                "journal preimage changed before retirement",
            ));
        }
        if ordinary_record(&pending_path, RETIREMENT_JOURNAL_LIMIT)?
            != record.retired_journal.as_bytes()
        {
            return Err(io::Error::other("pending retirement postimage changed"));
        }
        fs::rename(&pending_path, &record.journal_path)?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&record.journal_path)?
            .sync_all()?;
        if ordinary_record(&record.journal_path, RETIREMENT_JOURNAL_LIMIT)?
            != record.retired_journal.as_bytes()
        {
            return Err(io::Error::other("retired journal postimage differs"));
        }
        self.recheck_retirement(&pins, registry_pins, admission, &original.run_root)
    }

    /// Explicitly retire one exact interrupted journal while retaining unmarked residue.
    ///
    /// The caller supplies a reviewed `sha256:` digest of the existing journal.
    /// This operation does not establish historical directory ownership, repair
    /// publication, reclaim directories, or certify the interrupted operation.
    /// Both existing lease domains must be idle. Only an empty target and a run
    /// containing its empty ordinary `s` directory are admitted. The immutable
    /// record preserves the exact original bytes before a same-directory journal
    /// replacement records `FAILED`/`RELEASED` with zero bytes cleaned.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched preimages, locks, registrations, identities,
    /// populated or uncertain residue, conflicting records, or unconfirmed writes.
    /// Partial records remain for inspection; no failed write is guessed complete.
    pub fn retain_empty_interrupted_run(
        &self,
        run_nonce: &str,
        expected_journal_digest: &str,
    ) -> io::Result<EmptyRunRetirement> {
        if !lower_hex(run_nonce, 24)
            || expected_journal_digest
                .strip_prefix("sha256:")
                .is_none_or(|value| !lower_hex(value, 64))
        {
            return Err(invalid("invalid exact retirement binding"));
        }
        let journal_path = self.registry().join(format!("{run_nonce}.json"));
        let record_path = self.registry().join(format!("{run_nonce}.retained"));
        let registry_pins = DirectoryPins::capture(&self.storage_root, &[self.registry()])?;
        let admission = HeavyAdmissionGuard::acquire_existing_for_recovery(
            DirectoryIdentity::capture(&self.repository)?,
            &self.root_identity,
        )?;
        let _lease = self.existing_lease()?;
        admission.validate_retirement(
            &self.root_identity,
            run_nonce,
            &journal_path,
            &self.target(),
        )?;
        if admission.compiler_bytes(&self.target())? > self.policy.compiler_budget_bytes {
            return Err(io::Error::other("compiler target exceeded local budget"));
        }
        let current = ordinary_record(&journal_path, RETIREMENT_JOURNAL_LIMIT)?;
        let existing_record = match fs::symlink_metadata(&record_path) {
            Ok(_) => Some(ordinary_record(&record_path, RETIREMENT_RECORD_LIMIT)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let report = EmptyRunRetirement {
            journal_path: journal_path.clone(),
            record_path: record_path.clone(),
            disposition: "EMPTY_RESIDUE_RETAINED".into(),
            cleaned_bytes: 0,
            retained_bytes: 0,
        };
        let record = if let Some(bytes) = existing_record {
            self.retirement_record_from_bytes(
                run_nonce,
                expected_journal_digest,
                admission.directory().key(),
                &bytes,
            )?
        } else {
            self.new_retirement_record(
                run_nonce,
                expected_journal_digest,
                admission.directory().key(),
                &current,
            )?
        };
        self.commit_empty_retirement(&record, &current, &registry_pins, &admission)?;
        Ok(report)
    }

    fn ensure_no_unresolved_run(&self) -> io::Result<()> {
        for entry in fs::read_dir(self.registry())? {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let journal: RunJournal = crate::wire::parse_strict_json_bytes(&fs::read(path)?)
                .map_err(|_| io::Error::other("uncertain prior execution journal"))?;
            if journal.root_identity == self.root_identity
                && journal.run_root.exists()
                && (journal.lease_state != "RELEASED"
                    || journal.lifecycle == "RECOVERY_REQUIRED"
                    || !journal.child_processes.is_empty())
            {
                return Err(io::Error::other(
                    "unresolved prior run retains the shared target",
                ));
            }
        }
        Ok(())
    }

    /// Reject insufficient disk headroom before any repository mutation.
    ///
    /// # Errors
    ///
    /// Returns an error if free space cannot be observed or is insufficient.
    pub fn reserve(&self, bytes: u64) -> io::Result<u64> {
        let free = free_bytes(&self.storage_root)?;
        if free.saturating_sub(bytes) < self.policy.reserve_bytes {
            return Err(io::Error::other("insufficient execution storage reserve"));
        }
        Ok(free)
    }

    /// Acquire an exclusive heavy-job lease and an owned staging directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the lease, disk reserve, budget, or journal fails.
    pub fn acquire_workspace(&self) -> io::Result<RunWorkspace> {
        let mut admission =
            HeavyAdmissionGuard::acquire(DirectoryIdentity::capture(&self.repository)?)?;
        admission.validate_target("rust", &self.target())?;
        let lease = self.lease()?;
        self.ensure_no_unresolved_run()?;
        let disk_free_before = self.reserve(0)?;
        let target = self.target();
        fs::create_dir_all(&target)?;
        let marker_path = target.join("_owner.json");
        let expected_marker = TargetMarker {
            root_identity: self.root_identity.clone(),
            namespace: "rust".into(),
        };
        if marker_path.exists() {
            let marker: TargetMarker =
                crate::wire::parse_strict_json_bytes(&fs::read(&marker_path)?)
                    .map_err(|_| io::Error::other("uncertain compiler target owner"))?;
            if marker != expected_marker {
                return Err(io::Error::other("compiler target owner mismatch"));
            }
        } else if fs::read_dir(&target)?.next().is_some() {
            return Err(io::Error::other("unmarked compiler target is not owned"));
        } else {
            fs::write(
                &marker_path,
                serde_json::to_vec(&expected_marker).map_err(io::Error::other)?,
            )?;
        }
        if admission.compiler_bytes(&target)? > self.policy.compiler_budget_bytes {
            return Err(io::Error::other("compiler target exceeded local budget"));
        }
        let run_nonce = nonce()?;
        let run_root = self
            .storage_root
            .join("rust")
            .join("r")
            .join(&self.root_identity[..16])
            .join(&run_nonce);
        fs::create_dir_all(run_root.join("s"))?;
        let marker = OwnerMarker {
            run_nonce: run_nonce.clone(),
            root_identity: self.root_identity.clone(),
        };
        fs::write(
            run_root.join("owner.json"),
            serde_json::to_vec(&marker).map_err(io::Error::other)?,
        )?;
        let journal = RunJournal {
            run_nonce: run_nonce.clone(),
            root_identity: self.root_identity.clone(),
            owner_identity: format!("{}:{}", self.repository.display(), std::process::id()),
            lease_state: "ACTIVE".into(),
            lifecycle: "RUNNING".into(),
            resource_kinds: vec!["shared_compiler".into(), "owned_staging".into()],
            preexisting_files: Vec::new(),
            owned: Vec::new(),
            child_processes: Vec::new(),
            publication_intent: None,
            run_root: run_root.clone(),
            disk_free_before,
            disk_free_after: None,
            cleaned_bytes: None,
            retained_bytes: None,
        };
        let journal_path = self.registry().join(format!("{run_nonce}.json"));
        write_journal(&journal_path, &journal)?;
        admission.register(
            "rust",
            &self.root_identity,
            &run_nonce,
            &journal_path,
            &target,
        )?;
        Ok(RunWorkspace {
            lease: Some(lease),
            admission: Some(admission),
            journal,
            journal_path,
            target,
            policy: self.policy.clone(),
            storage_root: self.storage_root.clone(),
            done: false,
        })
    }

    /// Recover only marked, inactive staging; retain uncertain runs for review.
    ///
    /// # Errors
    ///
    /// Returns an error if the registry cannot be leased or safely inspected.
    pub fn recover_owned_orphans(&self) -> io::Result<Vec<(PathBuf, String)>> {
        let mut admission = HeavyAdmissionGuard::acquire_for_recovery(
            DirectoryIdentity::capture(&self.repository)?,
            "rust",
            &self.root_identity,
        )?;
        let _lease = self.lease()?;
        let mut results = Vec::new();
        for entry in fs::read_dir(self.registry())? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                results.push((path, "RETAINED_UNCERTAIN".into()));
                continue;
            };
            let Ok(mut journal) = crate::wire::parse_strict_json_bytes::<RunJournal>(&bytes) else {
                results.push((path, "RETAINED_UNCERTAIN".into()));
                continue;
            };
            let expected = self
                .storage_root
                .join("rust")
                .join("r")
                .join(&self.root_identity[..16])
                .join(&journal.run_nonce);
            if journal.root_identity != self.root_identity
                || journal.run_root != expected
                || journal.lifecycle == "RUNNING"
                || !journal.child_processes.is_empty()
            {
                results.push((path, "RETAINED_UNCERTAIN".into()));
                continue;
            }
            if !expected.exists() {
                continue;
            }
            let marker = fs::read(expected.join("owner.json"))
                .ok()
                .and_then(|value| crate::wire::parse_strict_json_bytes::<OwnerMarker>(&value).ok());
            if marker.is_none_or(|marker| {
                marker.run_nonce != journal.run_nonce || marker.root_identity != self.root_identity
            }) {
                results.push((path, "RETAINED_UNCERTAIN".into()));
                continue;
            }
            let bytes = tree_bytes(&expected)?;
            fs::remove_dir_all(&expected)?;
            journal.lifecycle = "CLEANUP_COMPLETE".into();
            journal.lease_state = "RELEASED".into();
            journal.cleaned_bytes = Some(bytes);
            journal.retained_bytes = Some(tree_bytes(&self.target())?);
            journal.disk_free_after = Some(free_bytes(&self.storage_root)?);
            write_journal(&path, &journal)?;
            results.push((path, "RECOVERED".into()));
        }
        admission.complete_owned("rust", &self.root_identity)?;
        Ok(results)
    }
}

/// One leased runtime workspace; Drop cleans catchable exits.
pub struct RunWorkspace {
    lease: Option<File>,
    admission: Option<HeavyAdmissionGuard>,
    journal: RunJournal,
    journal_path: PathBuf,
    target: PathBuf,
    policy: StoragePolicy,
    storage_root: PathBuf,
    done: bool,
}

impl RunWorkspace {
    /// Job-specific staging directory, distinct from the shared target.
    #[must_use]
    pub fn staging(&self) -> PathBuf {
        self.journal.run_root.join("s")
    }

    /// Leased compiler target for this physical repository.
    #[must_use]
    pub fn compiler_target(&self) -> &Path {
        &self.target
    }

    /// Recheck free space and the compiler budget while work progresses.
    ///
    /// # Errors
    ///
    /// Returns an error if disk observation fails or a budget is exceeded.
    pub fn reserve(&self, bytes: u64) -> io::Result<()> {
        let free = free_bytes(&self.storage_root)?;
        if free.saturating_sub(bytes) < self.policy.reserve_bytes {
            return Err(io::Error::other("insufficient execution storage reserve"));
        }
        let compiler_bytes = self
            .admission
            .as_ref()
            .ok_or_else(|| invalid("runtime admission was released"))?
            .compiler_bytes(&self.target)?;
        if compiler_bytes > self.policy.compiler_budget_bytes {
            return Err(io::Error::other("compiler target exceeded local budget"));
        }
        Ok(())
    }

    /// Record exact owned staging bytes for later publication or recovery.
    ///
    /// # Errors
    ///
    /// Returns an error for an out-of-scope path, mismatched digest, or I/O.
    pub fn record_owned(&mut self, path: &Path, digest: &str) -> io::Result<()> {
        let path = path.canonicalize()?;
        if !path.starts_with(self.staging()) {
            return Err(invalid("owned output must be within this run's staging"));
        }
        let actual = format!("sha256:{:x}", Sha256::digest(fs::read(&path)?));
        if actual != digest {
            return Err(invalid("owned output digest mismatch"));
        }
        self.journal.owned.push(OwnedPath {
            path,
            digest: digest.into(),
        });
        write_journal(&self.journal_path, &self.journal)
    }

    /// Record a child before it can write into this workspace.
    ///
    /// # Errors
    ///
    /// Returns an error if the local journal cannot be persisted.
    pub fn record_child(&mut self, pid: u32) -> io::Result<()> {
        self.journal.child_processes.push(pid);
        write_journal(&self.journal_path, &self.journal)
    }

    /// Clear a child only after it has exited and been waited for.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown child or failed journal persistence.
    pub fn clear_child(&mut self, pid: u32) -> io::Result<()> {
        let position = self
            .journal
            .child_processes
            .iter()
            .position(|child| *child == pid)
            .ok_or_else(|| invalid("child was not recorded"))?;
        self.journal.child_processes.remove(position);
        write_journal(&self.journal_path, &self.journal)
    }

    /// Mark validation complete before a caller publishes its final pointer.
    ///
    /// # Errors
    ///
    /// Returns an error if the local journal cannot be persisted.
    pub fn validating(&mut self) -> io::Result<()> {
        self.journal.lifecycle = "VALIDATING".into();
        write_journal(&self.journal_path, &self.journal)
    }

    /// Record the generation published by the caller's final pointer update.
    ///
    /// # Errors
    ///
    /// Returns an error unless validation completed or journal storage fails.
    pub fn publish(&mut self, generation: &str) -> io::Result<()> {
        if self.journal.lifecycle != "VALIDATING" {
            return Err(invalid("publication requires validated staging"));
        }
        self.journal.publication_intent = Some(generation.into());
        self.journal.lifecycle = "PUBLISHED".into();
        write_journal(&self.journal_path, &self.journal)
    }

    fn finish(&mut self) -> io::Result<StorageReport> {
        let staging_bytes = tree_bytes(&self.journal.run_root)?;
        let compiler_bytes = tree_bytes(&self.target)?;
        let (cleaned_bytes, retained_bytes, lifecycle) = if self.journal.child_processes.is_empty()
        {
            let retained_compiler = if self.policy.retain_shared_compiler {
                compiler_bytes
            } else {
                let marker: TargetMarker = crate::wire::parse_strict_json_bytes(&fs::read(
                    self.target.join("_owner.json"),
                )?)
                .map_err(|_| io::Error::other("uncertain compiler target owner"))?;
                if marker.root_identity != self.journal.root_identity || marker.namespace != "rust"
                {
                    return Err(io::Error::other("compiler target owner mismatch"));
                }
                fs::remove_dir_all(&self.target)?;
                0
            };
            fs::remove_dir_all(&self.journal.run_root)?;
            let state = if self.journal.lifecycle == "PUBLISHED" {
                "CLEANUP_COMPLETE"
            } else {
                "FAILED"
            };
            (
                staging_bytes + compiler_bytes - retained_compiler,
                retained_compiler,
                state,
            )
        } else {
            (0, staging_bytes + compiler_bytes, "RECOVERY_REQUIRED")
        };
        let disk_free_after = free_bytes(&self.storage_root)?;
        self.journal.lifecycle = lifecycle.into();
        self.journal.lease_state = "RELEASED".into();
        self.journal.cleaned_bytes = Some(cleaned_bytes);
        self.journal.retained_bytes = Some(retained_bytes);
        self.journal.disk_free_after = Some(disk_free_after);
        write_journal(&self.journal_path, &self.journal)?;
        if let Some(admission) = &mut self.admission {
            admission.complete_owned("rust", &self.journal.root_identity)?;
        }
        self.done = true;
        self.lease.take();
        self.admission.take();
        Ok(StorageReport {
            disk_free_before: self.journal.disk_free_before,
            disk_free_after,
            cleaned_bytes,
            retained_bytes,
            lifecycle: lifecycle.into(),
        })
    }

    /// Release the lease and report cleaned and retained storage.
    ///
    /// # Errors
    ///
    /// Returns an error if staging cleanup, disk observation, or journaling fails.
    pub fn release(mut self) -> io::Result<StorageReport> {
        self.finish()
    }
}

impl Drop for RunWorkspace {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.finish();
        }
    }
}
