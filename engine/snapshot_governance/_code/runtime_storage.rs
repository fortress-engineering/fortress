//! Machine-local storage supervision for installed Rust runtime jobs.
//!
//! This adapter owns operational leases and journals only. Callers keep
//! semantic records, policy authority, and publication pointers elsewhere.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::Disks;

const GIB: u64 = 1024 * 1024 * 1024;

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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OwnedPath {
    path: PathBuf,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

    fn ensure_no_unresolved_run(&self) -> io::Result<()> {
        for entry in fs::read_dir(self.registry())? {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let journal: RunJournal = serde_json::from_slice(&fs::read(path)?)
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
            let marker: TargetMarker = serde_json::from_slice(&fs::read(&marker_path)?)
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
        if tree_bytes(&target)? > self.policy.compiler_budget_bytes {
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
        Ok(RunWorkspace {
            lease: Some(lease),
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
            let Ok(mut journal) = serde_json::from_slice::<RunJournal>(&bytes) else {
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
                .and_then(|value| serde_json::from_slice::<OwnerMarker>(&value).ok());
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
        Ok(results)
    }
}

/// One leased runtime workspace; Drop cleans catchable exits.
pub struct RunWorkspace {
    lease: Option<File>,
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
        if tree_bytes(&self.target)? > self.policy.compiler_budget_bytes {
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
                let marker: TargetMarker =
                    serde_json::from_slice(&fs::read(self.target.join("_owner.json"))?)
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
        self.done = true;
        self.lease.take();
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
