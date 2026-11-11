//! Retained same-volume migration resources under the shared OPS admission registry.
use super::{
    DirectoryIdentity, DirectoryPins, HeavyAdmissionGuard, StoragePolicy, free_bytes, linked,
    nonce, tree_bytes,
};
use crate::migration_governance::{MigrationError, MigrationResourceLease, ResourceLeasePort};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

fn err(e: impl std::fmt::Display) -> MigrationError {
    MigrationError {
        code: "MIGRATION_STORAGE_ERROR".into(),
        message: e.to_string(),
        transaction_ref: None,
    }
}
fn checked_dir(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::other("migration storage must be absolute"));
    }
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(m) if m.is_dir() && !linked(&m) => {}
            Ok(_) => return Err(io::Error::other("unsafe storage ancestor")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(ancestor)?,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseRecord {
    version: u16,
    root_identity: String,
    run_nonce: String,
    plan_ref: String,
    repository_identity: String,
    run_root: PathBuf,
    run_identity: String,
    lease_state: String,
    lifecycle: String,
    outcome: Option<String>,
    result_ref: Option<String>,
    child_processes: Vec<u32>,
}
/// Explicit external OPS storage selection. The repository cannot choose its own grant or lease.
pub struct MigrationStorage {
    root: PathBuf,
    policy: StoragePolicy,
}
impl MigrationStorage {
    /// Selects an external storage root; acquire verifies volume, ownership and reserve limits.
    /// # Errors
    /// Refuses relative storage or unsupported parallel admission policy.
    pub fn new(root: PathBuf, policy: StoragePolicy) -> Result<Self, MigrationError> {
        if !root.is_absolute() || policy.max_heavy_jobs != 1 {
            return Err(err(
                "migration requires absolute external storage and exclusive admission",
            ));
        }
        Ok(Self { root, policy })
    }
    fn open(
        &self,
        repository: &Path,
        transaction: Option<&str>,
        plan: Option<&str>,
        bytes: u64,
    ) -> Result<MigrationStorageLease, MigrationError> {
        let repository = repository.canonicalize().map_err(err)?;
        let directory = DirectoryIdentity::capture(&repository).map_err(err)?;
        let identity = directory.key().to_owned();
        let mut admission = if transaction.is_some() {
            HeavyAdmissionGuard::acquire_for_recovery(directory, "migration", &identity)
        } else {
            HeavyAdmissionGuard::acquire(directory)
        }
        .map_err(err)?;
        checked_dir(&self.root).map_err(err)?;
        let root = self.root.canonicalize().map_err(err)?;
        if root.starts_with(&repository) || repository.starts_with(&root) {
            return Err(err(
                "migration staging must be external, not a repository ancestor",
            ));
        }
        if !crate::heavy_admission::same_native_volume(&repository, &root).map_err(err)? {
            return Err(err(
                "migration requires explicitly selected same-volume external storage",
            ));
        }
        let short = &identity[..16];
        let registry = root.join("migration/x").join(short);
        let runs = root.join("migration/r").join(short);
        let compiler = root.join("migration/c").join(short);
        for path in [&registry, &runs] {
            checked_dir(path).map_err(err)?;
        }
        if bytes > self.policy.projection_budget_bytes
            || free_bytes(&root).map_err(err)?.saturating_sub(bytes) < self.policy.reserve_bytes
            || tree_bytes(&runs).map_err(err)?.saturating_add(bytes)
                > self.policy.projection_budget_bytes
        {
            return Err(err(
                "insufficient bounded migration storage or free-space reserve",
            ));
        }
        let id = match transaction {
            Some(id)
                if id.len() == 24
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
            {
                id.to_owned()
            }
            Some(_) => return Err(err("invalid transaction incarnation")),
            None => nonce().map_err(err)?,
        };
        let journal_path = registry.join(format!("{id}.json"));
        let run = runs.join(&id);
        let record = acquire_record(
            transaction.is_some(),
            plan,
            &identity,
            &id,
            &journal_path,
            &run,
        )?;
        let pins = DirectoryPins::capture(&root, &[registry.clone(), runs.clone(), run.clone()])
            .map_err(err)?;
        let lock_path = run.join("lease.lock");
        if lock_path.exists() {
            let m = fs::symlink_metadata(&lock_path).map_err(err)?;
            if linked(&m) || !m.is_file() {
                return Err(err("invalid transaction lease"));
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(3);
        }
        let lock = options.open(&lock_path).map_err(err)?;
        lock.try_lock().map_err(err)?;
        let mut owned = MigrationStorageLease {
            root: run,
            storage_root: root,
            policy: self.policy.clone(),
            record,
            journal_path,
            pins,
            admission: None,
            _lock: lock,
        };
        owned.record.lease_state = "HELD".into();
        if transaction.is_none() {
            owned.save()?;
        }
        admission
            .register("migration", &identity, &id, &owned.journal_path, &compiler)
            .map_err(err)?;
        owned.admission = Some(admission);
        owned.verify(&repository)?;
        Ok(owned)
    }
}
impl ResourceLeasePort for MigrationStorage {
    type Lease = MigrationStorageLease;
    fn acquire(
        &self,
        repository: &Path,
        plan: &str,
        bytes: u64,
    ) -> Result<Self::Lease, MigrationError> {
        self.open(repository, None, Some(plan), bytes)
    }
    fn recover(
        &self,
        repository: &Path,
        transaction: &str,
        plan: &str,
    ) -> Result<Self::Lease, MigrationError> {
        self.open(repository, Some(transaction), Some(plan), 0)
    }
}
/// Exclusive process-local resource ownership. Drop retains all recovery material and active state.
pub struct MigrationStorageLease {
    root: PathBuf,
    storage_root: PathBuf,
    policy: StoragePolicy,
    record: LeaseRecord,
    journal_path: PathBuf,
    pins: DirectoryPins,
    admission: Option<HeavyAdmissionGuard>,
    _lock: File,
}
impl MigrationStorageLease {
    fn save(&self) -> Result<(), MigrationError> {
        self.pins.recheck().map_err(err)?;
        let bytes = serde_json::to_vec(&self.record).map_err(err)?;
        if bytes.len() > 65536 {
            return Err(err("owner record exceeds admission"));
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&self.journal_path)
            .map_err(err)?;
        file.write_all(&bytes).map_err(err)?;
        file.sync_all().map_err(err)
    }
}
impl MigrationResourceLease for MigrationStorageLease {
    fn root(&self) -> &Path {
        &self.root
    }
    fn transaction_ref(&self) -> &str {
        &self.record.run_nonce
    }
    fn repository_identity(&self) -> &str {
        &self.record.repository_identity
    }
    fn verify(&self, repository: &Path) -> Result<(), MigrationError> {
        self.pins.recheck().map_err(err)?;
        if crate::heavy_admission::native_object_identity(repository).map_err(err)?
            != self.record.repository_identity
            || crate::heavy_admission::native_object_identity(&self.root).map_err(err)?
                != self.record.run_identity
            || !crate::heavy_admission::same_native_volume(repository, &self.root).map_err(err)?
        {
            return Err(err("migration physical ownership changed"));
        }
        Ok(())
    }
    fn reserve(&self, bytes: u64) -> Result<(), MigrationError> {
        self.pins.recheck().map_err(err)?;
        if bytes > self.policy.projection_budget_bytes
            || free_bytes(&self.storage_root)
                .map_err(err)?
                .saturating_sub(bytes)
                < self.policy.reserve_bytes
            || tree_bytes(
                self.root
                    .parent()
                    .ok_or_else(|| err("missing run parent"))?,
            )
            .map_err(err)?
            .saturating_add(bytes)
                > self.policy.projection_budget_bytes
        {
            return Err(err("migration storage quota or reserve exhausted"));
        }
        Ok(())
    }
    fn object_identity(&self, path: &Path) -> Result<String, MigrationError> {
        crate::heavy_admission::native_object_identity(path).map_err(err)
    }
    fn applying(&mut self, plan: &str, journal: &Path) -> Result<(), MigrationError> {
        if plan != self.record.plan_ref || journal != self.root.join("operations.jsonl") {
            return Err(err("application ownership or plan differs"));
        }
        self.pins.recheck().map_err(err)?;
        let phase = self.journal_path.with_extension("phase");
        if phase.exists() {
            let m = fs::symlink_metadata(&phase).map_err(err)?;
            if linked(&m) || !m.is_file() {
                return Err(err("unsafe phase marker"));
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(phase)
            .map_err(err)?;
        if file.metadata().map_err(err)?.len() > 65536 {
            return Err(err("phase history exceeds admission"));
        }
        file.write_all(b"APPLYING\n").map_err(err)?;
        file.sync_all().map_err(err)
    }
    fn finish(&mut self, outcome: &str, result: &str) -> Result<(), MigrationError> {
        if !matches!(
            outcome,
            "COMMITTED" | "ROLLED_BACK" | "ABORTED_BEFORE_APPLY"
        ) {
            return Err(err("unsupported terminal migration outcome"));
        }
        self.record.lifecycle = "COMPLETED_BYTES_VERIFIED".into();
        self.record.lease_state = "RELEASED".into();
        self.record.outcome = Some(outcome.into());
        self.record.result_ref = Some(result.into());
        self.pins.recheck().map_err(err)?;
        let completed = self.journal_path.with_extension("complete");
        let bytes = serde_json::to_vec(&self.record).map_err(err)?;
        let staged = self
            .root
            .join(format!("terminal-{}.json", nonce().map_err(err)?));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staged)
            .map_err(err)?;
        file.write_all(&bytes).map_err(err)?;
        file.sync_all().map_err(err)?;
        if fs::read(&staged).map_err(err)? != bytes {
            return Err(err("terminal staging changed"));
        }
        match fs::hard_link(&staged, &completed) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let m = fs::symlink_metadata(&completed).map_err(err)?;
                if linked(&m)
                    || !m.is_file()
                    || m.len() > 65536
                    || fs::read(&completed).map_err(err)? != bytes
                {
                    return Err(err("terminal migration record conflicts"));
                }
            }
            Err(e) => return Err(err(e)),
        }
        if let Some(admission) = &mut self.admission {
            admission
                .complete_owned("migration", &self.record.root_identity)
                .map_err(err)?;
        }
        Ok(())
    }
}

fn acquire_record(
    recovery: bool,
    plan: Option<&str>,
    identity: &str,
    id: &str,
    journal_path: &Path,
    run: &Path,
) -> Result<LeaseRecord, MigrationError> {
    let record = if recovery {
        let metadata = fs::symlink_metadata(journal_path).map_err(err)?;
        if !metadata.is_file() || linked(&metadata) || metadata.len() > 65536 {
            return Err(err("invalid migration owner record"));
        }
        let mut file = File::open(journal_path).map_err(err)?;
        let mut bytes = vec![];
        Read::by_ref(&mut file)
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        let record: LeaseRecord = crate::wire::parse_strict_json_bytes(&bytes).map_err(err)?;
        if record.version != 1
            || Some(record.plan_ref.as_str()) != plan
            || record.root_identity != identity
            || record.repository_identity != identity
            || record.run_nonce != id
            || record.run_root != run
            || record.run_identity
                != crate::heavy_admission::native_object_identity(run).map_err(err)?
        {
            return Err(err("recovery ownership binding differs"));
        }
        record
    } else {
        fs::create_dir(run).map_err(err)?;
        LeaseRecord {
            version: 1,
            root_identity: identity.to_owned(),
            run_nonce: id.to_owned(),
            plan_ref: plan.ok_or_else(|| err("missing plan identity"))?.into(),
            repository_identity: identity.to_owned(),
            run_root: run.to_path_buf(),
            run_identity: crate::heavy_admission::native_object_identity(run).map_err(err)?,
            lease_state: "HELD".into(),
            lifecycle: "PREPARING".into(),
            outcome: None,
            result_ref: None,
            child_processes: vec![],
        }
    };
    Ok(record)
}
