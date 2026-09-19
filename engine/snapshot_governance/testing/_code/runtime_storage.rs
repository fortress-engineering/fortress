//! Storage lifecycle contract vectors for the installed Rust runtime.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use fortress_core::runtime_storage::{RuntimeStorage, StoragePolicy};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "fortress-runtime-storage-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("repository")).expect("test repository");
        fs::create_dir_all(root.join("storage")).expect("test storage");
        Self(root)
    }

    fn storage(&self) -> RuntimeStorage {
        RuntimeStorage::new(
            &self.0.join("repository"),
            &self.0.join("storage"),
            StoragePolicy {
                reserve_bytes: 0,
                ..StoragePolicy::default()
            },
        )
        .expect("runtime storage")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn active_runtime_target_lease_prevents_second_job() {
    let fixture = Fixture::new();
    let runtime = fixture.storage();
    let first = runtime.acquire_workspace().expect("first lease");
    assert!(runtime.acquire_workspace().is_err());
    drop(first);
    assert!(runtime.acquire_workspace().is_ok());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn runtime_reserve_rejects_before_staging() {
    let fixture = Fixture::new();
    let runtime = RuntimeStorage::new(
        &fixture.0.join("repository"),
        &fixture.0.join("storage"),
        StoragePolicy {
            reserve_bytes: u64::MAX,
            ..StoragePolicy::default()
        },
    )
    .expect("runtime storage");
    assert!(runtime.acquire_workspace().is_err());
    assert!(!fixture.0.join("storage/rust/r").exists());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn runtime_retains_staging_for_unwaited_child() {
    let fixture = Fixture::new();
    let runtime = fixture.storage();
    let mut workspace = runtime.acquire_workspace().expect("workspace");
    let staging = workspace.staging();
    fs::write(staging.join("child-output"), b"in use").expect("child output");
    workspace
        .record_child(std::process::id())
        .expect("record child");
    let report = workspace.release().expect("release with uncertain child");
    assert_eq!(report.lifecycle, "RECOVERY_REQUIRED");
    assert!(staging.exists());
    let recovered = runtime.recover_owned_orphans().expect("recovery review");
    assert!(
        recovered
            .iter()
            .any(|(_, status)| status == "RETAINED_UNCERTAIN")
    );
    assert!(runtime.acquire_workspace().is_err());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn selected_runtime_compiler_cleanup_requires_marker() {
    let fixture = Fixture::new();
    let runtime = RuntimeStorage::new(
        &fixture.0.join("repository"),
        &fixture.0.join("storage"),
        StoragePolicy {
            reserve_bytes: 0,
            retain_shared_compiler: false,
            ..StoragePolicy::default()
        },
    )
    .expect("runtime storage");
    let mut workspace = runtime.acquire_workspace().expect("workspace");
    let target = workspace.compiler_target().to_path_buf();
    fs::write(target.join("compiled"), b"owned").expect("compiler output");
    workspace.validating().expect("validation");
    workspace.publish("generation").expect("publication");
    let report = workspace.release().expect("owned cleanup");
    assert_eq!(report.retained_bytes, 0);
    assert!(!target.exists());
}
