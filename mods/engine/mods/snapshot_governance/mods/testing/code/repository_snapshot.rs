//! Repository-level evidence for canonical stabilized Fortress snapshots.

use std::path::{Path, PathBuf};

use fortress_core::audit::audit_repository;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R01-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R01
#[test]
fn fortress_self_snapshot_is_repeatable_and_binds_distributed_contracts() {
    let root = repository_root();
    let first = audit_repository(&root).expect("first self audit builds a snapshot");
    let second = audit_repository(&root).expect("second self audit builds a snapshot");
    assert_eq!(first.snapshot_fingerprint(), second.snapshot_fingerprint());
    assert_eq!(first.to_json_pretty().ok(), second.to_json_pretty().ok());
    assert!(first.snapshot_fingerprint().starts_with("sha256:"));
}
