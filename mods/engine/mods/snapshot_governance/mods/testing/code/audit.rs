//! End-to-end self-application evidence for the Snapshot Governance audit.

use std::path::{Path, PathBuf};

use fortress_core::audit::audit_repository;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R08-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R08
#[test]
fn fortress_self_audit_passes_every_implemented_rule() {
    let result = audit_repository(repository_root()).expect("Fortress self-audit completes");
    assert!(result.is_success());
    assert_eq!(result.summary().rules_evaluated(), 8);
    assert_eq!(result.summary().passed(), 8);
    assert_eq!(result.summary().failed(), 0);
    assert_eq!(result.summary().unsupported(), 1);
    assert!(result.findings().is_empty());
}
