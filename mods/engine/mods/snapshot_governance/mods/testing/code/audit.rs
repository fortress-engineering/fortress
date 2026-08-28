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
    assert_eq!(result.summary().rules_evaluated(), 16);
    assert_eq!(result.summary().passed(), 16);
    assert_eq!(result.summary().failed(), 0);
    assert_eq!(result.summary().unsupported(), 1);
    assert!(result.findings().is_empty());
    assert!(
        result
            .unsupported_analysis()
            .contains(&"capability_to_symbol_realization".to_owned())
    );
    assert_eq!(result.is_success(), result.findings().is_empty());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R13-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R13
#[test]
fn self_audit_reuses_one_applicable_intended_behavior_evaluation() {
    let result = audit_repository(repository_root()).expect("Fortress self-audit completes");
    let executions = result
        .rules()
        .iter()
        .filter(|rule| rule.rule_id() == "BEHAVIOR-FLOW-001")
        .collect::<Vec<_>>();
    assert_eq!(executions.len(), 1);
    assert!(executions[0].applicable());
    assert_eq!(executions[0].finding_count(), 0);
    assert!(executions[0].detail().contains("1 modeled Feature"));
}
