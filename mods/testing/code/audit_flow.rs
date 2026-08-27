//! Root-owned verification of the complete Fortress audit behavior.

use std::path::{Path, PathBuf};

use fortress_core::audit::{audit_repository, compile_repository_bfg};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `T-AF-FORTRESS-AUDIT-0001-R01-001`
/// Fortress requirement: AF-FORTRESS-AUDIT-0001-R01
#[test]
fn fortress_audit_intended_flow_spans_the_root_scope_coherently() {
    let graph = compile_repository_bfg(repository_root()).expect("self-BFG compiles");
    let flow = graph
        .flows()
        .iter()
        .find(|flow| flow.feature() == "AF-FORTRESS-AUDIT-0001")
        .expect("root audit Feature is modeled");
    assert_eq!(flow.owner(), "PF-FORTRESS");
    assert_eq!(flow.trigger_checkpoint(), Some("CHK-AUDIT-REQUESTED"));
    assert_eq!(flow.nodes().len(), 10);
    assert_eq!(flow.edges().len(), 9);
    assert_eq!(flow.terminal_checkpoints().len(), 2);
    assert_eq!(flow.participating_modules().len(), 6);
    assert_eq!(flow.module_boundary_crossings().len(), 8);
}

/// `T-AF-FORTRESS-AUDIT-0001-R01-002`
/// Fortress requirement: AF-FORTRESS-AUDIT-0001-R01
#[test]
fn fortress_audit_evaluates_the_modeled_flow_without_certification_claims() {
    let result = audit_repository(repository_root()).expect("self-audit completes");
    let behavior = result
        .rules()
        .iter()
        .find(|rule| rule.rule_id() == "BEHAVIOR-FLOW-001")
        .expect("behavior rule executes");
    assert!(behavior.applicable());
    assert_eq!(behavior.finding_count(), 0);
    assert!(behavior.detail().contains("1 coherent"));
    assert!(result.is_success());
}
