//! Repository-level evidence for truthful Snapshot Governance rule execution.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::architecture::{ArchitectureManifest, ComponentDeclaration};
use fortress_core::audit::audit_repository;
use fortress_core::evaluation::RuleExecutionState;
use serde::Deserialize;

#[derive(Deserialize)]
struct ArchitectureWire {
    components: Vec<ComponentWire>,
}

#[derive(Deserialize)]
struct ComponentWire {
    id: String,
    title: String,
    paths: Vec<String>,
    depends_on: Vec<String>,
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn invalid_architecture() -> ArchitectureManifest {
    let path = repository_root()
        .join("mods/engine/mods/architecture_evaluation/mods/testing/data/dependency_invalid.json");
    let source = fs::read_to_string(path).expect("negative fixture reads");
    let wire: ArchitectureWire = serde_json::from_str(&source).expect("fixture parses");
    ArchitectureManifest::from_components(
        wire.components
            .into_iter()
            .map(|component| {
                ComponentDeclaration::new(
                    component.id,
                    component.title,
                    component.paths,
                    component.depends_on,
                )
            })
            .collect(),
    )
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R04-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R04
#[test]
fn registered_architecture_evaluator_distinguishes_pass_and_failure() {
    let audit = audit_repository(repository_root()).expect("self audit completes");
    let execution = audit
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "ARCH-DEPENDENCY-001")
        .expect("dependency rule executes");
    assert_eq!(execution.state(), RuleExecutionState::Passed);

    let finding = invalid_architecture()
        .evaluate_acyclic_dependencies("1.0.0-draft.1")
        .expect("negative evaluation completes");
    assert!(finding.is_some());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R04-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R04
#[test]
fn missing_snapshot_evaluator_is_unsupported_not_passed() {
    let audit = audit_repository(repository_root()).expect("self audit completes");
    let unsupported = audit
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "STD-ID-001")
        .expect("STD-ID-001 execution is reported");
    assert_eq!(unsupported.state(), RuleExecutionState::Unsupported);
    assert_eq!(unsupported.finding_count(), 0);
    assert_eq!(audit.summary().unsupported(), 1);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R06-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R06
#[test]
fn fortress_active_requirements_have_complete_snapshot_bound_rust_evidence() {
    let audit = audit_repository(repository_root()).expect("self audit completes");
    let execution = audit
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "TEST-TRACEABILITY-001")
        .expect("traceability execution is reported");
    assert_eq!(execution.state(), RuleExecutionState::Passed);
    assert_eq!(execution.finding_count(), 0);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R11-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R11
#[test]
fn contract_coherency_passes_without_overclaiming_semantic_closure() {
    let audit = audit_repository(repository_root()).expect("self audit completes");
    let execution = audit
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "CONTRACT-COHERENCY-001")
        .expect("contract coherency execution is reported");
    assert_eq!(execution.state(), RuleExecutionState::Passed);
    assert_eq!(execution.finding_count(), 0);
    assert!(execution.detail().contains("general rule satisfiability"));
    assert!(execution.detail().contains("remain unsupported"));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R12-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R12
#[test]
fn recursive_testing_boundaries_pass_for_fortress_itself() {
    let audit = audit_repository(repository_root()).expect("self audit completes");
    let execution = audit
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "TEST-BOUNDARY-001")
        .expect("testing-boundary execution is reported");
    assert_eq!(execution.state(), RuleExecutionState::Passed);
    assert_eq!(execution.finding_count(), 0);
}
