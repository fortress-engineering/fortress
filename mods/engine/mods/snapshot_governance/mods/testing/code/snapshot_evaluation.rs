//! Repository-level evidence for truthful Snapshot Governance rule execution.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::architecture::ArchitectureManifest;
use fortress_core::evaluation::{RuleExecutionState, SnapshotRuleEngine};
use fortress_core::feature::FeatureContract;
use fortress_core::observation::ObservationPolicy;
use fortress_core::project::ProjectManifest;
use fortress_core::rust_test_analyzer::analyze_snapshot_rust_tests;
use fortress_core::snapshot::{RepositorySnapshot, SnapshotDocuments, build_repository_snapshot};
use fortress_core::standard::StandardBundle;
use serde_json::Value;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn read_bytes(root: &Path, relative: &str) -> Vec<u8> {
    let path = root.join(relative);
    fs::read(&path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn self_snapshot_and_standard() -> (RepositorySnapshot, StandardBundle) {
    let root = repository_root();
    let project_bytes = read_bytes(&root, "data/project.json");
    let project_source = String::from_utf8(project_bytes.clone()).expect("project JSON is UTF-8");
    let project = ProjectManifest::from_json_str(&project_source).expect("project must validate");
    let architecture_bytes = read_bytes(&root, project.model().architecture());
    let feature_sources: Vec<(String, Vec<u8>)> = project
        .model()
        .features()
        .iter()
        .map(|path| (path.clone(), read_bytes(&root, path)))
        .collect();

    let standard_manifest_path = project.standard().manifest();
    let standard_manifest_bytes = read_bytes(&root, standard_manifest_path);
    let standard_manifest_source =
        String::from_utf8(standard_manifest_bytes.clone()).expect("standard manifest is UTF-8");
    let standard_manifest: Value =
        serde_json::from_str(&standard_manifest_source).expect("standard manifest is JSON");
    let rule_sources: Vec<(String, Vec<u8>)> = standard_manifest["rules"]
        .as_array()
        .expect("standard rules must be an array")
        .iter()
        .map(|value| {
            let relative = value.as_str().expect("rule path is a string");
            let path = relative.to_owned();
            let bytes = read_bytes(&root, &path);
            (path, bytes)
        })
        .collect();
    let rule_text: Vec<(String, String)> = rule_sources
        .iter()
        .map(|(path, bytes)| {
            (
                path.clone(),
                String::from_utf8(bytes.clone()).expect("rule JSON is UTF-8"),
            )
        })
        .collect();
    let rule_documents: Vec<(&str, &str)> = rule_text
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect();
    let standard = StandardBundle::from_json_documents(&standard_manifest_source, &rule_documents)
        .expect("self standard bundle must validate");

    let documents = SnapshotDocuments::new(
        standard_manifest_path,
        &standard_manifest_bytes,
        rule_sources
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
        &project_bytes,
        &architecture_bytes,
        feature_sources
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
    );
    let policy = ObservationPolicy::new(project.model().observation_exclusions().iter().cloned())
        .expect("self policy must validate");
    let snapshot = build_repository_snapshot(&root, &policy, &project, &documents)
        .expect("self snapshot must stabilize");
    (snapshot, standard)
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R04-002`
#[test]
fn registered_architecture_evaluator_distinguishes_pass_and_failure() {
    let (snapshot, standard) = self_snapshot_and_standard();
    let valid_source = fs::read_to_string(repository_root().join("data/architecture.json"))
        .expect("self architecture is readable");
    let valid =
        ArchitectureManifest::from_json_str(&valid_source).expect("self architecture loads");
    let pass = SnapshotRuleEngine::builtin()
        .evaluate(&standard, &snapshot, &valid)
        .expect("valid evaluation completes");
    assert_eq!(pass.passed_count(), 3);
    assert_eq!(pass.failed_count(), 0);
    assert!(pass.findings().is_empty());

    let invalid_source = fs::read_to_string(repository_root().join(
        "mods/engine/mods/architecture_evaluation/mods/testing/data/dependency_invalid.json",
    ))
    .expect("negative fixture is readable");
    let invalid = ArchitectureManifest::from_json_str(&invalid_source)
        .expect("negative fixture is structurally valid");
    let failure = SnapshotRuleEngine::builtin()
        .evaluate(&standard, &snapshot, &invalid)
        .expect("invalid evaluation completes");
    let dependency_execution = failure
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "ARCH-DEPENDENCY-001")
        .expect("dependency execution is reported");
    assert_eq!(dependency_execution.state(), RuleExecutionState::Failed);
    assert!(
        failure
            .findings()
            .iter()
            .any(|finding| finding.rule_id() == "ARCH-DEPENDENCY-001")
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R04-003`
#[test]
fn missing_snapshot_evaluator_is_unsupported_not_passed() {
    let (snapshot, standard) = self_snapshot_and_standard();
    let source = fs::read_to_string(repository_root().join("data/architecture.json"))
        .expect("self architecture is readable");
    let architecture = ArchitectureManifest::from_json_str(&source).expect("architecture loads");
    let result = SnapshotRuleEngine::builtin()
        .evaluate(&standard, &snapshot, &architecture)
        .expect("evaluation completes");
    let unsupported = result
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "STD-ID-001")
        .expect("STD-ID-001 execution is reported");
    assert_eq!(unsupported.state(), RuleExecutionState::Unsupported);
    assert_eq!(unsupported.finding_count(), 0);
    assert_eq!(result.unsupported_count(), 3);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R06-003`
#[test]
fn fortress_active_requirements_have_complete_snapshot_bound_rust_evidence() {
    let (snapshot, standard) = self_snapshot_and_standard();
    let root = repository_root();
    let architecture_source = fs::read_to_string(root.join("data/architecture.json"))
        .expect("self architecture is readable");
    let architecture =
        ArchitectureManifest::from_json_str(&architecture_source).expect("architecture loads");
    let feature_source = fs::read_to_string(root.join("data/features.json"))
        .expect("self feature contract is readable");
    let feature = FeatureContract::from_json_str("data/features.json", &feature_source)
        .expect("feature contract loads");
    let rust_tests = analyze_snapshot_rust_tests(&root, &snapshot)
        .expect("snapshot-bound Rust test analysis completes");
    let result = SnapshotRuleEngine::builtin()
        .evaluate_with_traceability(&standard, &snapshot, &architecture, &[feature], &rust_tests)
        .expect("evaluation completes");
    let execution = result
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "TEST-TRACEABILITY-001")
        .expect("traceability execution is reported");
    assert_eq!(execution.state(), RuleExecutionState::Passed);
    assert_eq!(execution.finding_count(), 0);
}
