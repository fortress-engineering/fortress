//! Implementation exercise of specification-authored `TEST-TRACEABILITY-001` fixtures.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::rust_test_analyzer::{RustTestClassification, RustTestFact};
use fortress_core::traceability::{RequirementEvidence, evaluate_test_traceability};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    module_contract: FeatureWire,
    tests: Vec<TestWire>,
}

#[derive(Deserialize)]
struct FeatureWire {
    features: Vec<FeatureEntry>,
}

#[derive(Deserialize)]
struct FeatureEntry {
    id: String,
    requirements: Vec<RequirementEntry>,
}

#[derive(Deserialize)]
struct RequirementEntry {
    id: String,
    statement: String,
    tests: Vec<String>,
}

#[derive(Deserialize)]
struct TestWire {
    id: String,
    path: String,
    symbol: String,
    classification: RustTestClassification,
    declared_requirement: Option<String>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mods/snapshot_governance/mods/testing/data")
}

fn read(relative: &str) -> String {
    let path = root().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn load(relative: &str) -> (Vec<RequirementEvidence>, Vec<RustTestFact>) {
    let fixture: Fixture = serde_json::from_str(&read(relative)).expect("fixture JSON loads");
    let requirements = fixture
        .module_contract
        .features
        .into_iter()
        .flat_map(|feature| {
            feature.requirements.into_iter().map(move |requirement| {
                RequirementEvidence::new(
                    "mods/feature/contract.json",
                    feature.id.clone(),
                    requirement.id,
                    requirement.statement,
                    requirement.tests,
                )
            })
        })
        .collect();
    let tests = fixture
        .tests
        .into_iter()
        .map(|test| {
            RustTestFact::new(
                test.id,
                test.path,
                test.symbol,
                test.classification,
                test.declared_requirement,
            )
            .expect("test fact validates")
        })
        .collect();
    (requirements, tests)
}

/// `T-TEST-TRACEABILITY-001-R01-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R06
#[test]
fn complete_bidirectional_traceability_passes() {
    let (requirements, tests) = load("traceability_valid.json");
    let result = evaluate_test_traceability(&requirements, &tests, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(result.findings().is_empty());
    assert_eq!(result.active_requirement_count(), 1);
    assert_eq!(result.referenced_test_count(), 1);
}

/// `T-TEST-TRACEABILITY-001-R01-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R06
#[test]
fn invalid_traceability_matches_expected_findings() {
    let (requirements, tests) = load("traceability_invalid.json");
    let result = evaluate_test_traceability(&requirements, &tests, "1.0.0-draft.1")
        .expect("evaluation completes");
    let mut actual: Vec<String> = result
        .findings()
        .iter()
        .map(|finding| finding.message().to_owned())
        .collect();
    actual.sort();
    let expected: Vec<String> =
        serde_json::from_str(&read("traceability_expected.json")).expect("expected JSON loads");
    assert_eq!(actual, expected);
}

/// `T-TEST-TRACEABILITY-001-R01-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R06
#[test]
fn explicit_infrastructure_test_is_a_legitimate_unmapped_boundary() {
    let (requirements, tests) = load("traceability_boundary.json");
    let result = evaluate_test_traceability(&requirements, &tests, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(result.findings().is_empty());
    assert_eq!(result.observed_behavior_test_count(), 1);
}
