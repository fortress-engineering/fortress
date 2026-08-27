//! Implementation exercise of specification-authored `TEST-TRACEABILITY-001` fixtures.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::feature::FeatureContract;
use fortress_core::rust_test_analyzer::{RustTestClassification, RustTestFact};
use fortress_core::traceability::evaluate_test_traceability;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    feature_contract: serde_json::Value,
    tests: Vec<TestWire>,
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

fn load(relative: &str) -> (FeatureContract, Vec<RustTestFact>) {
    let fixture: Fixture = serde_json::from_str(&read(relative)).expect("fixture JSON loads");
    let contract = FeatureContract::from_json_str(
        "fixtures/feature.json",
        &fixture.feature_contract.to_string(),
    )
    .expect("feature contract loads");
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
    (contract, tests)
}

/// `T-TEST-TRACEABILITY-001-R01-001`
#[test]
fn complete_bidirectional_traceability_passes() {
    let (contract, tests) = load("traceability_valid.json");
    let result = evaluate_test_traceability(&[contract], &tests, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(result.findings().is_empty());
    assert_eq!(result.active_requirement_count(), 1);
    assert_eq!(result.referenced_test_count(), 1);
}

/// `T-TEST-TRACEABILITY-001-R01-002`
#[test]
fn invalid_traceability_matches_expected_findings() {
    let (contract, tests) = load("traceability_invalid.json");
    let result = evaluate_test_traceability(&[contract], &tests, "1.0.0-draft.1")
        .expect("evaluation completes");
    let actual = serde_json::to_value(result.findings()).expect("findings serialize");
    let expected: serde_json::Value =
        serde_json::from_str(&read("traceability_expected.json")).expect("expected JSON loads");
    assert_eq!(actual, expected);
}

/// `T-TEST-TRACEABILITY-001-R01-003`
#[test]
fn explicit_infrastructure_test_is_a_legitimate_unmapped_boundary() {
    let (contract, tests) = load("traceability_boundary.json");
    let result = evaluate_test_traceability(&[contract], &tests, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(result.findings().is_empty());
    assert_eq!(result.observed_behavior_test_count(), 1);
}
