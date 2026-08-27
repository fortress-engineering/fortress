//! CCG-backed conformance evidence for `TEST-TRACEABILITY-001`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::contract_coherency::{
    CcgObservedTestFact, ContractStandardIndex, ModuleContract, compile_contract_coherency_graph,
};
use fortress_core::rust_test_analyzer::{RustTestClassification, RustTestFact};
use fortress_core::traceability::evaluate_ccg_test_traceability;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Fixture {
    module_contract: FeatureWire,
    tests: Vec<TestWire>,
}

#[derive(Deserialize, Serialize)]
struct FeatureWire {
    features: Vec<FeatureEntry>,
}

#[derive(Deserialize, Serialize)]
struct FeatureEntry {
    id: String,
    requirements: Vec<RequirementEntry>,
}

#[derive(Deserialize, Serialize)]
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

fn empty_contract(id: &str, display_name: &str, root: bool) -> Value {
    let mut value = json!({
        "$schema": "urn:fortress:schema:v2:module-contract",
        "schema_version": 2,
        "id": id,
        "display_name": display_name,
        "provides": [],
        "requires": [],
        "relationships": [],
        "constraints": [],
        "guarantees": [],
        "features": [],
        "behavior": []
    });
    if root {
        value["ecosystem"] = json!({
            "repository_grammar": 1,
            "standard": {
                "id": "STD-FORTRESS-ENGINEERING",
                "edition": "1.0.0-draft.1"
            }
        });
    }
    value
}

fn canonical(value: Value) -> Vec<u8> {
    serde_json::from_value::<ModuleContract>(value)
        .expect("fixture has the contract wire shape")
        .to_canonical_json()
        .expect("fixture contract canonicalizes")
        .into_bytes()
}

fn load(
    relative: &str,
) -> (
    fortress_core::contract_coherency::ContractCoherencyGraph,
    Vec<RustTestFact>,
) {
    let fixture: Fixture = serde_json::from_str(&read(relative)).expect("fixture JSON loads");
    let feature_ids: Vec<String> = fixture
        .module_contract
        .features
        .iter()
        .map(|feature| feature.id.clone())
        .collect();
    let mut feature = empty_contract("AF-SAMPLE-MODULE-0001", "Sample", false);
    feature["features"] = json!(
        fixture
            .module_contract
            .features
            .into_iter()
            .map(|feature| json!({
                "id": feature.id,
                "version": "0.1.0",
                "requirements": feature.requirements
            }))
            .collect::<Vec<_>>()
    );
    let mut testing = empty_contract("AF-SAMPLE-TESTING-0001", "Sample Testing", false);
    testing["relationships"] = json!([{
        "type": "verifies",
        "target": "AF-SAMPLE-MODULE-0001",
        "subjects": feature_ids
    }]);
    let files = BTreeMap::from([
        (
            "contract.json".to_owned(),
            canonical(empty_contract("AF-SAMPLE-ROOT-0001", "Sample Root", true)),
        ),
        ("mods/feature/contract.json".to_owned(), canonical(feature)),
        (
            "mods/feature/mods/testing/contract.json".to_owned(),
            canonical(testing),
        ),
    ]);
    let tests: Vec<RustTestFact> = fixture
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
    let observed: Vec<CcgObservedTestFact> = tests.iter().map(CcgObservedTestFact::from).collect();
    let compilation = compile_contract_coherency_graph(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            [
                "CONTRACT-COHERENCY-001",
                "TEST-BOUNDARY-001",
                "TEST-TRACEABILITY-001",
            ],
        ),
        Some(&observed),
    );
    (
        compilation
            .graph()
            .cloned()
            .unwrap_or_else(|| panic!("fixture graph compiles: {:?}", compilation.violations())),
        tests,
    )
}

/// `T-TEST-TRACEABILITY-001-R01-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R06
#[test]
fn complete_bidirectional_traceability_passes() {
    let (ccg, tests) = load("traceability_valid.json");
    let result = evaluate_ccg_test_traceability(&ccg, &tests, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(result.findings().is_empty());
    assert_eq!(result.active_requirement_count(), 1);
    assert_eq!(result.referenced_test_count(), 1);
}

/// `T-TEST-TRACEABILITY-001-R01-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R06
#[test]
fn invalid_traceability_matches_expected_findings() {
    let (ccg, tests) = load("traceability_invalid.json");
    let result = evaluate_ccg_test_traceability(&ccg, &tests, "1.0.0-draft.1")
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
    let (ccg, tests) = load("traceability_boundary.json");
    let result = evaluate_ccg_test_traceability(&ccg, &tests, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(result.findings().is_empty());
    assert_eq!(result.observed_behavior_test_count(), 1);
}
