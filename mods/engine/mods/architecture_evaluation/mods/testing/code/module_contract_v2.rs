//! Conformance evidence for canonical Module Contract v2 resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::module_contract::{
    ContractResolution, ContractStandardIndex, ModuleContract, ModuleContractLoadError,
    resolve_contracts,
};
use serde::Deserialize;
use serde_json::{Value, json};

const STANDARD_ID: &str = "STD-FORTRESS-ENGINEERING";
const STANDARD_EDITION: &str = "1.0.0-draft.1";
const RULE_ID: &str = "STD-ID-001";

#[derive(Deserialize)]
struct EcosystemFixture {
    standard: FixtureStandard,
    tests: Vec<String>,
    expected: FixtureExpected,
    contracts: Vec<FixtureContract>,
}

#[derive(Deserialize)]
struct FixtureStandard {
    id: String,
    edition: String,
    rules: Vec<String>,
}

#[derive(Deserialize)]
struct FixtureExpected {
    modules: usize,
    capabilities: usize,
    features: usize,
    requirements: usize,
    guarantees: usize,
    checkpoints: usize,
    direct_requirements: usize,
    relationships: usize,
}

#[derive(Deserialize)]
struct FixtureContract {
    path: String,
    contract: Value,
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mods/architecture_evaluation/mods/testing/data")
}

fn ecosystem() -> Value {
    json!({
        "repository_grammar": 1,
        "standard": {
            "id": STANDARD_ID,
            "edition": STANDARD_EDITION
        }
    })
}

fn contract(id: &str, display_name: &str, root: bool) -> Value {
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
        value["ecosystem"] = ecosystem();
    }
    value
}

fn canonical(value: &Value) -> String {
    serde_json::from_value::<ModuleContract>(value.clone())
        .expect("fixture has the contract wire shape")
        .to_canonical_json()
        .expect("contract serializes")
}

fn files(contracts: &[(&str, Value)]) -> BTreeMap<String, Vec<u8>> {
    contracts
        .iter()
        .map(|(path, value)| ((*path).to_owned(), canonical(value).into_bytes()))
        .collect()
}

fn standard() -> ContractStandardIndex {
    ContractStandardIndex::new(STANDARD_ID, STANDARD_EDITION, [RULE_ID])
}

fn resolve(contracts: &[(&str, Value)], tests: Option<&BTreeSet<String>>) -> ContractResolution {
    resolve_contracts(&files(contracts), &standard(), tests)
}

fn messages(resolution: &ContractResolution) -> String {
    resolution
        .violations()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_violation(contracts: &[(&str, Value)], needle: &str) {
    let result = resolve(contracts, Some(&BTreeSet::new()));
    assert!(!result.is_success());
    let actual = messages(&result);
    assert!(actual.contains(needle), "expected `{needle}` in:\n{actual}");
}

fn provider_contract() -> Value {
    let mut provider = contract("AF-PROVIDER-0001", "Provider", false);
    provider["provides"] = json!([{
        "id": "CAP-PROVIDER",
        "version": "0.1.0",
        "visibility": "project"
    }]);
    provider
}

fn consumer_contract() -> Value {
    let mut consumer = contract("TF-CONSUMER-0001", "Consumer", false);
    consumer["requires"] = json!([{
        "provider": "AF-PROVIDER-0001",
        "capability": "CAP-PROVIDER",
        "version": "^0.1.0"
    }]);
    consumer
}

fn owned_feature_contract(id: &str, feature: &str, requirement: &str, test: &str) -> Value {
    let mut value = contract(id, "Feature Owner", false);
    value["features"] = json!([{
        "id": feature,
        "version": "0.1.0",
        "requirements": [{
            "id": requirement,
            "statement": "The modeled behavior remains deterministic.",
            "tests": [test]
        }]
    }]);
    value
}

fn checkpoint(
    id: &str,
    feature: &str,
    kind: &str,
    outcome: Option<&str>,
    transitions: &Value,
) -> Value {
    let mut value = json!({
        "id": id,
        "feature": feature,
        "kind": kind,
        "transitions": transitions.clone()
    });
    if let Some(outcome) = outcome {
        value["outcome"] = Value::String(outcome.to_owned());
    }
    value
}

fn load_ecosystem_fixture(name: &str) -> EcosystemFixture {
    let source = fs::read_to_string(fixture_root().join(name)).expect("ecosystem fixture reads");
    serde_json::from_str(&source).expect("ecosystem fixture parses")
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R01-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R01
#[test]
fn local_contract_shape_and_canonical_bytes_are_strict() {
    let minimal = canonical(&contract("AF-MINIMAL-0001", "Minimal", false));
    assert!(ModuleContract::from_json_str(&minimal).is_ok());
    let root = canonical(&contract("PF-CONTRACT-TEST", "Contract Test", true));
    assert!(ModuleContract::from_json_str(&root).is_ok());

    let v1 = "{\"$schema\":\"urn:fortress:schema:v1:module-contract\",\"schema_version\":1}";
    assert!(matches!(
        ModuleContract::from_json_str(v1),
        Err(ModuleContractLoadError::UnsupportedSchemaVersion(Some(1)))
    ));
    assert!(matches!(
        ModuleContract::from_json_str(root.trim_end()),
        Err(ModuleContractLoadError::NoncanonicalSerialization)
    ));

    let malformed_version = canonical(&{
        let mut value = provider_contract();
        value["provides"][0]["version"] = json!("not-semver");
        value
    });
    assert!(ModuleContract::from_json_str(&malformed_version).is_err());

    let invalid_visibility = canonical(&provider_contract()).replace("\"project\"", "\"private\"");
    assert!(ModuleContract::from_json_str(&invalid_visibility).is_err());

    let mut malformed_requirement = consumer_contract();
    malformed_requirement["requires"][0]["version"] = json!("not-a-range");
    assert!(ModuleContract::from_json_str(&canonical(&malformed_requirement)).is_err());

    let mut unknown_relationship = contract("TF-VERIFIER-0001", "Verifier", false);
    unknown_relationship["relationships"] = json!([{
        "type": "verifies",
        "target": "AF-PROVIDER-0001",
        "subjects": []
    }]);
    let unknown_relationship =
        canonical(&unknown_relationship).replace("\"type\": \"verifies\"", "\"type\": \"governs\"");
    assert!(ModuleContract::from_json_str(&unknown_relationship).is_err());

    let mut self_requirement = provider_contract();
    self_requirement["requires"] = json!([{
        "provider": "AF-PROVIDER-0001",
        "capability": "CAP-PROVIDER",
        "version": "^0.1.0"
    }]);
    assert!(ModuleContract::from_json_str(&canonical(&self_requirement)).is_err());
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R01-002`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R01
#[test]
#[allow(clippy::too_many_lines)]
fn ecosystem_resolution_rejects_incoherent_intent() {
    let root = contract("PF-CONTRACT-TEST", "Contract Test", true);
    let provider = provider_contract();
    let consumer = consumer_contract();

    assert_violation(
        &[(
            "contract.json",
            contract("PF-CONTRACT-TEST", "Contract Test", false),
        )],
        "root contract must declare ecosystem interpretation",
    );

    let mut descendant_ecosystem = provider.clone();
    descendant_ecosystem["ecosystem"] = ecosystem();
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", descendant_ecosystem),
        ],
        "descendant contract must not author ecosystem interpretation",
    );

    let mut wrong_standard = root.clone();
    wrong_standard["ecosystem"]["standard"]["edition"] = json!("9.0.0");
    assert_violation(
        &[("contract.json", wrong_standard)],
        "does not match loaded registry",
    );

    let duplicate_id = contract("PF-CONTRACT-TEST", "Duplicate", false);
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/duplicate/contract.json", duplicate_id),
        ],
        "duplicates",
    );

    let mut second_provider = contract("AF-SECOND-0001", "Second", false);
    second_provider["provides"] = provider["provides"].clone();
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", provider.clone()),
            ("mods/second/contract.json", second_provider),
        ],
        "capability ID `CAP-PROVIDER` duplicates",
    );

    let mut missing_provider = consumer.clone();
    missing_provider["requires"][0]["provider"] = json!("AF-MISSING-0001");
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/consumer/contract.json", missing_provider),
        ],
        "provider Module `AF-MISSING-0001` does not exist",
    );

    let mut missing_capability = consumer.clone();
    missing_capability["requires"][0]["capability"] = json!("CAP-MISSING");
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", provider.clone()),
            ("mods/consumer/contract.json", missing_capability),
        ],
        "capability `CAP-MISSING` does not exist",
    );

    let mut incompatible = consumer.clone();
    incompatible["requires"][0]["version"] = json!("^1.0.0");
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", provider.clone()),
            ("mods/consumer/contract.json", incompatible),
        ],
        "does not satisfy `^1.0.0`",
    );

    let mut missing_target = contract("TF-VERIFIER-0001", "Verifier", false);
    missing_target["relationships"] = json!([{
        "type": "verifies",
        "target": "AF-MISSING-0001",
        "subjects": []
    }]);
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/verifier/contract.json", missing_target),
        ],
        "target Module `AF-MISSING-0001` does not exist",
    );

    let mut self_relationship = contract("TF-VERIFIER-0001", "Verifier", false);
    self_relationship["relationships"] = json!([{
        "type": "verifies",
        "target": "TF-VERIFIER-0001",
        "subjects": []
    }]);
    assert!(ModuleContract::from_json_str(&canonical(&self_relationship)).is_err());

    let mut duplicate_relationship = contract("TF-VERIFIER-0001", "Verifier", false);
    duplicate_relationship["relationships"] = json!([
        {"type": "verifies", "target": "AF-PROVIDER-0001", "subjects": []},
        {"type": "verifies", "target": "AF-PROVIDER-0001", "subjects": []}
    ]);
    assert!(ModuleContract::from_json_str(&canonical(&duplicate_relationship)).is_err());

    let mut unknown_subject = contract("TF-VERIFIER-0001", "Verifier", false);
    unknown_subject["relationships"] = json!([{
        "type": "verifies",
        "target": "AF-PROVIDER-0001",
        "subjects": ["GUA-MISSING"]
    }]);
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", provider.clone()),
            ("mods/verifier/contract.json", unknown_subject),
        ],
        "verification subject `GUA-MISSING`",
    );

    let mut unknown_constraint = provider.clone();
    unknown_constraint["constraints"] = json!([{"rule": "REPO-MISSING-001", "scope": "self"}]);
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", unknown_constraint),
        ],
        "does not exist in selected standard",
    );

    let mut constrained_root = root.clone();
    constrained_root["constraints"] = json!([{"rule": RULE_ID, "scope": "subtree"}]);
    let mut redundant_child = provider.clone();
    redundant_child["constraints"] = json!([{"rule": RULE_ID, "scope": "subtree"}]);
    assert_violation(
        &[
            ("contract.json", constrained_root),
            ("mods/provider/contract.json", redundant_child),
        ],
        "redundantly redeclares an inherited obligation",
    );

    let requirement = "AF-PROVIDER-FEATURE-0001-R01";
    let test = "T-CONTRACT-PROVIDER-R01-001";
    let mut guarantees = owned_feature_contract(
        "AF-PROVIDER-0001",
        "AF-PROVIDER-FEATURE-0001",
        requirement,
        test,
    );
    guarantees["guarantees"] = json!([{
        "id": "GUA-PROVIDER-INTEGRITY",
        "subject": {"kind": "feature", "id": "AF-MISSING-FEATURE-0001"},
        "requirements": [requirement]
    }]);
    assert!(ModuleContract::from_json_str(&canonical(&guarantees)).is_err());
    guarantees["guarantees"][0]["subject"]["id"] = json!("AF-PROVIDER-FEATURE-0001");
    guarantees["guarantees"][0]["requirements"] = json!(["AF-MISSING-FEATURE-0001-R01"]);
    assert!(ModuleContract::from_json_str(&canonical(&guarantees)).is_err());

    let feature_a = owned_feature_contract(
        "AF-PROVIDER-0001",
        "AF-SHARED-FEATURE-0001",
        "AF-SHARED-FEATURE-0001-R01",
        "T-SHARED-FEATURE-R01-001",
    );
    let feature_b = owned_feature_contract(
        "AF-SECOND-0001",
        "AF-SHARED-FEATURE-0001",
        "AF-SHARED-FEATURE-0001-R01",
        "T-SHARED-FEATURE-R01-001",
    );
    let evidence = BTreeSet::from(["T-SHARED-FEATURE-R01-001".to_owned()]);
    let duplicates = resolve(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", feature_a),
            ("mods/second/contract.json", feature_b),
        ],
        Some(&evidence),
    );
    assert!(messages(&duplicates).contains("Feature ID `AF-SHARED-FEATURE-0001` duplicates"));
    assert!(
        messages(&duplicates).contains("requirement ID `AF-SHARED-FEATURE-0001-R01` duplicates")
    );

    let unknown_test = owned_feature_contract(
        "AF-PROVIDER-0001",
        "AF-PROVIDER-FEATURE-0001",
        requirement,
        test,
    );
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", unknown_test),
        ],
        "does not exist in the supported evidence inventory",
    );

    let feature = "AF-BEHAVIOR-FEATURE-0001";
    let mut behavior = owned_feature_contract(
        "AF-PROVIDER-0001",
        feature,
        "AF-BEHAVIOR-FEATURE-0001-R01",
        "T-BEHAVIOR-FEATURE-R01-001",
    );
    behavior["behavior"] = json!([
        checkpoint(
            "CHK-FLOW-START",
            feature,
            "trigger",
            None,
            &json!([{"target": "CHK-FLOW-TERMINAL"}])
        ),
        checkpoint(
            "CHK-FLOW-TERMINAL",
            feature,
            "terminal",
            Some("done"),
            &json!([])
        )
    ]);
    let behavior_tests = BTreeSet::from(["T-BEHAVIOR-FEATURE-R01-001".to_owned()]);
    let valid_behavior = resolve(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", behavior.clone()),
        ],
        Some(&behavior_tests),
    );
    assert!(
        valid_behavior.is_success(),
        "valid behavior must resolve: {}",
        messages(&valid_behavior)
    );

    let mut unknown_feature = behavior.clone();
    unknown_feature["behavior"][0]["feature"] = json!("AF-MISSING-FEATURE-0001");
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", unknown_feature),
        ],
        "Feature `AF-MISSING-FEATURE-0001` does not exist",
    );

    let mut multiple_triggers = behavior.clone();
    multiple_triggers["behavior"]
        .as_array_mut()
        .expect("array")
        .insert(
            1,
            checkpoint(
                "CHK-FLOW-START-TWO",
                feature,
                "trigger",
                None,
                &json!([{"target": "CHK-FLOW-TERMINAL"}]),
            ),
        );
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", multiple_triggers),
        ],
        "must have exactly one trigger, found 2",
    );

    let mut missing_terminal = behavior.clone();
    missing_terminal["behavior"]
        .as_array_mut()
        .expect("array")
        .pop();
    missing_terminal["behavior"][0]["transitions"] = json!([{"target": "CHK-FLOW-START"}]);
    assert_violation(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", missing_terminal),
        ],
        "has no terminal checkpoint",
    );

    let mut invalid_decision = behavior.clone();
    invalid_decision["behavior"][0] = checkpoint(
        "CHK-FLOW-START",
        feature,
        "decision",
        None,
        &json!([
            {"outcome": "same", "target": "CHK-FLOW-TERMINAL"},
            {"outcome": "same", "target": "CHK-FLOW-TERMINAL"}
        ]),
    );
    assert!(ModuleContract::from_json_str(&canonical(&invalid_decision)).is_err());

    let mut second_feature = behavior.clone();
    second_feature["features"]
        .as_array_mut()
        .expect("array")
        .push(json!({
            "id": "AF-SECOND-FEATURE-0001",
            "version": "0.1.0",
            "requirements": [{
                "id": "AF-SECOND-FEATURE-0001-R01",
                "statement": "Second behavior exists.",
                "tests": ["T-SECOND-FEATURE-R01-001"]
            }]
        }));
    second_feature["behavior"][1]["feature"] = json!("AF-SECOND-FEATURE-0001");
    let cross_tests = BTreeSet::from([
        "T-BEHAVIOR-FEATURE-R01-001".to_owned(),
        "T-SECOND-FEATURE-R01-001".to_owned(),
    ]);
    let cross = resolve(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", second_feature),
        ],
        Some(&cross_tests),
    );
    assert!(messages(&cross).contains("crosses from Feature"));

    let mut unreachable = behavior;
    unreachable["behavior"]
        .as_array_mut()
        .expect("array")
        .insert(
            0,
            checkpoint(
                "CHK-FLOW-ORPHAN",
                feature,
                "terminal",
                Some("orphaned"),
                &json!([]),
            ),
        );
    assert_violation(
        &[
            ("contract.json", root),
            ("mods/provider/contract.json", unreachable),
        ],
        "is unreachable",
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R01-003`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R01
#[test]
fn simple_and_complex_ecosystems_resolve_deterministically() {
    for name in ["contract_simple.json", "contract_complex.json"] {
        let fixture = load_ecosystem_fixture(name);
        let documents = fixture
            .contracts
            .iter()
            .map(|document| {
                (
                    document.path.clone(),
                    canonical(&document.contract).into_bytes(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let tests = fixture.tests.into_iter().collect::<BTreeSet<_>>();
        let standard = ContractStandardIndex::new(
            fixture.standard.id,
            fixture.standard.edition,
            fixture.standard.rules,
        );
        let first = resolve_contracts(&documents, &standard, Some(&tests));
        let second = resolve_contracts(&documents, &standard, Some(&tests));
        assert_eq!(first, second, "{name} resolution must repeat exactly");
        let resolved = first
            .resolved()
            .unwrap_or_else(|| panic!("{name} must resolve: {:#?}", first.violations()));
        assert_eq!(resolved.modules().len(), fixture.expected.modules);
        assert_eq!(resolved.capabilities().len(), fixture.expected.capabilities);
        assert_eq!(resolved.features().len(), fixture.expected.features);
        assert_eq!(resolved.requirements().len(), fixture.expected.requirements);
        assert_eq!(resolved.guarantees().len(), fixture.expected.guarantees);
        assert_eq!(resolved.checkpoints().len(), fixture.expected.checkpoints);
        assert_eq!(
            resolved.direct_requirements().len(),
            fixture.expected.direct_requirements
        );
        assert_eq!(
            resolved.relationships().len(),
            fixture.expected.relationships
        );
        assert!(
            resolved
                .modules()
                .values()
                .all(|module| module.digest().starts_with("sha256:"))
        );
    }
}
