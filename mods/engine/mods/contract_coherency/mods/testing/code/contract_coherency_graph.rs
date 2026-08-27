//! Conformance evidence for canonical Module Contract v2 resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::audit::compile_repository_ccg;
use fortress_core::contract_coherency::{
    CcgCompilation, CcgObservedTestFact, CcgTestClassification, ContractStandardIndex,
    ModuleContract, ModuleContractLoadError, compile_contract_coherency_graph,
};
use fortress_core::standard::{StandardBundle, StandardLoadError};
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
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mods/contract_coherency/mods/testing/data")
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

fn rule_document(id: &str, implies: &[&str], conflicts_with: &[&str]) -> String {
    serde_json::to_string(&json!({
        "$schema": "urn:fortress:schema:v1:rule",
        "schema_version": 1,
        "id": id,
        "title": id,
        "status": "draft",
        "statement": "Synthetic rule statement.",
        "rationale": "Synthetic rule rationale.",
        "failure_prevented": "Synthetic failure class.",
        "applicability": "Synthetic ecosystem.",
        "category": "contract",
        "integrity_tier": 1,
        "evaluation": "Synthetic logical evaluation.",
        "required_capabilities": [],
        "logic": {"implies": implies, "conflicts_with": conflicts_with},
        "finding": {"message": "Synthetic finding.", "location": "repository"},
        "remediation": "Correct the synthetic rule logic.",
        "valid_example": "Satisfiable rules.",
        "invalid_example": "Contradictory rules.",
        "exception_policy": "No exceptions.",
        "introduced": "1.0.0-draft.1",
        "history": ["Synthetic CCG conformance record."]
    }))
    .expect("synthetic rule serializes")
}

fn standard_with_rules(
    declarations: &[(&str, &[&str], &[&str])],
) -> Result<StandardBundle, StandardLoadError> {
    let paths = declarations
        .iter()
        .map(|(id, _, _)| format!("rules/{id}.json"))
        .collect::<Vec<_>>();
    let manifest = serde_json::to_string(&json!({
        "$schema": "urn:fortress:schema:v1:standard-manifest",
        "schema_version": 1,
        "id": STANDARD_ID,
        "title": "Synthetic Standard",
        "edition": STANDARD_EDITION,
        "status": "draft",
        "release_digest": null,
        "rules": paths
    }))
    .expect("synthetic standard manifest serializes");
    let sources = declarations
        .iter()
        .map(|(id, implies, conflicts)| rule_document(id, implies, conflicts))
        .collect::<Vec<_>>();
    let documents = paths
        .iter()
        .zip(&sources)
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect::<Vec<_>>();
    StandardBundle::from_json_documents(&manifest, &documents)
}

fn resolve(contracts: &[(&str, Value)], tests: Option<&BTreeSet<String>>) -> CcgCompilation {
    let documents = files(contracts);
    let observed = tests.map(|tests| observed_test_facts(tests, &documents));
    compile_contract_coherency_graph(&documents, &standard(), observed.as_deref())
}

fn observed_test_facts(
    tests: &BTreeSet<String>,
    documents: &BTreeMap<String, Vec<u8>>,
) -> Vec<CcgObservedTestFact> {
    let contracts = documents
        .iter()
        .filter(|(path, _)| path.as_str() == "contract.json" || path.ends_with("/contract.json"))
        .map(|(path, bytes)| {
            (
                path,
                ModuleContract::from_json_str(
                    std::str::from_utf8(bytes).expect("contract fixture is UTF-8"),
                )
                .expect("contract fixture parses"),
            )
        })
        .collect::<Vec<_>>();
    tests
        .iter()
        .map(|id| {
            let declaration = contracts.iter().find_map(|(path, contract)| {
                contract.features().iter().find_map(|feature| {
                    feature.requirements().iter().find_map(|requirement| {
                        requirement
                            .tests()
                            .iter()
                            .any(|test| test == id)
                            .then(|| ((*path).as_str(), requirement.id()))
                    })
                })
            });
            let (path, classification, requirement) = declaration.map_or_else(
                || {
                    (
                        "mods/testing/code/fixture.rs".into(),
                        CcgTestClassification::Infrastructure,
                        None,
                    )
                },
                |(contract_path, requirement)| {
                    let module = contract_path.strip_suffix("/contract.json").unwrap_or("");
                    let testing = if module.is_empty() {
                        "mods/testing".into()
                    } else {
                        format!("{module}/mods/testing")
                    };
                    (
                        format!("{testing}/code/fixture.rs"),
                        CcgTestClassification::Conformance,
                        Some(requirement.to_owned()),
                    )
                },
            );
            CcgObservedTestFact::new(
                id,
                path,
                id.trim_start_matches("T-").to_ascii_lowercase(),
                classification,
                requirement,
            )
        })
        .collect()
}

fn messages(resolution: &CcgCompilation) -> String {
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

fn testing_contract(id: &str, target: &str, feature: &str) -> Value {
    let mut value = contract(id, "Testing", false);
    value["relationships"] = json!([{
        "type": "verifies",
        "target": target,
        "subjects": [feature]
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

/// `T-AF-CONTRACT-COHERENCY-0001-R01-001`
/// Fortress requirement: AF-CONTRACT-COHERENCY-0001-R01
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

/// `T-AF-CONTRACT-COHERENCY-0001-R02-001`
/// Fortress requirement: AF-CONTRACT-COHERENCY-0001-R02
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
            (
                "mods/provider/mods/testing/contract.json",
                testing_contract("AF-PROVIDER-TESTING-0001", "AF-PROVIDER-0001", feature),
            ),
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

    let mut cycle_a = provider_contract();
    cycle_a["requires"] = json!([{
        "provider": "AF-SECOND-0001",
        "capability": "CAP-SECOND",
        "version": "^0.1.0"
    }]);
    let mut cycle_b = contract("AF-SECOND-0001", "Second", false);
    cycle_b["provides"] = json!([{
        "id": "CAP-SECOND",
        "version": "0.1.0",
        "visibility": "project"
    }]);
    cycle_b["requires"] = json!([{
        "provider": "AF-PROVIDER-0001",
        "capability": "CAP-PROVIDER",
        "version": "^0.1.0"
    }]);
    let direct_cycle = resolve(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", cycle_a),
            ("mods/second/contract.json", cycle_b),
        ],
        None,
    );
    assert!(
        direct_cycle
            .violations()
            .iter()
            .any(|violation| violation.code() == "CCG-DEPENDENCY-CYCLE")
    );

    let mut transitive_a = provider_contract();
    transitive_a["requires"] = json!([{
        "provider": "AF-SECOND-0001",
        "capability": "CAP-SECOND",
        "version": "^0.1.0"
    }]);
    let mut transitive_b = contract("AF-SECOND-0001", "Second", false);
    transitive_b["provides"] = json!([{
        "id": "CAP-SECOND",
        "version": "0.1.0",
        "visibility": "project"
    }]);
    transitive_b["requires"] = json!([{
        "provider": "AF-THIRD-0001",
        "capability": "CAP-THIRD",
        "version": "^0.1.0"
    }]);
    let mut transitive_c = contract("AF-THIRD-0001", "Third", false);
    transitive_c["provides"] = json!([{
        "id": "CAP-THIRD",
        "version": "0.1.0",
        "visibility": "project"
    }]);
    transitive_c["requires"] = json!([{
        "provider": "AF-PROVIDER-0001",
        "capability": "CAP-PROVIDER",
        "version": "^0.1.0"
    }]);
    let transitive_cycle = resolve(
        &[
            ("contract.json", root.clone()),
            ("mods/provider/contract.json", transitive_a),
            ("mods/second/contract.json", transitive_b),
            ("mods/third/contract.json", transitive_c),
        ],
        None,
    );
    assert!(
        transitive_cycle
            .violations()
            .iter()
            .any(|violation| violation.code() == "CCG-DEPENDENCY-CYCLE")
    );

    let conflict_standard = standard_with_rules(&[
        ("REPO-A-001", &[], &["REPO-B-001"]),
        ("REPO-B-001", &[], &[]),
    ])
    .expect("conflict declarations are satisfiable until jointly applied");
    let mut explicit_conflict = root.clone();
    explicit_conflict["constraints"] = json!([
        {"rule": "REPO-A-001", "scope": "self"},
        {"rule": "REPO-B-001", "scope": "self"}
    ]);
    let result = compile_contract_coherency_graph(
        &files(&[("contract.json", explicit_conflict)]),
        &ContractStandardIndex::from_bundle(&conflict_standard),
        None,
    );
    assert!(
        result
            .violations()
            .iter()
            .any(|violation| violation.code() == "CCG-CONSTRAINT-CONFLICT")
    );

    let mut inherited_root = root.clone();
    inherited_root["constraints"] = json!([{"rule": "REPO-A-001", "scope": "subtree"}]);
    let mut inherited_child = contract("AF-CHILD-0001", "Child", false);
    inherited_child["constraints"] = json!([{"rule": "REPO-B-001", "scope": "self"}]);
    let result = compile_contract_coherency_graph(
        &files(&[
            ("contract.json", inherited_root),
            ("mods/child/contract.json", inherited_child),
        ]),
        &ContractStandardIndex::from_bundle(&conflict_standard),
        None,
    );
    assert!(result.violations().iter().any(|violation| {
        violation.code() == "CCG-CONSTRAINT-CONFLICT"
            && violation.path() == "mods/child/contract.json"
    }));

    let implication_standard = standard_with_rules(&[
        ("REPO-A-001", &["REPO-B-001"], &[]),
        ("REPO-B-001", &["REPO-C-001"], &[]),
        ("REPO-C-001", &[], &[]),
    ])
    .expect("transitive implication standard is satisfiable");
    let mut implied_root = root.clone();
    implied_root["constraints"] = json!([{"rule": "REPO-A-001", "scope": "self"}]);
    let implied = compile_contract_coherency_graph(
        &files(&[("contract.json", implied_root)]),
        &ContractStandardIndex::from_bundle(&implication_standard),
        None,
    );
    let implied_document: Value = serde_json::from_str(
        &implied
            .graph()
            .expect("implication graph exists")
            .to_canonical_json()
            .expect("implication graph serializes"),
    )
    .expect("implication graph parses");
    assert!(
        implied_document["constraints"]["effective"]
            .as_array()
            .expect("effective constraints")
            .iter()
            .any(|constraint| constraint["rule"] == "REPO-C-001")
    );

    let induced_standard = standard_with_rules(&[
        ("REPO-A-001", &["REPO-B-001"], &[]),
        ("REPO-B-001", &[], &["REPO-C-001"]),
        ("REPO-C-001", &[], &[]),
    ])
    .expect("implication is satisfiable until C is jointly applied");
    let mut induced_root = root;
    induced_root["constraints"] = json!([
        {"rule": "REPO-A-001", "scope": "self"},
        {"rule": "REPO-C-001", "scope": "self"}
    ]);
    let induced = compile_contract_coherency_graph(
        &files(&[("contract.json", induced_root)]),
        &ContractStandardIndex::from_bundle(&induced_standard),
        None,
    );
    assert!(
        induced
            .violations()
            .iter()
            .any(|violation| violation.code() == "CCG-CONSTRAINT-CONFLICT")
    );

    let inherently_unsatisfiable = standard_with_rules(&[
        ("REPO-A-001", &["REPO-B-001"], &["REPO-B-001"]),
        ("REPO-B-001", &[], &[]),
    ]);
    assert!(inherently_unsatisfiable.is_err());

    let unknown_implication = standard_with_rules(&[("REPO-A-001", &["REPO-MISSING-001"], &[])]);
    assert!(unknown_implication.is_err());

    let implication_cycle = standard_with_rules(&[
        ("REPO-A-001", &["REPO-B-001"], &[]),
        ("REPO-B-001", &["REPO-A-001"], &[]),
    ])
    .expect("an implication cycle without a conflict is satisfiable");
    let mut cyclic_root = contract("PF-CONTRACT-TEST", "Contract Test", true);
    cyclic_root["constraints"] = json!([{"rule": "REPO-A-001", "scope": "self"}]);
    let cyclic = compile_contract_coherency_graph(
        &files(&[("contract.json", cyclic_root)]),
        &ContractStandardIndex::from_bundle(&implication_cycle),
        None,
    );
    assert!(
        cyclic.is_success(),
        "satisfiable implication cycle compiles: {}",
        messages(&cyclic)
    );
    let cyclic_document: Value = serde_json::from_str(
        &cyclic
            .graph()
            .expect("cycle graph exists")
            .to_canonical_json()
            .expect("cycle graph serializes"),
    )
    .expect("cycle graph parses");
    assert_eq!(
        cyclic_document["constraints"]["effective"]
            .as_array()
            .expect("effective constraints")
            .len(),
        2
    );
}

/// `T-AF-CONTRACT-COHERENCY-0001-R03-001`
/// Fortress requirement: AF-CONTRACT-COHERENCY-0001-R03
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
        let observed = observed_test_facts(&tests, &documents);
        let standard = ContractStandardIndex::new(
            fixture.standard.id,
            fixture.standard.edition,
            fixture.standard.rules,
        );
        let first = compile_contract_coherency_graph(&documents, &standard, Some(&observed));
        let second = compile_contract_coherency_graph(&documents, &standard, Some(&observed));
        assert_eq!(first, second, "{name} resolution must repeat exactly");
        let resolved = first
            .graph()
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
        assert!(
            first.is_success(),
            "{name} must be semantically coherent: {}",
            messages(&first)
        );
    }
}

/// `T-AF-CONTRACT-COHERENCY-0001-R01-002`
/// Fortress requirement: AF-CONTRACT-COHERENCY-0001-R01
#[test]
fn source_and_derived_facts_retain_precise_provenance() {
    let root = contract("PF-PROVENANCE", "Provenance", true);
    let result = resolve(&[("contract.json", root)], Some(&BTreeSet::new()));
    assert!(
        result.is_success(),
        "minimal graph compiles: {}",
        messages(&result)
    );
    let graph = result.graph().expect("graph exists");
    let document: Value = serde_json::from_str(&graph.to_canonical_json().expect("CCG serializes"))
        .expect("CCG JSON parses");
    assert_eq!(
        document["modules"][0]["provenance"]["path"],
        "contract.json"
    );
    assert_eq!(document["modules"][0]["provenance"]["pointer"], "/");
    assert!(
        document["derivations"]
            .as_array()
            .expect("derivations are an array")
            .iter()
            .all(|derivation| {
                !derivation["input_facts"]
                    .as_array()
                    .expect("input facts")
                    .is_empty()
                    && !derivation["provenance_closure"]
                        .as_array()
                        .expect("provenance closure")
                        .is_empty()
            })
    );
}

/// `T-AF-CONTRACT-COHERENCY-0001-R02-002`
/// Fortress requirement: AF-CONTRACT-COHERENCY-0001-R02
#[test]
fn complex_graph_derives_closure_without_capability_reexport() {
    let fixture = load_ecosystem_fixture("contract_complex.json");
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
    let observed = observed_test_facts(&tests, &documents);
    let result = compile_contract_coherency_graph(
        &documents,
        &ContractStandardIndex::new(
            fixture.standard.id,
            fixture.standard.edition,
            fixture.standard.rules,
        ),
        Some(&observed),
    );
    assert!(
        result.is_success(),
        "complex graph is coherent: {}",
        messages(&result)
    );
    let graph = result.graph().expect("graph exists");
    let document: Value = serde_json::from_str(&graph.to_canonical_json().expect("CCG serializes"))
        .expect("CCG JSON parses");
    assert!(
        !document["relationships"]["inverse_consumers"]
            .as_array()
            .expect("inverse consumers")
            .is_empty()
    );
    assert!(
        document["relationships"]["dependency_reachability"]
            .as_array()
            .expect("dependency reachability")
            .iter()
            .any(|fact| fact["direct"] == false)
    );
    assert!(
        document["relationships"]["reachable_capabilities"]
            .as_array()
            .expect("reachable capabilities")
            .iter()
            .all(|fact| fact["reexported"] == false)
    );
    assert!(
        document["guarantees"]
            .as_array()
            .expect("guarantees")
            .iter()
            .all(|guarantee| {
                guarantee["complete_declared_verification_obligations"] == true
                    && !guarantee["support_topology"]
                        .as_array()
                        .expect("support topology")
                        .is_empty()
            })
    );
    assert!(
        document["verification"]["requirement_support"]
            .as_array()
            .expect("requirement support")
            .iter()
            .all(|support| support["complete_declared_support"] == true)
    );
    assert!(
        document["constraints"]["effective"]
            .as_array()
            .expect("effective constraints")
            .iter()
            .any(|constraint| {
                constraint["module"] == "TF-APPLICATION-INTERFACE-0001"
                    && constraint["rule"] == RULE_ID
                    && constraint["origins"][0]["kind"] == "inherited"
                    && constraint["origins"][0]["declared_by"] == "PF-COMPLEX"
            })
    );
    assert_eq!(
        document["coherency"]["unsupported_semantics"],
        json!([
            "arbitrary_natural_language_requirement_contradiction",
            "general_behavioral_satisfiability",
            "source_code_dependency_realization",
            "lowest_semantic_ownership_from_runtime_consumers",
            "security_information_flow_proof",
            "arbitrary_theorem_proving"
        ])
    );
    assert_eq!(document["coherency"]["status"], "coherent");
}

/// `T-AF-CONTRACT-COHERENCY-0001-R03-002`
/// Fortress requirement: AF-CONTRACT-COHERENCY-0001-R03
#[test]
fn canonical_graph_bytes_and_digest_repeat_exactly() {
    let root = contract("PF-DETERMINISTIC", "Deterministic", true);
    let first = resolve(&[("contract.json", root.clone())], Some(&BTreeSet::new()));
    let second = resolve(&[("contract.json", root)], Some(&BTreeSet::new()));
    let first_graph = first.graph().expect("first graph exists");
    let second_graph = second.graph().expect("second graph exists");
    let first_bytes = first_graph
        .to_canonical_json()
        .expect("first CCG serializes");
    let second_bytes = second_graph
        .to_canonical_json()
        .expect("second CCG serializes");
    assert_eq!(first_bytes, second_bytes);
    assert_eq!(
        first_graph.digest().expect("first digest"),
        second_graph.digest().expect("second digest")
    );
    assert!(first_bytes.ends_with('\n'));
    assert!(!first_bytes.contains('\r'));

    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let self_graph = compile_repository_ccg(&repository).expect("Fortress self-CCG compiles");
    let generated = self_graph
        .to_canonical_json()
        .expect("Fortress self-CCG serializes");
    let temporary =
        std::env::temp_dir().join(format!("fortress-self-ccg-{}.json", std::process::id()));
    fs::write(&temporary, generated.as_bytes()).expect("temporary self-CCG writes");
    let committed = fs::read(repository.join("info/contract_coherency_graph.json"))
        .expect("committed self-CCG reads");
    let fresh = fs::read(&temporary).expect("temporary self-CCG reads");
    fs::remove_file(&temporary).expect("temporary self-CCG removes");
    assert_eq!(fresh, committed, "committed self-CCG must be fresh");
}
