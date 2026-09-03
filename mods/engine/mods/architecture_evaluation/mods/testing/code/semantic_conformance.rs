//! Module semantic-policy conformance fixtures.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Instant;

use fortress_core::architecture_realization::reconcile_implementation;
use fortress_core::contract_coherency::{
    ContractStandardIndex, ModuleContract, compile_contract_coherency_graph,
};
use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile, observe_rust_implementation,
};
use fortress_core::program_semantics::{ProgramSemanticInput, compile_program_semantic_model};
use fortress_core::semantic_analysis::{analyze_program_domains, load_function_contracts};
use fortress_core::semantic_conformance::{
    SemanticConformanceEvaluation, SemanticConformanceState, evaluate_semantic_conformance,
};
use fortress_core::state_effect_analysis::{analyze_state_effects, load_state_contracts};

const EDITION: &str = "1.0.0-draft.1";

fn canonical_contract(document: serde_json::Value) -> String {
    let contract: ModuleContract = serde_json::from_value(document).expect("contract shape parses");
    contract.to_canonical_json().expect("contract serializes")
}

fn root_contract() -> String {
    canonical_contract(serde_json::json!({
        "$schema": "urn:fortress:schema:v2:module-contract",
        "schema_version": 2,
        "id": "PF-SEMANTIC-FIXTURE",
        "display_name": "Semantic Fixture",
        "ecosystem": {
            "repository_grammar": 1,
            "standard": {
                "id": "STD-FORTRESS-ENGINEERING",
                "edition": "1.0.0-draft.1"
            }
        },
        "provides": [],
        "requires": [],
        "relationships": [],
        "constraints": [],
        "guarantees": [],
        "features": [],
        "behavior": []
    }))
}

fn module_contract(
    id: &str,
    capability_allow: &[&str],
    capability_deny: &[&str],
    effect_allow: &[&str],
    effect_deny: &[&str],
) -> String {
    canonical_contract(serde_json::json!({
        "$schema": "urn:fortress:schema:v3:module-contract",
        "schema_version": 3,
        "id": id,
        "display_name": id,
        "provides": [],
        "requires": [],
        "relationships": [],
        "constraints": [],
        "guarantees": [],
        "features": [],
        "behavior": [],
        "semantic_policy": {
            "default": "UNDECLARED",
            "capabilities": {
                "allow": capability_allow,
                "deny": capability_deny
            },
            "effects": {
                "allow": effect_allow,
                "deny": effect_deny
            }
        }
    }))
}

fn evaluate(source: &str, contract: String) -> SemanticConformanceEvaluation {
    let files = BTreeMap::from([
        ("contract.json".to_owned(), root_contract().into_bytes()),
        (
            "mods/sample/contract.json".to_owned(),
            contract.into_bytes(),
        ),
        (
            "mods/sample/data/Cargo.toml".to_owned(),
            b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../code/lib.rs'\n"
                .to_vec(),
        ),
        (
            "mods/sample/code/lib.rs".to_owned(),
            source.as_bytes().to_vec(),
        ),
    ]);
    evaluate_files(&files)
}

fn evaluate_files(files: &BTreeMap<String, Vec<u8>>) -> SemanticConformanceEvaluation {
    let standard =
        ContractStandardIndex::new("STD-FORTRESS-ENGINEERING", EDITION, ["ARCH-SEMANTIC-001"]);
    let compilation = compile_contract_coherency_graph(files, &standard, None);
    let ccg = compilation
        .graph()
        .unwrap_or_else(|| panic!("fixture CCG compiles: {:#?}", compilation.violations()));
    let input = ImplementationObservationInput::new(
        "sha256:semantic-conformance-fixture",
        files
            .iter()
            .map(|(path, bytes)| SnapshotBoundFile::from_bytes(path, bytes.clone()))
            .collect(),
        vec![
            ModuleTerritory::new("PF-SEMANTIC-FIXTURE", ""),
            ModuleTerritory::new("AF-SAMPLE-0001", "mods/sample"),
        ],
    );
    let observed = observe_rust_implementation(&input).expect("implementation observes");
    let psm = compile_program_semantic_model(&ProgramSemanticInput::new(
        "PF-SEMANTIC-FIXTURE",
        input,
        Vec::<String>::new(),
        observed.module_dependencies().iter().map(|dependency| {
            (
                dependency.source_module().to_owned(),
                dependency.target_module().to_owned(),
            )
        }),
    ))
    .expect("PSM compiles");
    let functions = load_function_contracts(&psm, Vec::new()).expect("empty functions load");
    let semantic = analyze_program_domains(&psm, &functions, EDITION).expect("domains analyze");
    let states = load_state_contracts(&psm, Vec::new()).expect("empty states load");
    let state_effect = analyze_state_effects(&psm, &semantic, &states, &functions, EDITION)
        .expect("effects analyze");
    let realization =
        reconcile_implementation(ccg, &observed, EDITION).expect("realization reconciles");
    evaluate_semantic_conformance(ccg, &psm, state_effect.model(), &realization, EDITION)
        .expect("semantic conformance evaluates")
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R05-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R05
#[test]
fn module_contract_versions_distinguish_undeclared_and_explicit_policy() {
    let legacy = ModuleContract::from_json_str(&root_contract()).expect("v2 remains supported");
    assert!(legacy.semantic_policy().is_none());

    let source = module_contract(
        "AF-SAMPLE-0001",
        &["filesystem"],
        &["network.server"],
        &["environment.read"],
        &["environment.write", "filesystem.write"],
    );
    let current = ModuleContract::from_json_str(&source).expect("v3 policy validates");
    let policy = current.semantic_policy().expect("policy is authored");
    assert_eq!(policy.capabilities().allow(), ["filesystem"]);
    assert_eq!(
        policy.effects().deny(),
        ["environment.write", "filesystem.write"]
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R05-002`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R05
#[test]
fn semantic_policy_rejects_unknown_or_contradictory_authority() {
    let unknown = module_contract("AF-SAMPLE-0001", &["database"], &[], &[], &[]);
    assert!(ModuleContract::from_json_str(&unknown).is_err());
    let conflict = module_contract("AF-SAMPLE-0001", &["filesystem"], &["filesystem"], &[], &[]);
    assert!(ModuleContract::from_json_str(&conflict).is_err());
}

/// `T-ARCH-SEMANTIC-001-R01-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn refined_policy_preserves_allowance_and_blocks_direct_and_transitive_write() {
    let source = r#"
pub fn read_file() { let _ = std::fs::read("input"); }
pub fn write_file() { let _ = std::fs::write("output", b"x"); }
pub fn entry() { write_file(); }
"#;
    let policy = module_contract(
        "AF-SAMPLE-0001",
        &["filesystem"],
        &[],
        &[],
        &["filesystem.write"],
    );
    let first = evaluate(source, policy.clone());
    let second = evaluate(source, policy);
    let module = first
        .model()
        .module("AF-SAMPLE-0001")
        .expect("Module concludes");
    assert_eq!(module.state(), SemanticConformanceState::Fail);
    assert!(module.observations().iter().any(|observation| {
        observation.effect().stable_id() == "filesystem.read"
            && observation.policy_disposition()
                == Some(fortress_core::semantic_conformance::PolicyDisposition::Allow)
    }));
    let writes = module
        .observations()
        .iter()
        .filter(|observation| observation.effect().stable_id() == "filesystem.write")
        .collect::<Vec<_>>();
    assert!(
        writes
            .iter()
            .any(|observation| observation.call_chain().len() == 1)
    );
    assert!(
        writes
            .iter()
            .any(|observation| observation.call_chain().len() == 2)
    );
    assert_eq!(first.findings().len(), 2);
    assert_eq!(
        first.model().to_canonical_json().unwrap(),
        second.model().to_canonical_json().unwrap()
    );
    assert_eq!(
        first
            .findings()
            .iter()
            .map(fortress_core::finding::CanonicalFinding::finding_id)
            .collect::<Vec<_>>(),
        second
            .findings()
            .iter()
            .map(fortress_core::finding::CanonicalFinding::finding_id)
            .collect::<Vec<_>>()
    );
}

/// `T-ARCH-SEMANTIC-001-R01-002`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn claim_relative_uncertainty_is_unknown_without_fabricated_capability() {
    let result = evaluate(
        "pub fn invoke<F: Fn()>(f: F) { f(); } pub fn arithmetic() -> u32 { 2 + 2 }",
        module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]),
    );
    let module = result.model().module("AF-SAMPLE-0001").unwrap();
    assert_eq!(module.state(), SemanticConformanceState::Unknown);
    assert_eq!(result.model().summary().blocking_findings(), 0);
    assert_eq!(result.model().summary().not_evaluable_findings(), 1);
    assert!(result.findings().is_empty());
    assert_eq!(result.coverage_findings().len(), 1);
    assert!(module.observations().iter().all(|observation| {
        observation
            .capability()
            .map(fortress_core::state_effect_analysis::EffectCapability::stable_id)
            != Some("filesystem")
    }));
}

/// `T-ARCH-SEMANTIC-001-R01-003`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn panic_unsafe_and_residual_external_remain_independent_policy_targets() {
    let source = r#"
pub unsafe fn raw() {}
pub fn panic_path() { panic!("stop"); }
pub fn residual() { std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst); }
"#;
    let result = evaluate(
        source,
        module_contract(
            "AF-SAMPLE-0001",
            &[],
            &[],
            &[],
            &["external_interaction", "may_panic", "unsafe_execution"],
        ),
    );
    let targets = result
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .conclusions()
        .iter()
        .filter(|conclusion| conclusion.state() == SemanticConformanceState::Fail)
        .map(fortress_core::semantic_conformance::SemanticPolicyConclusion::target)
        .collect::<Vec<_>>();
    assert_eq!(
        targets,
        ["external_interaction", "may_panic", "unsafe_execution"]
    );
    assert!(result.findings().len() >= 3);
}

/// `T-ARCH-SEMANTIC-001-R01-004`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn indexed_evaluation_scales_to_one_thousand_policies_and_ten_thousand_effects() {
    let mut files = BTreeMap::new();
    files.insert("contract.json".into(), root_contract().into_bytes());
    for index in 0..1_000 {
        let id = format!("AF-STRESS-{index:04}");
        files.insert(
            format!("mods/m{index:04}/contract.json"),
            module_contract(&id, &["filesystem"], &[], &[], &[]).into_bytes(),
        );
    }
    files.insert(
        "mods/sample/contract.json".into(),
        module_contract("AF-SAMPLE-0001", &["filesystem"], &[], &[], &[]).into_bytes(),
    );
    files.insert(
        "mods/sample/data/Cargo.toml".into(),
        b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../code/lib.rs'\n"
            .to_vec(),
    );
    let mut source = String::new();
    for index in 0..10_000 {
        writeln!(
            source,
            "pub fn f{index:05}() {{ let _ = std::fs::read(\"x\"); }}"
        )
        .expect("String writes cannot fail");
    }
    files.insert("mods/sample/code/lib.rs".into(), source.into_bytes());
    let started = Instant::now();
    let result = evaluate_files(&files);
    assert!(started.elapsed().as_secs() < 120);
    assert_eq!(result.model().summary().modules_with_policy(), 1_001);
    assert_eq!(result.model().summary().governed_observations(), 10_000);
    assert!(result.findings().is_empty());
}
