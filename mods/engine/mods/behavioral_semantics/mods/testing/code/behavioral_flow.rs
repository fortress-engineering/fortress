//! Parent-local conformance for Intended Behavioral Flow Graph v1.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::audit::compile_repository_bfg;
use fortress_core::behavioral_semantics::{
    BFG_UNSUPPORTED_SEMANTICS, BehavioralModelingState, compile_intended_bfg,
    evaluate_behavioral_semantics,
};
use fortress_core::contract_coherency::{
    ContractCoherencyGraph, ContractStandardIndex, ModuleContract, compile_contract_coherency_graph,
};
use serde_json::{Value, json};

const FEATURE: &str = "AF-BFG-FEATURE-0001";
const REQUIREMENT: &str = "AF-BFG-FEATURE-0001-R01";
const TEST_ID: &str = "T-AF-BFG-FEATURE-0001-R01-001";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn base_contract(id: &str, name: &str) -> Value {
    json!({
        "$schema": "urn:fortress:schema:v2:module-contract",
        "schema_version": 2,
        "id": id,
        "display_name": name,
        "provides": [],
        "requires": [],
        "relationships": [],
        "constraints": [],
        "guarantees": [],
        "features": [],
        "behavior": []
    })
}

fn root_contract(behavior: Value) -> Value {
    let mut contract = base_contract("PF-BFG-FIXTURE", "Bfg Fixture");
    contract["ecosystem"] = json!({
        "repository_grammar": 1,
        "standard": {
            "id": "STD-FORTRESS-ENGINEERING",
            "edition": "1.0.0-draft.1"
        }
    });
    contract["features"] = json!([{
        "id": FEATURE,
        "version": "0.1.0",
        "requirements": [{
            "id": REQUIREMENT,
            "statement": "The synthetic Feature has an intended behavioral flow.",
            "tests": [TEST_ID]
        }]
    }]);
    contract["behavior"] = behavior;
    contract
}

fn testing_contract() -> Value {
    let mut contract = base_contract("TEST-BFG-FIXTURE-0001", "Bfg Fixture Testing");
    contract["relationships"] = json!([{
        "type": "verifies",
        "target": "PF-BFG-FIXTURE",
        "subjects": [FEATURE]
    }]);
    contract
}

fn participant_contract(behavior: Value) -> Value {
    let mut contract = base_contract("AF-BFG-PARTICIPANT-0001", "Bfg Participant");
    contract["behavior"] = behavior;
    contract
}

fn checkpoint(id: &str, kind: &str, outcome: Option<&str>, transitions: Value) -> Value {
    let mut value = json!({
        "id": id,
        "feature": FEATURE,
        "kind": kind,
        "transitions": []
    });
    value["transitions"] = transitions;
    if let Some(outcome) = outcome {
        value["outcome"] = json!(outcome);
    }
    value
}

fn canonical(value: Value) -> Vec<u8> {
    serde_json::from_value::<ModuleContract>(value)
        .expect("contract fixture has the v2 wire shape")
        .to_canonical_json()
        .expect("contract fixture serializes")
        .into_bytes()
}

fn compile(root_behavior: Value, participant_behavior: Option<Value>) -> ContractCoherencyGraph {
    let mut files = BTreeMap::from([
        (
            "contract.json".to_owned(),
            canonical(root_contract(root_behavior)),
        ),
        (
            "mods/testing/contract.json".to_owned(),
            canonical(testing_contract()),
        ),
    ]);
    if let Some(behavior) = participant_behavior {
        files.insert(
            "mods/participant/contract.json".into(),
            canonical(participant_contract(behavior)),
        );
    }
    let result = compile_contract_coherency_graph(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            ["BEHAVIOR-FLOW-001"],
        ),
        None,
    );
    result
        .graph()
        .unwrap_or_else(|| panic!("fixture CCG compiles: {:#?}", result.violations()))
        .clone()
}

fn linear() -> Value {
    json!([
        checkpoint(
            "CHK-FLOW-ACTION",
            "action",
            None,
            json!([{"target": "CHK-FLOW-DONE"}])
        ),
        checkpoint("CHK-FLOW-DONE", "terminal", Some("done"), json!([])),
        checkpoint(
            "CHK-FLOW-START",
            "trigger",
            None,
            json!([{"target": "CHK-FLOW-ACTION"}])
        )
    ])
}

fn violation_codes(behavior: Value) -> Vec<String> {
    let ccg = compile(behavior, None);
    compile_intended_bfg(&ccg)
        .expect("BFG compiles")
        .violations()
        .iter()
        .map(|violation| violation.code().to_owned())
        .collect()
}

/// `T-AF-BEHAVIORAL-SEMANTICS-0001-R01-001`
/// Fortress requirement: AF-BEHAVIORAL-SEMANTICS-0001-R01
#[test]
fn linear_branching_and_looping_flows_compile() {
    let linear_graph = compile_intended_bfg(&compile(linear(), None)).expect("linear BFG compiles");
    assert_eq!(linear_graph.summary().modeled_features(), 1);
    assert_eq!(linear_graph.summary().checkpoints(), 3);
    assert_eq!(linear_graph.summary().edges(), 2);
    assert_eq!(linear_graph.summary().terminals(), 1);
    assert!(linear_graph.violations().is_empty());

    let branching = json!([
        checkpoint(
            "CHK-FLOW-DECIDE",
            "decision",
            None,
            json!([
                {"outcome": "accept", "target": "CHK-FLOW-DONE"},
                {"outcome": "reject", "target": "CHK-FLOW-REJECTED"}
            ])
        ),
        checkpoint("CHK-FLOW-DONE", "terminal", Some("done"), json!([])),
        checkpoint("CHK-FLOW-REJECTED", "terminal", Some("rejected"), json!([])),
        checkpoint(
            "CHK-FLOW-START",
            "trigger",
            None,
            json!([{"target": "CHK-FLOW-DECIDE"}])
        )
    ]);
    let graph = compile_intended_bfg(&compile(branching, None)).expect("branching BFG compiles");
    assert_eq!(graph.summary().decisions(), 1);
    assert_eq!(graph.flows()[0].decision_branches().len(), 2);
    assert!(graph.violations().is_empty());

    let looping = json!([
        checkpoint(
            "CHK-FLOW-DECIDE",
            "decision",
            None,
            json!([
                {"outcome": "retry", "target": "CHK-FLOW-START"},
                {"outcome": "stop", "target": "CHK-FLOW-DONE"}
            ])
        ),
        checkpoint("CHK-FLOW-DONE", "terminal", Some("done"), json!([])),
        checkpoint(
            "CHK-FLOW-START",
            "trigger",
            None,
            json!([{"target": "CHK-FLOW-DECIDE"}])
        )
    ]);
    let graph = compile_intended_bfg(&compile(looping, None)).expect("loop BFG compiles");
    assert_eq!(graph.summary().loops(), 1);
    assert!(graph.violations().is_empty());
}

/// `T-AF-BEHAVIORAL-SEMANTICS-0001-R01-002`
/// Fortress requirement: AF-BEHAVIORAL-SEMANTICS-0001-R01
#[test]
fn distributed_flow_derives_lanes_boundaries_and_provenance() {
    let root = json!([checkpoint(
        "CHK-FLOW-START",
        "trigger",
        None,
        json!([{"target": "CHK-FLOW-WORK"}])
    )]);
    let child = json!([
        checkpoint("CHK-FLOW-DONE", "terminal", Some("done"), json!([])),
        checkpoint(
            "CHK-FLOW-WORK",
            "action",
            None,
            json!([{"target": "CHK-FLOW-DONE"}])
        )
    ]);
    let graph =
        compile_intended_bfg(&compile(root, Some(child))).expect("distributed BFG compiles");
    let flow = &graph.flows()[0];
    assert_eq!(
        flow.participating_modules(),
        ["AF-BFG-PARTICIPANT-0001", "PF-BFG-FIXTURE"]
    );
    assert_eq!(flow.module_boundary_crossings().len(), 1);
    assert_eq!(
        flow.module_boundary_crossings()[0].source(),
        "CHK-FLOW-START"
    );
    assert_eq!(
        flow.module_boundary_crossings()[0].provenance().path(),
        "contract.json"
    );
    assert!(
        flow.nodes()
            .iter()
            .all(|node| node.provenance().pointer().starts_with("/behavior/"))
    );
}

/// `T-AF-BEHAVIORAL-SEMANTICS-0001-R01-003`
/// Fortress requirement: AF-BEHAVIORAL-SEMANTICS-0001-R01
#[test]
fn dominators_post_dominators_bytes_and_digest_are_deterministic() {
    let ccg = compile(linear(), None);
    let first = compile_intended_bfg(&ccg).expect("first BFG compiles");
    let second = compile_intended_bfg(&ccg).expect("second BFG compiles");
    assert_eq!(first, second);
    assert_eq!(
        first.to_canonical_json().expect("first serializes"),
        second.to_canonical_json().expect("second serializes")
    );
    assert_eq!(
        first.digest().expect("first digests"),
        second.digest().expect("second digests")
    );
    let flow = &first.flows()[0];
    let dominators = flow
        .immediate_dominators()
        .iter()
        .map(|value| (value.checkpoint(), value.immediate()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(dominators["CHK-FLOW-START"], None);
    assert_eq!(dominators["CHK-FLOW-ACTION"], Some("CHK-FLOW-START"));
    assert_eq!(dominators["CHK-FLOW-DONE"], Some("CHK-FLOW-ACTION"));
    let post = flow
        .immediate_post_dominators()
        .iter()
        .map(|value| (value.checkpoint(), value.immediate()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(post["CHK-FLOW-START"], Some("CHK-FLOW-ACTION"));
    assert_eq!(post["CHK-FLOW-ACTION"], Some("CHK-FLOW-DONE"));
    assert_eq!(post["CHK-FLOW-DONE"], None);
}

/// `T-AF-BEHAVIORAL-SEMANTICS-0001-R02-001`
/// Fortress requirement: AF-BEHAVIORAL-SEMANTICS-0001-R02
#[test]
fn unmodeled_feature_is_explicit_and_non_failing() {
    let ccg = compile(json!([]), None);
    let evaluation =
        evaluate_behavioral_semantics(&ccg, "1.0.0-draft.1").expect("unmodeled graph evaluates");
    assert_eq!(evaluation.graph().summary().modeled_features(), 0);
    assert_eq!(evaluation.graph().summary().unmodeled_features(), 1);
    assert_eq!(
        evaluation.graph().feature_states()[0].state(),
        BehavioralModelingState::Unmodeled
    );
    assert!(evaluation.findings().is_empty());
    assert_eq!(
        evaluation.graph().unsupported_semantics(),
        BFG_UNSUPPORTED_SEMANTICS
    );
}

/// `T-BEHAVIOR-FLOW-001-R01-001`
/// Fortress requirement: AF-BEHAVIORAL-SEMANTICS-0001-R02
#[test]
fn trigger_terminal_and_dead_region_contradictions_are_exact() {
    let zero_trigger = json!([
        checkpoint("CHK-FLOW-DONE", "terminal", Some("done"), json!([])),
        checkpoint(
            "CHK-FLOW-WORK",
            "action",
            None,
            json!([{"target": "CHK-FLOW-DONE"}])
        )
    ]);
    assert_eq!(violation_codes(zero_trigger), ["BFG-TRIGGER-COUNT"]);

    let multiple_trigger = json!([
        checkpoint("CHK-FLOW-DONE", "terminal", Some("done"), json!([])),
        checkpoint(
            "CHK-FLOW-START",
            "trigger",
            None,
            json!([{"target": "CHK-FLOW-DONE"}])
        ),
        checkpoint(
            "CHK-FLOW-START-TWO",
            "trigger",
            None,
            json!([{"target": "CHK-FLOW-DONE"}])
        )
    ]);
    assert_eq!(violation_codes(multiple_trigger), ["BFG-TRIGGER-COUNT"]);

    let unreachable = json!([
        checkpoint("CHK-FLOW-DONE", "terminal", Some("done"), json!([])),
        checkpoint("CHK-FLOW-ORPHAN", "terminal", Some("orphan"), json!([])),
        checkpoint(
            "CHK-FLOW-START",
            "trigger",
            None,
            json!([{"target": "CHK-FLOW-DONE"}])
        )
    ]);
    assert_eq!(violation_codes(unreachable), ["BFG-UNREACHABLE-CHECKPOINT"]);
}

/// `T-BEHAVIOR-FLOW-001-R01-002`
/// Fortress requirement: AF-BEHAVIORAL-SEMANTICS-0001-R02
#[test]
fn nonterminating_components_and_branches_are_exact() {
    let no_terminal = json!([
        checkpoint(
            "CHK-FLOW-START",
            "trigger",
            None,
            json!([{"target": "CHK-FLOW-WORK"}])
        ),
        checkpoint(
            "CHK-FLOW-WORK",
            "action",
            None,
            json!([{"target": "CHK-FLOW-START"}])
        )
    ]);
    assert_eq!(
        violation_codes(no_terminal),
        [
            "BFG-CLOSED-SCC",
            "BFG-NO-TERMINAL-PATH",
            "BFG-NO-TERMINAL-PATH",
            "BFG-TERMINAL-MISSING"
        ]
    );

    let bad_branch = json!([
        checkpoint(
            "CHK-FLOW-DECIDE",
            "decision",
            None,
            json!([
                {"outcome": "done", "target": "CHK-FLOW-DONE"},
                {"outcome": "loop", "target": "CHK-FLOW-LOOP"}
            ])
        ),
        checkpoint("CHK-FLOW-DONE", "terminal", Some("done"), json!([])),
        checkpoint(
            "CHK-FLOW-LOOP",
            "action",
            None,
            json!([{"target": "CHK-FLOW-LOOP"}])
        ),
        checkpoint(
            "CHK-FLOW-START",
            "trigger",
            None,
            json!([{"target": "CHK-FLOW-DECIDE"}])
        )
    ]);
    assert_eq!(
        violation_codes(bad_branch),
        [
            "BFG-CLOSED-SCC",
            "BFG-NO-TERMINAL-PATH",
            "BFG-NONVIABLE-BRANCH"
        ]
    );
}

/// `T-BEHAVIOR-FLOW-001-R01-003`
/// Fortress requirement: AF-BEHAVIORAL-SEMANTICS-0001-R02
#[test]
fn contract_and_ccg_boundaries_reject_invalid_authored_declarations() {
    let mut duplicate_decision = root_contract(json!([
        checkpoint(
            "CHK-FLOW-DECIDE",
            "decision",
            None,
            json!([
                {"outcome": "same", "target": "CHK-FLOW-DONE"},
                {"outcome": "same", "target": "CHK-FLOW-DONE"}
            ])
        ),
        checkpoint("CHK-FLOW-DONE", "terminal", Some("done"), json!([]))
    ]));
    let wire = canonical(duplicate_decision.clone());
    let error = ModuleContract::from_json_str(
        std::str::from_utf8(&wire).expect("canonical contract is UTF-8"),
    )
    .expect_err("duplicate outcome fails locally");
    let message = error.to_string();
    assert_eq!(
        message,
        "Module Contract is invalid: `behavior.transitions` must be strictly sorted and contain no duplicates"
    );

    duplicate_decision["behavior"] = json!([]);
    let mut unrelated = participant_contract(json!([checkpoint(
        "CHK-FLOW-DONE",
        "terminal",
        Some("done"),
        json!([])
    )]));
    unrelated["behavior"][0]["feature"] = json!("AF-MISSING-FEATURE-0001");
    let files = BTreeMap::from([
        ("contract.json".to_owned(), canonical(duplicate_decision)),
        ("mods/other/contract.json".to_owned(), canonical(unrelated)),
        (
            "mods/testing/contract.json".to_owned(),
            canonical(testing_contract()),
        ),
    ]);
    let result = compile_contract_coherency_graph(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            ["BEHAVIOR-FLOW-001"],
        ),
        None,
    );
    assert_eq!(
        result
            .violations()
            .iter()
            .map(fortress_core::contract_coherency::CcgViolation::code)
            .collect::<Vec<_>>(),
        ["CCG-CONTRACT-INVALID"]
    );
}

/// `T-AF-BEHAVIORAL-SEMANTICS-0001-R01-004`
/// Fortress requirement: AF-BEHAVIORAL-SEMANTICS-0001-R01
#[test]
fn live_fortress_bfg_is_coherent_deterministic_and_fresh() {
    let root = repository_root();
    let first = compile_repository_bfg(&root).expect("Fortress BFG compiles");
    let second = compile_repository_bfg(&root).expect("Fortress BFG repeats");
    let first_bytes = first.to_canonical_json().expect("first BFG serializes");
    assert_eq!(first, second);
    assert_eq!(
        first_bytes,
        second.to_canonical_json().expect("second BFG serializes")
    );
    assert!(first_bytes.ends_with('\n'));
    assert!(!first_bytes.contains('\r'));
    assert_eq!(first.summary().modeled_features(), 1);
    assert_eq!(first.summary().incoherent_features(), 0);
    assert!(first.violations().is_empty());
    let committed =
        fs::read(root.join("info/behavioral_flow_graph.json")).expect("committed self-BFG reads");
    assert_eq!(first_bytes.as_bytes(), committed);
}
