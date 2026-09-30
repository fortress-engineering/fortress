//! Parent-local conformance for Intended Behavioral Flow Graph v1.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::audit::{compile_repository_bfg, prepare_repository_certification_source};
use fortress_core::behavioral_semantics::{
    BFG_UNSUPPORTED_SEMANTICS, BehavioralModelingState, compile_intended_bfg,
    evaluate_behavioral_semantics,
};
use fortress_core::contract_coherency::{
    ContractCoherencyGraph, ContractStandardIndex, ModuleContract, compile_contract_coherency_graph,
};
use fortress_core::control_layout::{CONTROL_LAYOUT_SOURCE, LEGACY_CONTROL_LAYOUT_SOURCE};
use fortress_core::control_manifest::{
    ArtifactStorage, AssessmentGenerationManifest, AssessmentSelectionIndex,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FEATURE: &str = "AF-BFG-FEATURE-0001";
const REQUIREMENT: &str = "AF-BFG-FEATURE-0001-R01";
const TEST_ID: &str = "T-AF-BFG-FEATURE-0001-R01-001";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[derive(Debug, Eq, PartialEq)]
enum SelectedBfgSubject {
    Current,
    StaleSource,
    RetainedLayout,
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn local_selection_key() -> String {
    let source = json!({
        "project": "PF-FORTRESS",
        "profile": "fortress-complete-local-v1",
        "scope": "repository",
        "context_family": "native-static",
    })
    .to_string();
    digest(
        &fortress_core::wire::canonicalize_public_json(&source).expect("selection canonicalizes"),
    )
}

fn validate_selected_bfg(
    manifest: &AssessmentGenerationManifest,
    bytes: &[u8],
    current_source: &str,
    current_bfg: &[u8],
) -> Result<SelectedBfgSubject, String> {
    // Inspect the serialization of an already strictly validated owner record.
    let view = serde_json::to_value(manifest).map_err(|error| error.to_string())?;
    if view["generation_kind"] != "LOCAL_QUALITY"
        || view["project"] != "PF-FORTRESS"
        || view["profile"] != "fortress-complete-local-v1"
        || view["selection_key"] != local_selection_key()
    {
        return Err("selected generation has a different assessment context".into());
    }
    let layout_source = match view["control_layout"]["id"].as_str() {
        Some("fortress-control-layout-v1") => LEGACY_CONTROL_LAYOUT_SOURCE,
        Some("fortress-control-layout-v2") => CONTROL_LAYOUT_SOURCE,
        _ => return Err("selected generation has an unsupported layout".into()),
    };
    if view["control_layout"]["digest"] != digest(layout_source.as_bytes()) {
        return Err("selected layout digest does not match its registry".into());
    }
    let artifacts = view["artifacts"]
        .as_array()
        .expect("validated artifact array");
    let bfg = artifacts
        .iter()
        .find(|artifact| artifact["id"] == "bfg")
        .ok_or("selected BFG descriptor is missing")?;
    if bfg["content_digest"] != digest(bytes)
        || bfg["byte_count"].as_u64() != Some(bytes.len() as u64)
    {
        return Err("selected BFG bytes do not match their descriptor".into());
    }
    let payload: Value = fortress_core::wire::parse_public_json(
        std::str::from_utf8(bytes).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let ccg = artifacts
        .iter()
        .find(|artifact| artifact["id"] == "ccg")
        .ok_or("selected CCG descriptor is missing")?;
    if payload["source_ccg_digest"] != ccg["content_digest"] {
        return Err("selected BFG is not bound to its generation's CCG".into());
    }
    if view["source"]["fingerprint"] != current_source {
        return Ok(SelectedBfgSubject::StaleSource);
    }
    if view["control_layout"]["id"] != "fortress-control-layout-v2" {
        return Ok(SelectedBfgSubject::RetainedLayout);
    }
    if bytes != current_bfg {
        return Err("current selected BFG differs from the independently compiled bytes".into());
    }
    Ok(SelectedBfgSubject::Current)
}

fn selected_live_bfg(
    root: &Path,
    current_source: &str,
    current_bfg: &[u8],
) -> Result<SelectedBfgSubject, String> {
    let evidence = root.join("__fortress/evidence");
    let index_source =
        fs::read_to_string(evidence.join("current.json")).map_err(|error| error.to_string())?;
    let index = AssessmentSelectionIndex::from_json_str(&index_source)
        .map_err(|error| error.to_string())?;
    let selected_digest = index
        .generation(&local_selection_key())
        .ok_or("exact local-quality selection is missing")?;
    let generation = evidence.join("generations").join(
        selected_digest
            .strip_prefix("sha256:")
            .expect("validated digest"),
    );
    let source =
        fs::read_to_string(generation.join("manifest.json")).map_err(|error| error.to_string())?;
    let manifest =
        AssessmentGenerationManifest::from_json_str(&source).map_err(|error| error.to_string())?;
    if manifest
        .generation_digest()
        .map_err(|error| error.to_string())?
        != selected_digest
    {
        return Err("selected generation manifest does not match its digest".into());
    }
    let artifact = manifest
        .artifacts()
        .iter()
        .find(|artifact| artifact.id() == "bfg")
        .ok_or("selected BFG descriptor is missing")?;
    let ArtifactStorage::Included { member_name } = artifact.storage() else {
        return Err("selected BFG must be an included generation member".into());
    };
    let bytes = fs::read(generation.join(member_name)).map_err(|error| error.to_string())?;
    validate_selected_bfg(&manifest, &bytes, current_source, current_bfg)
}

fn selected_bfg_subject_controls(bytes: &[u8]) {
    let current_source = format!("sha256:{}", "a".repeat(64));
    let stale_source = format!("sha256:{}", "b".repeat(64));
    let payload: Value = serde_json::from_slice(bytes).expect("current BFG parses");
    let mut fixture = json!({
        "$schema": "urn:fortress:derived:v2:assessment-generation-manifest",
        "schema_version": 2,
        "generation_kind": "LOCAL_QUALITY",
        "project": "PF-FORTRESS",
        "profile": "fortress-complete-local-v1",
        "selection_key": local_selection_key(),
        "source": {"fingerprint": current_source, "file_count": 1},
        "control_layout": {
            "id": "fortress-control-layout-v2",
            "digest": digest(CONTROL_LAYOUT_SOURCE.as_bytes()),
        },
        "artifacts": [{
            "id": "bfg", "producer_id": "behavioral_semantics",
            "schema_ref": "urn:fortress:derived:v1:behavioral-flow-graph",
            "producer_semantic_version": "1.0.0",
            "content_digest": digest(bytes), "byte_count": bytes.len(),
            "disposition": "REQUIRED",
            "storage": {"kind": "INCLUDED", "member_name": "behavioral_flow_graph.json"},
        }, {
            "id": "ccg", "producer_id": "contract_coherency",
            "schema_ref": "urn:fortress:derived:v1:contract-coherency-graph",
            "producer_semantic_version": "1.0.0",
            "content_digest": payload["source_ccg_digest"], "byte_count": 1,
            "disposition": "REQUIRED",
            "storage": {"kind": "INCLUDED", "member_name": "ccg.json"},
        }],
    });
    let parse = |value: &Value| {
        AssessmentGenerationManifest::from_json_str(&value.to_string())
            .expect("selected generation fixture validates")
    };
    let current = parse(&fixture);
    assert_eq!(
        validate_selected_bfg(&current, bytes, &current_source, bytes),
        Ok(SelectedBfgSubject::Current)
    );
    assert!(validate_selected_bfg(&current, bytes, &current_source, b"different").is_err());
    assert_eq!(
        validate_selected_bfg(&current, bytes, &stale_source, b"different"),
        Ok(SelectedBfgSubject::StaleSource)
    );
    assert!(validate_selected_bfg(&current, b"corrupt", &stale_source, bytes).is_err());
    fixture["artifacts"][0]["storage"]["member_name"] = json!("../escape.json");
    assert!(AssessmentGenerationManifest::from_json_str(&fixture.to_string()).is_err());
    fixture["artifacts"][0]["storage"]["member_name"] = json!("behavioral_flow_graph.json");
    fixture["artifacts"][0]["byte_count"] = json!(bytes.len() + 1);
    assert!(validate_selected_bfg(&parse(&fixture), bytes, &stale_source, bytes).is_err());
    fixture["artifacts"][0]["byte_count"] = json!(bytes.len());
    fixture["control_layout"]["digest"] = json!(stale_source);
    assert!(validate_selected_bfg(&parse(&fixture), bytes, &stale_source, bytes).is_err());
    fixture["control_layout"] = json!({
        "id": "fortress-control-layout-v1",
        "digest": digest(LEGACY_CONTROL_LAYOUT_SOURCE.as_bytes()),
    });
    fixture["$schema"] = json!("urn:fortress:derived:v1:assessment-generation-manifest");
    fixture["schema_version"] = json!(1);
    assert_eq!(
        validate_selected_bfg(&parse(&fixture), bytes, &current_source, b"different"),
        Ok(SelectedBfgSubject::RetainedLayout)
    );
}

fn has_historical_generation(root: &Path) -> bool {
    fs::read_dir(root.join("__fortress/evidence/generations"))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| {
            fs::read(entry.path().join("manifest.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .is_some_and(|manifest| manifest["generation_kind"] == "HISTORICAL_MIGRATION")
        })
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
            "testing/contract.json".to_owned(),
            canonical(testing_contract()),
        ),
    ]);
    if let Some(behavior) = participant_behavior {
        files.insert(
            "participant/contract.json".into(),
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
        ("other/contract.json".to_owned(), canonical(unrelated)),
        (
            "testing/contract.json".to_owned(),
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
    selected_bfg_subject_controls(first_bytes.as_bytes());
    if root.join("__fortress/evidence/current.json").is_file() {
        let source = prepare_repository_certification_source(&root)
            .expect("current exact certification subject prepares");
        let subject = selected_live_bfg(&root, &source.digest, first_bytes.as_bytes())
            .expect("exact selected local-quality BFG is intact and reconciles with its subject");
        eprintln!("selected behavioral evidence subject: {subject:?}");
    } else {
        assert!(has_historical_generation(&root));
    }
}
