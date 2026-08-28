//! Parent-local conformance for Behavioral Realization and Realized BFG v1.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use fortress_core::audit::compile_repository_realized_bfg;
use fortress_core::behavioral_realization::{
    FeatureRealizationState, RealizedBehavioralFlowGraph,
    canonicalize_behavior_realization_contract_json,
};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repository root exists")
}

fn graph() -> &'static RealizedBehavioralFlowGraph {
    static GRAPH: OnceLock<RealizedBehavioralFlowGraph> = OnceLock::new();
    GRAPH.get_or_init(|| {
        compile_repository_realized_bfg(repository_root()).expect("self Realized BFG compiles")
    })
}

fn document() -> serde_json::Value {
    serde_json::from_str(&graph().to_canonical_json().expect("graph serializes"))
        .expect("graph JSON parses")
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R01-001`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R01
#[test]
fn validates_canonical_realization_contract() {
    let source =
        std::fs::read_to_string(repository_root().join("data/behavior_realization_contracts.json"))
            .expect("self contract exists");
    assert_eq!(
        canonicalize_behavior_realization_contract_json(&source).expect("canonicalizes"),
        source
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R01-002`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R01
#[test]
fn opts_in_complete_feature() {
    assert_eq!(graph().summary().opted_in_features(), 1);
    assert_eq!(document()["summary"]["checkpoints"], 10);
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R01-003`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R01
#[test]
fn binds_every_checkpoint_to_an_anchor() {
    assert_eq!(document()["summary"]["anchors"], 10);
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R01-004`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R01
#[test]
fn supports_alternative_anchor_arrays() {
    assert!(
        document()["flows"][0]["checkpoints"]
            .as_array()
            .expect("checkpoints")
            .iter()
            .all(|item| !item["anchor_events"].as_array().expect("events").is_empty())
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R01-005`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R01
#[test]
fn resolves_exact_symbol_anchors() {
    assert!(
        document()["implementation_events"]["events"]
            .as_array()
            .expect("events")
            .iter()
            .any(|event| event["kind"] == "symbol_entry")
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R01-006`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R01
#[test]
fn distinguishes_boolean_terminal_anchors() {
    let checkpoints = document()["flows"][0]["checkpoints"]
        .as_array()
        .expect("checkpoints")
        .clone();
    assert!(
        checkpoints
            .iter()
            .any(|item| item["checkpoint"] == "CHK-AUDIT-PASSED")
    );
    assert!(
        checkpoints
            .iter()
            .any(|item| item["checkpoint"] == "CHK-AUDIT-FAILED")
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R01-007`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R01
#[test]
fn retains_contract_provenance() {
    assert!(
        document()["flows"][0]["checkpoints"][0]["provenance"]
            .as_array()
            .expect("provenance")
            .iter()
            .any(|value| value == "data/behavior_realization_contracts.json")
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R01-008`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R01
#[test]
fn contract_digest_is_bound() {
    assert!(
        document()["realization_contract_digest"]
            .as_str()
            .expect("digest")
            .starts_with("sha256:")
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R02-001`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R02
#[test]
fn derives_language_neutral_events() {
    assert!(
        !document()["implementation_events"]["events"]
            .as_array()
            .expect("events")
            .is_empty()
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R02-002`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R02
#[test]
fn derives_program_control_edges() {
    assert!(
        !document()["implementation_events"]["edges"]
            .as_array()
            .expect("edges")
            .is_empty()
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R02-003`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R02
#[test]
fn event_model_is_deterministic() {
    assert_eq!(
        graph().to_canonical_json().expect("first"),
        graph().to_canonical_json().expect("second")
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R02-004`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R02
#[test]
fn events_preserve_module_lanes() {
    assert!(
        document()["implementation_events"]["events"]
            .as_array()
            .expect("events")
            .iter()
            .all(|event| event["module"]
                .as_str()
                .is_some_and(|value| !value.is_empty()))
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R02-005`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R02
#[test]
fn events_preserve_semantic_authority() {
    assert!(
        document()["implementation_events"]["events"]
            .as_array()
            .expect("events")
            .iter()
            .all(|event| event["authority"].is_string())
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R02-006`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R02
#[test]
fn events_preserve_coverage() {
    assert!(
        document()["implementation_events"]["events"]
            .as_array()
            .expect("events")
            .iter()
            .all(|event| event["coverage"].is_string())
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R02-007`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R02
#[test]
fn semantic_helpers_are_not_checkpoints() {
    assert!(
        document()["flows"][0]["checkpoints"]
            .as_array()
            .expect("checkpoints")
            .iter()
            .all(|item| item["checkpoint"]
                .as_str()
                .expect("checkpoint")
                .starts_with("CHK-"))
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R03-001`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R03
#[test]
fn live_audit_feature_realizes_coherently() {
    assert_eq!(
        graph().flows()[0].state(),
        FeatureRealizationState::RealizedCoherent
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R03-002`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R03
#[test]
fn intended_edges_are_realized() {
    assert_eq!(document()["summary"]["intended_and_realized_edges"], 9);
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R03-003`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R03
#[test]
fn no_intended_edge_is_unproven_in_self_model() {
    assert_eq!(document()["summary"]["intended_unproven_edges"], 0);
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R03-004`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R03
#[test]
fn no_realized_undeclared_self_edge_exists() {
    assert_eq!(document()["summary"]["realized_undeclared_edges"], 0);
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R03-005`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R03
#[test]
fn no_intended_edge_is_proven_impossible() {
    assert_eq!(document()["summary"]["intended_proven_impossible_edges"], 0);
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R03-006`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R03
#[test]
fn intended_dominators_are_checked() {
    assert!(
        document()["summary"]["dominator_checks"]
            .as_u64()
            .expect("checks")
            > 0
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R03-007`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R03
#[test]
fn no_supported_self_bypass_exists() {
    assert_eq!(graph().summary().proven_bypasses(), 0);
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R03-008`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R03
#[test]
fn reconciles_decision_branches() {
    assert_eq!(document()["summary"]["decision_reconciliations"], 2);
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R03-009`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R03
#[test]
fn reconciles_terminal_outcomes() {
    assert_eq!(document()["summary"]["terminal_reconciliations"], 2);
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R04-001`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R04
#[test]
fn canonical_realized_bfg_has_trailing_lf() {
    assert!(graph().to_canonical_json().expect("JSON").ends_with('\n'));
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R04-002`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R04
#[test]
fn realized_bfg_digest_is_deterministic() {
    assert_eq!(
        graph().digest().expect("first"),
        graph().digest().expect("second")
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R04-003`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R04
#[test]
fn binds_every_upstream_digest() {
    for field in [
        "intended_bfg_digest",
        "psm_digest",
        "semantic_analysis_digest",
        "state_effect_digest",
        "information_flow_digest",
        "environmental_analysis_digest",
    ] {
        assert!(
            document()[field]
                .as_str()
                .expect("digest")
                .starts_with("sha256:")
        );
    }
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R04-004`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R04
#[test]
fn derives_verification_obligations_without_evidence_claim() {
    assert!(!graph().verification_obligations().is_empty());
    assert!(
        document()["verification_obligations"]
            .as_array()
            .expect("obligations")
            .iter()
            .all(|item| item["evidence_status"] == "NOT_ESTABLISHED")
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R04-005`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R04
#[test]
fn unsupported_semantics_remain_explicit() {
    assert!(
        graph()
            .unsupported_semantics()
            .iter()
            .any(|item| item == "dynamic_runtime_trace_realization")
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R04-006`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R04
#[test]
fn repeated_live_self_generation_is_byte_identical() {
    let first = compile_repository_realized_bfg(repository_root())
        .expect("fresh graph")
        .to_canonical_json()
        .expect("fresh JSON");
    assert_eq!(first, graph().to_canonical_json().expect("cached JSON"));
}
