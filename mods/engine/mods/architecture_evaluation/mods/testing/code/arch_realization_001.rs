//! Conformance evidence for observed implementation reconciliation.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::architecture_realization::{ReconciliationState, reconcile_implementation};
use fortress_core::contract_coherency::{
    ContractCoherencyGraph, ContractStandardIndex, ModuleContract, compile_contract_coherency_graph,
};
use fortress_core::implementation_observation::{
    Conditionality, ImplementationObservation, ImplementationObservationInput, ModuleTerritory,
    ObservationIssue, ObservationIssueKind, ObservationProvenance, ObservedImplementation,
    SnapshotBoundFile, SourceLocation, observe_rust_implementation,
};
use fortress_core::observation::{ObservationPolicy, observe_repository};
use serde_json::{Value, json};

const EDITION: &str = "1.0.0-draft.1";

fn contract(id: &str, name: &str, root: bool, capability: &str) -> Value {
    let mut value = json!({
        "$schema": "urn:fortress:schema:v2:module-contract",
        "schema_version": 2,
        "id": id,
        "display_name": name,
        "provides": [{
            "id": capability,
            "version": "0.1.0",
            "visibility": "project"
        }],
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
                "edition": EDITION
            }
        });
    }
    value
}

fn require(value: &mut Value, provider: &str, capability: &str) {
    value["requires"] = json!([{
        "provider": provider,
        "capability": capability,
        "version": "^0.1.0"
    }]);
}

fn canonical(value: Value) -> Vec<u8> {
    serde_json::from_value::<ModuleContract>(value)
        .expect("contract shape")
        .to_canonical_json()
        .expect("canonicalizes")
        .into_bytes()
}

fn declared_chain() -> ContractCoherencyGraph {
    let mut a = contract("AF-A-0001", "A", true, "CAP-A");
    require(&mut a, "AF-B-0001", "CAP-B");
    let mut b = contract("AF-B-0001", "B", false, "CAP-B");
    require(&mut b, "AF-C-0001", "CAP-C");
    let c = contract("AF-C-0001", "C", false, "CAP-C");
    let files = BTreeMap::from([
        ("contract.json".into(), canonical(a)),
        ("mods/b/contract.json".into(), canonical(b)),
        ("mods/c/contract.json".into(), canonical(c)),
    ]);
    let compilation = compile_contract_coherency_graph(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            EDITION,
            ["ARCH-REALIZATION-001"],
        ),
        None,
    );
    compilation
        .graph()
        .unwrap_or_else(|| panic!("chain compiles: {:#?}", compilation.violations()))
        .clone()
}

fn evidence(source: &str, target: Option<&str>, reference: &str) -> ObservationProvenance {
    ObservationProvenance::new(
        format!("mods/{}/code/source.rs", source.to_ascii_lowercase()),
        source,
        reference,
        SourceLocation::new(4, 5),
        target.map(str::to_owned),
    )
}

fn governed(source: &str, target: &str, reference: &str) -> ImplementationObservation {
    let provenance = evidence(source, Some(target), reference);
    ImplementationObservation::governed(
        source,
        provenance.source_path(),
        target,
        Conditionality::Unconditional,
        provenance.clone(),
    )
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R03-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R03
#[test]
fn reconciliation_distinguishes_every_supported_state_without_circular_observation() {
    let observations = vec![
        governed("AF-A-0001", "AF-B-0001", "crate::b::Surface"),
        governed("AF-A-0001", "AF-C-0001", "crate::c::Surface"),
        governed("AF-C-0001", "AF-A-0001", "crate::a::Surface"),
        ImplementationObservation::external(
            "AF-A-0001",
            "code/source.rs",
            "serde",
            Conditionality::Unconditional,
            evidence("AF-A-0001", Some("serde"), "serde::Serialize"),
        ),
        ImplementationObservation::unresolved(
            "AF-A-0001",
            "code/source.rs",
            Conditionality::Unconditional,
            evidence("AF-A-0001", None, "mystery::Surface"),
        ),
    ];
    let observed = ObservedImplementation::from_facts(
        "sha256:fixture",
        "fixture-rust",
        "1.0.0",
        observations,
        Vec::new(),
    );
    let result = reconcile_implementation(&declared_chain(), &observed, EDITION)
        .expect("findings normalize");
    let summary = result.summary();
    assert_eq!(summary.declared_direct(), 2);
    assert_eq!(summary.observed_governed(), 3);
    assert_eq!(summary.declared_and_observed(), 1);
    assert_eq!(summary.observed_transitive_bypass(), 1);
    assert_eq!(summary.observed_undeclared(), 1);
    assert_eq!(summary.declared_unobserved(), 1);
    assert_eq!(summary.external(), 1);
    assert_eq!(summary.unresolved(), 1);
    assert_eq!(result.findings().len(), 2);
    assert!(
        result
            .unsupported_semantics()
            .contains(&"capability_to_source_realization".to_owned())
    );
}

/// `T-ARCH-REALIZATION-001-R01-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R03
#[test]
fn transitive_reachability_never_authorizes_direct_source_access() {
    let observed = ObservedImplementation::from_facts(
        "sha256:fixture",
        "fixture-rust",
        "1.0.0",
        vec![governed("AF-A-0001", "AF-C-0001", "crate::c::Surface")],
        Vec::new(),
    );
    let result = reconcile_implementation(&declared_chain(), &observed, EDITION)
        .expect("finding normalizes");
    let bypass = result
        .records()
        .iter()
        .find(|record| record.state() == ReconciliationState::ObservedTransitiveBypass)
        .expect("bypass recorded");
    assert_eq!(
        bypass.declared_path(),
        ["AF-A-0001", "AF-B-0001", "AF-C-0001"]
    );
    assert!(
        result.findings()[0]
            .message()
            .contains("transitive reachability is not direct authorization")
    );
}

/// `T-ARCH-REALIZATION-001-R01-002`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R03
#[test]
fn declared_unobserved_is_explicit_without_becoming_a_hard_failure() {
    let observed = ObservedImplementation::from_facts(
        "sha256:fixture",
        "fixture-rust",
        "1.0.0",
        Vec::new(),
        Vec::new(),
    );
    let first = reconcile_implementation(&declared_chain(), &observed, EDITION)
        .expect("reconciliation succeeds");
    let second = reconcile_implementation(&declared_chain(), &observed, EDITION)
        .expect("reconciliation repeats");
    assert_eq!(first, second);
    assert_eq!(first.summary().declared_unobserved(), 2);
    assert!(first.findings().is_empty());
}

/// `T-ARCH-REALIZATION-001-R01-003`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R03
#[test]
fn invalid_observation_is_a_hard_finding_while_unsupported_coverage_is_explicit() {
    let observed = ObservedImplementation::from_facts(
        "sha256:fixture",
        "fixture-rust",
        "1.0.0",
        Vec::new(),
        vec![
            ObservationIssue::new(
                ObservationIssueKind::Invalid,
                "code/invalid.rs",
                "source has no physical Module owner",
            ),
            ObservationIssue::new(
                ObservationIssueKind::Unsupported,
                "code/macro.rs",
                "macro-generated dependency semantics are unsupported",
            ),
        ],
    );
    let result = reconcile_implementation(&declared_chain(), &observed, EDITION)
        .expect("issue finding normalizes");
    assert_eq!(result.summary().invalid(), 1);
    assert_eq!(result.summary().unsupported(), 1);
    assert_eq!(result.findings().len(), 1);
    assert!(result.findings()[0].message().contains("invalid"));
}

/// `T-ARCH-REALIZATION-001-R01-004`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R03
#[test]
fn live_fortress_has_no_unauthorized_or_transitive_bypass_rust_edges() {
    let root = repository_root();
    let observation = observe_repository(
        &root,
        &ObservationPolicy::new([".git"]).expect("policy validates"),
    )
    .expect("repository observes");
    let files: BTreeMap<String, Vec<u8>> = observation
        .files()
        .iter()
        .map(|file| {
            (
                file.path().into(),
                fs::read(root.join(file.path())).expect("observed bytes read"),
            )
        })
        .collect();
    let compilation = compile_contract_coherency_graph(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            EDITION,
            [
                "ARCH-DEPENDENCY-001",
                "ARCH-OWNERSHIP-001",
                "ARCH-REALIZATION-001",
                "BEHAVIOR-FLOW-001",
                "CONTRACT-COHERENCY-001",
                "REPO-DOCS-001",
                "REPO-MODULE-001",
                "STD-ID-001",
                "TEST-BOUNDARY-001",
                "TEST-TRACEABILITY-001",
            ],
        ),
        None,
    );
    let ccg = compilation
        .graph()
        .unwrap_or_else(|| panic!("live CCG compiles: {:#?}", compilation.violations()));
    let identity_by_path: BTreeMap<&str, _> = observation
        .files()
        .iter()
        .map(|file| (file.path(), file))
        .collect();
    let input = ImplementationObservationInput::new(
        "sha256:live-fixture",
        files
            .iter()
            .map(|(path, bytes)| {
                let identity = identity_by_path[path.as_str()];
                SnapshotBoundFile::new(path, identity.size(), identity.sha256(), bytes.clone())
            })
            .collect(),
        ccg.modules()
            .iter()
            .map(|(id, module)| ModuleTerritory::new(id, module.path()))
            .collect(),
    );
    let observed = observe_rust_implementation(&input).expect("live Rust observes");
    let realization =
        reconcile_implementation(ccg, &observed, EDITION).expect("live reconciliation succeeds");
    let unresolved: Vec<_> = realization
        .records()
        .iter()
        .filter(|record| record.state() == ReconciliationState::Unresolved)
        .flat_map(|record| record.evidence().iter())
        .map(|evidence| {
            format!(
                "{}:{}:{} {}",
                evidence.source_path(),
                evidence.location().line(),
                evidence.location().column(),
                evidence.reference()
            )
        })
        .collect();
    let declared_unobserved: Vec<_> = realization
        .records()
        .iter()
        .filter(|record| record.state() == ReconciliationState::DeclaredUnobserved)
        .map(|record| {
            format!(
                "{} -> {} ({})",
                record.source_module(),
                record.target_module().unwrap_or("unresolved"),
                record.declared_capabilities().join(", ")
            )
        })
        .collect();
    println!(
        "live realization summary: {:?}; declared-unobserved: {declared_unobserved:#?}; unresolved: {unresolved:#?}",
        realization.summary()
    );
    assert_eq!(realization.summary().observed_undeclared(), 0);
    assert_eq!(realization.summary().observed_transitive_bypass(), 0);
    assert!(realization.findings().is_empty());
}
