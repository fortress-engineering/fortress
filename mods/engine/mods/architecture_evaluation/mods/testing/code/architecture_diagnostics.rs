//! Conformance evidence for deterministic Semantic Architecture Diagnostics v1.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fortress_core::architecture_diagnostics::{
    ArchitectureDiagnosticKind, derive_architecture_diagnostics, lowest_common_module_ancestor,
};
use fortress_core::architecture_realization::reconcile_implementation;
use fortress_core::audit::{audit_repository, compile_repository_ccg};
use fortress_core::contract_coherency::{
    ContractCoherencyGraph, ContractStandardIndex, ModuleContract, compile_contract_coherency_graph,
};
use fortress_core::implementation_observation::{
    Conditionality, ImplementationObservation, ObservationProvenance, ObservedImplementation,
    SourceLocation,
};
use serde_json::{Value, json};

const EDITION: &str = "1.0.0-draft.1";

fn module(id: &str, display_name: &str, root: bool) -> Value {
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
                "edition": EDITION
            }
        });
    }
    value
}

fn provide(value: &mut Value, capability: &str, visibility: &str) {
    value["provides"]
        .as_array_mut()
        .expect("provides array")
        .push(json!({
            "id": capability,
            "version": "0.1.0",
            "visibility": visibility
        }));
}

fn require(value: &mut Value, provider: &str, capability: &str) {
    value["requires"]
        .as_array_mut()
        .expect("requires array")
        .push(json!({
            "provider": provider,
            "capability": capability,
            "version": "^0.1.0"
        }));
}

fn feature(value: &mut Value, feature_id: &str, requirement: &str, test_id: &str) {
    value["features"] = json!([{
        "id": feature_id,
        "version": "0.1.0",
        "requirements": [{
            "id": requirement,
            "statement": "The fixture behavior remains deterministic.",
            "tests": [test_id]
        }]
    }]);
}

fn verifies(value: &mut Value, parent: &str, subject: &str) {
    value["relationships"] = json!([{
        "type": "verifies",
        "target": parent,
        "subjects": [subject]
    }]);
}

fn canonical(value: Value) -> Vec<u8> {
    serde_json::from_value::<ModuleContract>(value)
        .expect("contract shape")
        .to_canonical_json()
        .expect("canonical contract")
        .into_bytes()
}

fn compile(modules: impl IntoIterator<Item = (&'static str, Value)>) -> ContractCoherencyGraph {
    let files = modules
        .into_iter()
        .map(|(path, contract)| (path.to_owned(), canonical(contract)))
        .collect::<BTreeMap<_, _>>();
    let compilation = compile_contract_coherency_graph(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            EDITION,
            std::iter::empty::<&str>(),
        ),
        None,
    );
    compilation
        .graph()
        .unwrap_or_else(|| panic!("fixture CCG compiles: {:#?}", compilation.violations()))
        .clone()
}

fn observed(edges: &[(&str, &str)]) -> ObservedImplementation {
    let facts = edges
        .iter()
        .enumerate()
        .flat_map(|(index, (source, target))| {
            [1_u32, 2].map(|offset| {
                let evidence = ObservationProvenance::new(
                    format!("mods/{}/code/source.rs", source.to_ascii_lowercase()),
                    *source,
                    format!("crate::surface_{index}_{offset}"),
                    SourceLocation::new(usize_to_u32(index) + offset, 5),
                    Some((*target).into()),
                );
                ImplementationObservation::governed(
                    *source,
                    evidence.source_path().to_owned(),
                    *target,
                    Conditionality::Unconditional,
                    evidence,
                )
            })
        })
        .collect();
    ObservedImplementation::from_facts(
        "sha256:diagnostic-fixture",
        "fixture-rust",
        "1.0.0",
        facts,
        Vec::new(),
    )
}

fn usize_to_u32(value: usize) -> u32 {
    u32::try_from(value).expect("small fixture index")
}

fn kinds(
    result: &fortress_core::architecture_diagnostics::ArchitectureDiagnostics,
) -> Vec<(ArchitectureDiagnosticKind, String)> {
    result
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.kind(), diagnostic.primary_module().into()))
        .collect()
}

fn derive(
    ccg: &ContractCoherencyGraph,
    observed: &ObservedImplementation,
) -> fortress_core::architecture_diagnostics::ArchitectureDiagnostics {
    let realization = reconcile_implementation(ccg, observed, EDITION).expect("reconciles");
    derive_architecture_diagnostics(ccg, observed, &realization).expect("diagnostics derive")
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R04-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R04
#[test]
fn profiles_lca_and_testing_topology_are_recursive_and_distinct() {
    let root = module("PF-FIXTURE", "Fixture", true);
    let mut engine = module("AF-ENGINE-0001", "Engine", false);
    provide(&mut engine, "CAP-ENGINE", "public");
    feature(
        &mut engine,
        "AF-ENGINE-0001",
        "AF-ENGINE-0001-R01",
        "T-AF-ENGINE-0001-R01-001",
    );
    let mut provider = module("AF-PROVIDER-0001", "Provider", false);
    provide(&mut provider, "CAP-PROVIDER", "project");
    require(&mut engine, "AF-PROVIDER-0001", "CAP-PROVIDER");
    let mut testing = module("TEST-ENGINE-0001", "Engine Testing", false);
    verifies(&mut testing, "AF-ENGINE-0001", "AF-ENGINE-0001");
    require(&mut testing, "AF-PROVIDER-0001", "CAP-PROVIDER");
    let ccg = compile([
        ("contract.json", root),
        ("mods/engine/contract.json", engine),
        ("mods/engine/mods/provider/contract.json", provider),
        ("mods/engine/mods/testing/contract.json", testing),
    ]);
    let result = derive(&ccg, &observed(&[("AF-ENGINE-0001", "AF-PROVIDER-0001")]));

    assert_eq!(result.profiles().len(), 3);
    assert_eq!(result.testing_modules(), ["TEST-ENGINE-0001"]);
    assert!(result.profiles().get("TEST-ENGINE-0001").is_none());
    let provider_profile = &result.profiles()["AF-PROVIDER-0001"];
    assert_eq!(
        provider_profile.declared_production_consumers(),
        ["AF-ENGINE-0001"]
    );
    assert_eq!(
        provider_profile.observed_production_consumers(),
        ["AF-ENGINE-0001"]
    );
    assert_eq!(
        provider_profile.consumer_lowest_common_ancestor(),
        Some("AF-ENGINE-0001")
    );
    assert_eq!(provider_profile.direct_consumer_count(), 1);
    assert!(result.diagnostics().is_empty());
    assert_eq!(
        lowest_common_module_ancestor(&ccg, ["AF-PROVIDER-0001", "TEST-ENGINE-0001"]).as_deref(),
        Some("AF-ENGINE-0001")
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R04-002`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R04
#[test]
fn cross_scope_provider_collapses_consumers_and_preserves_lca_evidence() {
    let root = module("PF-FIXTURE", "Fixture", true);
    let scope_a = module("AF-SCOPE-A-0001", "Scope A", false);
    let scope_b = module("AF-SCOPE-B-0001", "Scope B", false);
    let mut provider = module("AF-PROVIDER-0001", "Provider", false);
    provide(&mut provider, "CAP-PROVIDER", "project");
    let mut one = module("AF-CONSUMER-ONE-0001", "Consumer One", false);
    require(&mut one, "AF-PROVIDER-0001", "CAP-PROVIDER");
    let mut two = module("AF-CONSUMER-TWO-0001", "Consumer Two", false);
    require(&mut two, "AF-PROVIDER-0001", "CAP-PROVIDER");
    let ccg = compile([
        ("contract.json", root),
        ("mods/scope_a/contract.json", scope_a),
        ("mods/scope_a/mods/provider/contract.json", provider),
        ("mods/scope_b/contract.json", scope_b),
        ("mods/scope_b/mods/consumer_one/contract.json", one),
        ("mods/scope_b/mods/consumer_two/contract.json", two),
    ]);
    let result = derive(
        &ccg,
        &observed(&[
            ("AF-CONSUMER-ONE-0001", "AF-PROVIDER-0001"),
            ("AF-CONSUMER-TWO-0001", "AF-PROVIDER-0001"),
        ]),
    );
    let diagnostic = result
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.kind() == ArchitectureDiagnosticKind::CrossScopeProvider)
        .expect("one cross-scope provider diagnostic");

    assert_eq!(diagnostic.primary_module(), "AF-PROVIDER-0001");
    assert_eq!(diagnostic.candidate_structural_scope(), Some("PF-FIXTURE"));
    assert_eq!(diagnostic.declared_evidence().len(), 2);
    assert_eq!(diagnostic.observed_evidence().len(), 4);
    assert_eq!(
        kinds(&result)
            .into_iter()
            .filter(|(kind, _)| *kind == ArchitectureDiagnosticKind::CrossScopeProvider)
            .count(),
        1
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R04-003`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R04
#[test]
fn narrower_and_isolated_diagnostics_respect_visibility_ancestry_and_testing() {
    let mut root = module("PF-FIXTURE", "Fixture", true);
    provide(&mut root, "CAP-ROOT", "public");
    let scope = module("AF-SCOPE-0001", "Scope", false);
    let mut consumer_one = module("AF-CONSUMER-ONE-0001", "Consumer One", false);
    let mut consumer_two = module("AF-CONSUMER-TWO-0001", "Consumer Two", false);
    let mut narrow = module("AF-NARROW-0001", "Narrow", false);
    provide(&mut narrow, "CAP-NARROW", "project");
    require(&mut consumer_one, "AF-NARROW-0001", "CAP-NARROW");
    require(&mut consumer_two, "AF-NARROW-0001", "CAP-NARROW");
    let mut public = module("AF-PUBLIC-0001", "Public", false);
    provide(&mut public, "CAP-PUBLIC", "public");
    require(&mut consumer_one, "AF-PUBLIC-0001", "CAP-PUBLIC");
    let mut public_isolated = module("AF-PUBLIC-ISOLATED-0001", "Public Isolated", false);
    provide(&mut public_isolated, "CAP-PUBLIC-ISOLATED", "public");
    let mut isolated = module("AF-ISOLATED-0001", "Isolated", false);
    provide(&mut isolated, "CAP-ISOLATED", "project");
    let mut testing_parent = module("AF-TESTED-0001", "Tested", false);
    feature(
        &mut testing_parent,
        "AF-TESTED-0001",
        "AF-TESTED-0001-R01",
        "T-AF-TESTED-0001-R01-001",
    );
    let mut testing = module("TEST-TESTED-0001", "Tested Testing", false);
    verifies(&mut testing, "AF-TESTED-0001", "AF-TESTED-0001");
    require(&mut testing, "AF-ISOLATED-0001", "CAP-ISOLATED");
    require(&mut testing, "AF-NARROW-0001", "CAP-NARROW");
    let mut ancestor = module("AF-ANCESTOR-0001", "Ancestor", false);
    provide(&mut ancestor, "CAP-ANCESTOR", "project");
    let mut descendant = module("AF-DESCENDANT-0001", "Descendant", false);
    require(&mut descendant, "AF-ANCESTOR-0001", "CAP-ANCESTOR");
    let ccg = compile([
        ("contract.json", root),
        ("mods/scope/contract.json", scope),
        ("mods/scope/mods/consumer_one/contract.json", consumer_one),
        ("mods/scope/mods/consumer_two/contract.json", consumer_two),
        ("mods/narrow/contract.json", narrow),
        ("mods/public/contract.json", public),
        ("mods/public_isolated/contract.json", public_isolated),
        ("mods/isolated/contract.json", isolated),
        ("mods/tested/contract.json", testing_parent),
        ("mods/tested/mods/testing/contract.json", testing),
        ("mods/ancestor/contract.json", ancestor),
        ("mods/ancestor/mods/descendant/contract.json", descendant),
    ]);
    let result = derive(&ccg, &observed(&[]));
    let diagnostic_kinds = kinds(&result);

    assert!(diagnostic_kinds.contains(&(
        ArchitectureDiagnosticKind::NarrowerConsumerScope,
        "AF-NARROW-0001".into()
    )));
    assert!(diagnostic_kinds.contains(&(
        ArchitectureDiagnosticKind::IsolatedInternalProvider,
        "AF-ISOLATED-0001".into()
    )));
    assert!(
        !diagnostic_kinds
            .iter()
            .any(|(_, module)| module == "AF-PUBLIC-0001" || module == "AF-PUBLIC-ISOLATED-0001")
    );
    assert!(!diagnostic_kinds.iter().any(|(kind, module)| {
        *kind == ArchitectureDiagnosticKind::NarrowerConsumerScope && module == "AF-ANCESTOR-0001"
    }));
    assert_eq!(
        result.profiles()["AF-ISOLATED-0001"].direct_consumer_count(),
        0
    );
    assert_eq!(
        result.profiles()["AF-NARROW-0001"].consumer_lowest_common_ancestor(),
        Some("AF-SCOPE-0001")
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R04-004`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R04
#[test]
fn fragmented_authorized_surface_is_diagnostic_while_unauthorized_access_is_finding() {
    let root = module("PF-FIXTURE", "Fixture", true);
    let mut foreign = module("AF-FOREIGN-0001", "Foreign", false);
    provide(&mut foreign, "CAP-FOREIGN", "project");
    let mut left = module("AF-LEFT-0001", "Left", false);
    provide(&mut left, "CAP-LEFT", "project");
    let mut right = module("AF-RIGHT-0001", "Right", false);
    provide(&mut right, "CAP-RIGHT", "project");
    let mut consumer = module("AF-CONSUMER-0001", "Consumer", false);
    require(&mut consumer, "AF-LEFT-0001", "CAP-LEFT");
    require(&mut consumer, "AF-RIGHT-0001", "CAP-RIGHT");
    let mut one = module("AF-ONE-0001", "One", false);
    require(&mut one, "AF-LEFT-0001", "CAP-LEFT");
    let empty_foreign = module("AF-EMPTY-FOREIGN-0001", "Empty Foreign", false);
    let mut empty_left = module("AF-EMPTY-LEFT-0001", "Empty Left", false);
    provide(&mut empty_left, "CAP-EMPTY-LEFT", "project");
    let mut empty_right = module("AF-EMPTY-RIGHT-0001", "Empty Right", false);
    provide(&mut empty_right, "CAP-EMPTY-RIGHT", "project");
    let mut empty_consumer = module("AF-EMPTY-CONSUMER-0001", "Empty Consumer", false);
    require(&mut empty_consumer, "AF-EMPTY-LEFT-0001", "CAP-EMPTY-LEFT");
    require(
        &mut empty_consumer,
        "AF-EMPTY-RIGHT-0001",
        "CAP-EMPTY-RIGHT",
    );
    let ccg = compile([
        ("contract.json", root),
        ("mods/foreign/contract.json", foreign),
        ("mods/foreign/mods/left/contract.json", left),
        ("mods/foreign/mods/right/contract.json", right),
        ("mods/consumer/contract.json", consumer),
        ("mods/one/contract.json", one),
        ("mods/empty_foreign/contract.json", empty_foreign),
        (
            "mods/empty_foreign/mods/empty_left/contract.json",
            empty_left,
        ),
        (
            "mods/empty_foreign/mods/empty_right/contract.json",
            empty_right,
        ),
        ("mods/empty_consumer/contract.json", empty_consumer),
    ]);
    let authorized = observed(&[
        ("AF-CONSUMER-0001", "AF-LEFT-0001"),
        ("AF-CONSUMER-0001", "AF-RIGHT-0001"),
    ]);
    let realization = reconcile_implementation(&ccg, &authorized, EDITION).expect("reconciles");
    assert!(realization.findings().is_empty());
    let result = derive_architecture_diagnostics(&ccg, &authorized, &realization)
        .expect("diagnostics derive");
    assert!(kinds(&result).contains(&(
        ArchitectureDiagnosticKind::FragmentedForeignSurface,
        "AF-CONSUMER-0001".into()
    )));
    assert!(!kinds(&result).iter().any(|(kind, module)| {
        *kind == ArchitectureDiagnosticKind::FragmentedForeignSurface
            && (module == "AF-ONE-0001" || module == "AF-EMPTY-CONSUMER-0001")
    }));

    let unauthorized = observed(&[("AF-ONE-0001", "AF-RIGHT-0001")]);
    let unauthorized_realization =
        reconcile_implementation(&ccg, &unauthorized, EDITION).expect("finding normalizes");
    assert_eq!(unauthorized_realization.findings().len(), 1);
    assert_eq!(
        unauthorized_realization.findings()[0].rule_id(),
        "ARCH-REALIZATION-001"
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R04-005`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R04
#[test]
fn diagnostics_are_content_addressed_deterministic_and_epistemically_limited() {
    let root = module("PF-FIXTURE", "Fixture", true);
    let mut isolated = module("AF-ISOLATED-0001", "Isolated", false);
    provide(&mut isolated, "CAP-ISOLATED", "project");
    let mut declared = module("AF-DECLARED-0001", "Declared", false);
    provide(&mut declared, "CAP-DECLARED", "project");
    let mut consumer = module("AF-CONSUMER-0001", "Consumer", false);
    require(&mut consumer, "AF-DECLARED-0001", "CAP-DECLARED");
    let ccg = compile([
        ("contract.json", root),
        ("mods/isolated/contract.json", isolated),
        ("mods/declared/contract.json", declared),
        ("mods/consumer/contract.json", consumer),
    ]);
    let facts = observed(&[]);
    let first = derive(&ccg, &facts);
    let second = derive(&ccg, &facts);

    assert_eq!(first, second);
    assert!(
        first
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.fingerprint().starts_with("sha256:"))
    );
    let serialized = serde_json::to_vec(first.diagnostics()).expect("diagnostics serialize");
    assert_eq!(
        serialized,
        serde_json::to_vec(second.diagnostics()).expect("diagnostics repeat")
    );
    let text = String::from_utf8(serialized)
        .expect("JSON UTF-8")
        .to_ascii_lowercase();
    assert!(!text.contains("stale_dependency"));
    assert!(!text.contains("unused_capability"));
    assert!(
        first
            .unsupported_analysis()
            .contains(&"capability_to_symbol_realization".to_owned())
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R04-006`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R04
#[test]
fn live_fortress_diagnostics_execute_repeatably_without_affecting_audit_outcome() {
    let root = repository_root();
    let ccg = compile_repository_ccg(&root).expect("live CCG compiles");
    let intent_only = observed(&[]);
    let profiles = derive(&ccg, &intent_only);
    let first = audit_repository(&root).expect("live audit executes");
    let second = audit_repository(&root).expect("live audit repeats");
    println!("live architecture diagnostics: {:#?}", first.diagnostics());

    assert_eq!(profiles.profiles().len(), 22);
    assert_eq!(profiles.testing_modules().len(), 20);
    assert_eq!(first.is_success(), second.is_success());
    assert_eq!(first.diagnostics(), second.diagnostics());
    assert_eq!(
        first.to_json_pretty().expect("JSON"),
        second.to_json_pretty().expect("JSON")
    );
    assert!(
        first
            .unsupported_analysis()
            .contains(&"natural_language_architecture_semantics".to_owned())
    );
}
