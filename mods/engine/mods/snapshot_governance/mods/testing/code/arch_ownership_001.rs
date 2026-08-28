//! Implementation exercise of specification-authored `ARCH-OWNERSHIP-001` fixtures.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::architecture::{ArchitectureManifest, ComponentDeclaration};
use fortress_core::contract_coherency::{
    CcgObservedTestFact, ContractStandardIndex, compile_contract_coherency_graph,
};
use fortress_core::ownership::evaluate_file_ownership;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    ownership: ArchitectureWire,
    observed_paths: Vec<String>,
}

#[derive(Deserialize)]
struct ArchitectureWire {
    components: Vec<ComponentWire>,
}

#[derive(Deserialize)]
struct ComponentWire {
    id: String,
    title: String,
    paths: Vec<String>,
    depends_on: Vec<String>,
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mods/snapshot_governance/mods/testing/data")
}

fn read(relative_path: &str) -> String {
    let path = fixture_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()))
}

fn load(relative_path: &str) -> (ArchitectureManifest, Vec<String>) {
    let fixture: Fixture =
        serde_json::from_str(&read(relative_path)).expect("fixture is valid JSON");
    let architecture = ArchitectureManifest::from_components(
        fixture
            .ownership
            .components
            .into_iter()
            .map(|component| {
                ComponentDeclaration::new(
                    component.id,
                    component.title,
                    component.paths,
                    component.depends_on,
                )
            })
            .collect(),
    );
    (architecture, fixture.observed_paths)
}

/// `T-ARCH-OWNERSHIP-001-R01-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R05
#[test]
fn complete_ownership_passes() {
    let (architecture, paths) = load("ownership_valid.json");
    let result = evaluate_file_ownership(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(result.findings().is_empty());
    assert_eq!(result.assignments().len(), 2);
    assert_eq!(result.assignments()[0].path(), "Cargo.toml");
    assert_eq!(result.assignments()[0].owner(), "AF-CORE-0001");
}

/// `T-ARCH-OWNERSHIP-001-R01-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R05
#[test]
fn orphan_overlap_and_missing_declarations_match_expected_findings() {
    let (architecture, paths) = load("ownership_invalid.json");
    let result = evaluate_file_ownership(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    let actual = serde_json::to_value(result.findings()).expect("findings serialize");
    let expected: serde_json::Value =
        serde_json::from_str(&read("ownership_expected.json")).expect("expected JSON is valid");
    assert_eq!(actual, expected);
}

/// `T-ARCH-OWNERSHIP-001-R01-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R05
#[test]
fn one_exact_path_is_the_minimum_boundary() {
    let (architecture, paths) = load("ownership_boundary.json");
    let result = evaluate_file_ownership(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(result.findings().is_empty());
    assert_eq!(result.assignments().len(), 1);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R05-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R05
#[test]
fn fortress_self_inventory_has_exactly_one_declared_owner() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let policy = fortress_core::observation::ObservationPolicy::new([".git", "target"])
        .expect("self exclusions are canonical");
    let observation = fortress_core::observation::observe_repository(&root, &policy)
        .expect("self repository observes");
    let paths: Vec<String> = observation
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect();
    let files: BTreeMap<String, Vec<u8>> = observation
        .files()
        .iter()
        .map(|file| {
            (
                file.path().to_owned(),
                fs::read(root.join(file.path())).expect("observed bytes read"),
            )
        })
        .collect();
    let mut tests = Vec::new();
    for (path, bytes) in &files {
        if Path::new(path)
            .extension()
            .is_some_and(|extension| extension == "rs")
        {
            let source = std::str::from_utf8(bytes).expect("Rust source is UTF-8");
            tests.extend(
                fortress_core::rust_test_analyzer::analyze_rust_source(path, source)
                    .expect("Rust test facts analyze"),
            );
        }
    }
    let test_facts: Vec<CcgObservedTestFact> =
        tests.iter().map(CcgObservedTestFact::from).collect();
    let resolution = compile_contract_coherency_graph(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            [
                "ARCH-DEPENDENCY-001",
                "ARCH-OWNERSHIP-001",
                "ARCH-REALIZATION-001",
                "BEHAVIOR-FLOW-001",
                "CONTRACT-COHERENCY-001",
                "PROGRAM-DOMAIN-001",
                "REPO-DOCS-001",
                "REPO-MODULE-001",
                "STD-ID-001",
                "TEST-BOUNDARY-001",
                "TEST-TRACEABILITY-001",
            ],
        ),
        Some(&test_facts),
    );
    let resolved = resolution
        .graph()
        .unwrap_or_else(|| panic!("self contracts resolve: {:#?}", resolution.violations()));
    let architecture = ArchitectureManifest::from_ccg(resolved, &paths);
    let result = evaluate_file_ownership(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(
        result.findings().is_empty(),
        "self ownership findings: {:#?}",
        result.findings()
    );
    assert_eq!(result.assignments().len(), paths.len());
}
