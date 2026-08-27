//! Implementation exercise of specification-authored `ARCH-OWNERSHIP-001` fixtures.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::architecture::ArchitectureManifest;
use fortress_core::ownership::evaluate_file_ownership;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    architecture: serde_json::Value,
    observed_paths: Vec<String>,
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("conformance/rules/ARCH-OWNERSHIP-001")
}

fn read(relative_path: &str) -> String {
    let path = fixture_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()))
}

fn load(relative_path: &str) -> (ArchitectureManifest, Vec<String>) {
    let fixture: Fixture =
        serde_json::from_str(&read(relative_path)).expect("fixture is valid JSON");
    let architecture = ArchitectureManifest::from_json_str(&fixture.architecture.to_string())
        .expect("fixture architecture is valid");
    (architecture, fixture.observed_paths)
}

/// `T-ARCH-OWNERSHIP-001-R01-001`
#[test]
fn complete_ownership_and_explicit_repository_metadata_pass() {
    let (architecture, paths) = load("valid/input.json");
    let result = evaluate_file_ownership(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(result.findings().is_empty());
    assert_eq!(result.assignments().len(), 2);
    assert_eq!(result.assignments()[0].path(), "Cargo.toml");
    assert_eq!(result.assignments()[0].owner(), "AF-CORE-0001");
}

/// `T-ARCH-OWNERSHIP-001-R01-002`
#[test]
fn orphan_overlap_and_missing_declarations_match_expected_findings() {
    let (architecture, paths) = load("invalid/input.json");
    let result = evaluate_file_ownership(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    let actual = serde_json::to_value(result.findings()).expect("findings serialize");
    let expected: serde_json::Value =
        serde_json::from_str(&read("expected/invalid.json")).expect("expected JSON is valid");
    assert_eq!(actual, expected);
}

/// `T-ARCH-OWNERSHIP-001-R01-003`
#[test]
fn one_exact_path_is_the_minimum_boundary() {
    let (architecture, paths) = load("boundary/input.json");
    let result = evaluate_file_ownership(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(result.findings().is_empty());
    assert_eq!(result.assignments().len(), 1);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R05-001`
#[test]
fn fortress_self_inventory_has_exactly_one_declared_owner() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = fs::read_to_string(root.join(".fortress/architecture/architecture.json"))
        .expect("self architecture is readable");
    let architecture = ArchitectureManifest::from_json_str(&source).expect("architecture loads");
    let policy = fortress_core::observation::ObservationPolicy::new([".git", "target"])
        .expect("self exclusions are canonical");
    let observation = fortress_core::observation::observe_repository(&root, &policy)
        .expect("self repository observes");
    let paths: Vec<String> = observation
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect();
    let result = evaluate_file_ownership(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(
        result.findings().is_empty(),
        "self ownership findings: {:#?}",
        result.findings()
    );
    assert_eq!(result.assignments().len(), paths.len());
}
