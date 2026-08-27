//! Implementation exercise of specification-authored `REPO-PLACEMENT-001` fixtures.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::architecture::ArchitectureManifest;
use fortress_core::placement::evaluate_repository_placement;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    architecture: serde_json::Value,
    observed_paths: Vec<String>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("conformance/rules/REPO-PLACEMENT-001")
}

fn read(relative: &str) -> String {
    let path = root().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn load(relative: &str) -> (ArchitectureManifest, Vec<String>) {
    let fixture: Fixture = serde_json::from_str(&read(relative)).expect("fixture JSON loads");
    let architecture = ArchitectureManifest::from_json_str(&fixture.architecture.to_string())
        .expect("architecture loads");
    (architecture, fixture.observed_paths)
}

/// `T-REPO-PLACEMENT-001-R01-001`
#[test]
fn declared_structure_and_ecosystem_metadata_pass() {
    let (architecture, paths) = load("valid/input.json");
    let findings = evaluate_repository_placement(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(findings.is_empty());
}

/// `T-REPO-PLACEMENT-001-R01-002`
#[test]
fn invalid_structure_matches_expected_findings() {
    let (architecture, paths) = load("invalid/input.json");
    let findings = evaluate_repository_placement(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    let actual = serde_json::to_value(findings).expect("findings serialize");
    let expected: serde_json::Value =
        serde_json::from_str(&read("expected/invalid.json")).expect("expected JSON loads");
    assert_eq!(actual, expected);
}

/// `T-REPO-PLACEMENT-001-R01-003`
#[test]
fn one_owned_file_is_the_minimum_declared_boundary() {
    let (architecture, paths) = load("boundary/input.json");
    let findings = evaluate_repository_placement(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(findings.is_empty());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R07-001`
#[test]
fn fortress_self_inventory_conforms_to_declared_structure() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let architecture_source =
        fs::read_to_string(repository.join(".fortress/architecture/architecture.json"))
            .expect("self architecture is readable");
    let architecture =
        ArchitectureManifest::from_json_str(&architecture_source).expect("architecture loads");
    let policy = fortress_core::observation::ObservationPolicy::new([".git", "target"])
        .expect("policy loads");
    let observation = fortress_core::observation::observe_repository(&repository, &policy)
        .expect("self repository observes");
    let paths: Vec<String> = observation
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect();
    let findings = evaluate_repository_placement(&architecture, &paths, "1.0.0-draft.1")
        .expect("evaluation completes");
    assert!(findings.is_empty(), "self placement: {findings:#?}");
}
