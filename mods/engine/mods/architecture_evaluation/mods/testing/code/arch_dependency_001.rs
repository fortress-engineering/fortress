//! Implementation exercise of specification-authored `ARCH-DEPENDENCY-001` fixtures.
//!
//! These tests evaluate declared edges only. They do not observe source imports
//! or create certification evidence.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::architecture::ArchitectureManifest;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mods/architecture_evaluation/mods/testing/data")
}

fn read_fixture(relative_path: &str) -> String {
    let path = fixture_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()))
}

/// `T-ARCH-DEPENDENCY-001-R01-001`
#[test]
fn valid_declared_graph_passes() {
    let architecture = ArchitectureManifest::from_json_str(&read_fixture("dependency_valid.json"))
        .expect("positive architecture fixture must load");
    assert!(
        architecture
            .evaluate_acyclic_dependencies("1.0.0-draft.1")
            .expect("finding normalization must succeed")
            .is_none()
    );
}

/// `T-ARCH-DEPENDENCY-001-R01-002`
#[test]
fn cycle_produces_the_expected_normalized_finding() {
    let architecture =
        ArchitectureManifest::from_json_str(&read_fixture("dependency_invalid.json"))
            .expect("negative architecture fixture must be structurally valid");
    let actual = architecture
        .evaluate_acyclic_dependencies("1.0.0-draft.1")
        .expect("finding normalization must succeed")
        .expect("negative architecture fixture must produce a finding");
    let actual = serde_json::to_value(actual).expect("finding must serialize");
    let expected: serde_json::Value =
        serde_json::from_str(&read_fixture("dependency_expected.json"))
            .expect("expected finding must be valid JSON");
    assert_eq!(actual, expected);
}

/// `T-ARCH-DEPENDENCY-001-R01-003`
#[test]
fn one_component_no_edge_boundary_passes() {
    let architecture =
        ArchitectureManifest::from_json_str(&read_fixture("dependency_boundary.json"))
            .expect("boundary architecture fixture must load");
    assert!(
        architecture
            .evaluate_acyclic_dependencies("1.0.0-draft.1")
            .expect("finding normalization must succeed")
            .is_none()
    );
}
