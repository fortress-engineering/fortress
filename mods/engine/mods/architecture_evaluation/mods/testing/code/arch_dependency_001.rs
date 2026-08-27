//! Implementation exercise of specification-authored `ARCH-DEPENDENCY-001` fixtures.
//!
//! These tests evaluate declared edges only. They do not observe source imports
//! or create certification evidence.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::architecture::{ArchitectureManifest, ComponentDeclaration};
use serde::Deserialize;

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

fn load(relative_path: &str) -> ArchitectureManifest {
    let wire: ArchitectureWire =
        serde_json::from_str(&read_fixture(relative_path)).expect("fixture must parse");
    ArchitectureManifest::from_components(
        wire.components
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
    )
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mods/architecture_evaluation/mods/testing/data")
}

fn read_fixture(relative_path: &str) -> String {
    let path = fixture_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()))
}

/// `T-ARCH-DEPENDENCY-001-R01-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R02
#[test]
fn valid_declared_graph_passes() {
    let architecture = load("dependency_valid.json");
    assert!(
        architecture
            .evaluate_acyclic_dependencies("1.0.0-draft.1")
            .expect("finding normalization must succeed")
            .is_none()
    );
}

/// `T-ARCH-DEPENDENCY-001-R01-002`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R02
#[test]
fn cycle_produces_the_expected_normalized_finding() {
    let architecture = load("dependency_invalid.json");
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
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R02
#[test]
fn one_component_no_edge_boundary_passes() {
    let architecture = load("dependency_boundary.json");
    assert!(
        architecture
            .evaluate_acyclic_dependencies("1.0.0-draft.1")
            .expect("finding normalization must succeed")
            .is_none()
    );
}
