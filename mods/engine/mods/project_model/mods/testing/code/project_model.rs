//! Positive, negative, and boundary implementation evidence for project loading.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::project::{
    ProjectConfiguration, ProjectConfigurationLoadError, ProjectConfigurationModelError,
};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mods/project_model/mods/testing/data")
}

fn load(relative_path: &str) -> Result<ProjectConfiguration, ProjectConfigurationLoadError> {
    let path = fixture_root().join(relative_path);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    ProjectConfiguration::from_json_str(&source)
}

/// `T-AF-PROJECT-MODEL-0001-R02-001`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R01
#[test]
fn valid_declared_project_loads() {
    let project = load("project_valid.json").expect("positive fixture must load");
    assert_eq!(project.observation_exclusions(), [".git", "runtime"]);
}

/// `T-AF-PROJECT-MODEL-0001-R02-002`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R01
#[test]
fn duplicate_exclusion_is_rejected() {
    let error = load("project_invalid.json").expect_err("negative fixture must fail");
    assert!(matches!(
        error,
        ProjectConfigurationLoadError::Model(ProjectConfigurationModelError::DuplicateExclusion(_))
    ));
}

/// `T-AF-PROJECT-MODEL-0001-R02-003`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R01
#[test]
fn parent_traversal_path_is_rejected() {
    let error = load("path_boundary.json").expect_err("boundary fixture must fail");
    assert!(matches!(
        error,
        ProjectConfigurationLoadError::Model(ProjectConfigurationModelError::InvalidExclusion(_))
    ));
}

/// `T-AF-PROJECT-MODEL-0001-R01-001`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R01
#[test]
fn minimal_operational_configuration_is_valid() {
    let source = r#"{
      "$schema": "urn:fortress:schema:v2:project-configuration",
      "schema_version": 2,
      "observation_exclusions": [".git"]
    }"#;
    let configuration =
        ProjectConfiguration::from_json_str(source).expect("configuration validates");
    assert_eq!(configuration.observation_exclusions(), [".git"]);
}

/// `T-AF-PROJECT-MODEL-0001-R01-002`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R01
#[test]
fn invalid_or_duplicate_exclusions_fail() {
    let invalid = r#"{
      "$schema": "urn:fortress:schema:v2:project-configuration",
      "schema_version": 2,
      "observation_exclusions": ["../outside"]
    }"#;
    assert!(matches!(
        ProjectConfiguration::from_json_str(invalid),
        Err(ProjectConfigurationLoadError::Model(_))
    ));
}

/// `T-AF-PROJECT-MODEL-0001-R03-001`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R03
#[test]
fn general_change_schema_does_not_require_bootstrap_provenance() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let source =
        fs::read_to_string(root.join("mods/engine/mods/project_model/data/change_schema_v1.json"))
            .expect("change schema reads");
    let schema: serde_json::Value = serde_json::from_str(&source).expect("change schema parses");
    let required = schema["required"]
        .as_array()
        .expect("change schema required list must be an array");
    assert!(required.iter().any(|value| value == "authority_refs"));
    assert!(!required.iter().any(|value| value == "bootstrap_provenance"));
    assert!(schema["properties"]["bootstrap_provenance"].is_object());
}
