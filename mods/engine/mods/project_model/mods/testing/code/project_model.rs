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

/// `T-LOGICAL-MODULE-CONFIG-001`
/// Fortress classification: infrastructure
#[test]
fn logical_contract_and_binding_authority_is_canonical() {
    let source = r#"{
      "$schema": "urn:fortress:schema:v3:project-configuration",
      "schema_version": 3,
      "observation_exclusions": [".git"],
      "logical_modules": [{
        "module": "AF-PAYMENTS-0001",
        "contract": "data/logical_modules/payments/contract.json",
        "parent": "PF-PROJECT",
        "bindings": [
          {"kind": "directory", "path": "crates/api/src/payments"},
          {"kind": "file", "path": "crates/core/src/ledger/payment.rs"}
        ]
      }]
    }"#;
    let project = ProjectConfiguration::from_json_str(source).expect("logical authority validates");
    let logical = &project.logical_modules()[0];
    assert_eq!(logical.module(), "AF-PAYMENTS-0001");
    assert_eq!(logical.parent(), "PF-PROJECT");
    assert_eq!(logical.bindings().len(), 2);
}

/// `T-LOGICAL-MODULE-CONFIG-INVALID-001`
/// Fortress classification: infrastructure
#[test]
fn absolute_traversal_and_windows_binding_paths_are_rejected() {
    for path in ["C:/repo/src", "../src", "src\\payments"] {
        let source = format!(
            "{{\"$schema\":\"urn:fortress:schema:v3:project-configuration\",\"schema_version\":3,\"observation_exclusions\":[\".git\"],\"logical_modules\":[{{\"module\":\"AF-PAYMENTS-0001\",\"contract\":\"data/logical_modules/payments/contract.json\",\"parent\":\"PF-PROJECT\",\"bindings\":[{{\"kind\":\"directory\",\"path\":{}}}]}}]}}",
            serde_json::to_string(path).unwrap()
        );
        assert!(matches!(
            ProjectConfiguration::from_json_str(&source),
            Err(ProjectConfigurationLoadError::Model(
                ProjectConfigurationModelError::InvalidBindingPath(_)
            ))
        ));
    }
}

/// `T-LOGICAL-MODULE-CONFIG-CONFLICT-001`
/// Fortress classification: infrastructure
#[test]
fn equal_source_binding_authority_is_rejected_without_manifest_order() {
    let source = r#"{
      "$schema": "urn:fortress:schema:v3:project-configuration",
      "schema_version": 3,
      "observation_exclusions": [".git"],
      "logical_modules": [
        {"module": "AF-ALPHA-0001", "contract": "data/logical_modules/alpha/contract.json", "parent": "PF-PROJECT", "bindings": [{"kind": "directory", "path": "src/shared"}]},
        {"module": "AF-BETA-0001", "contract": "data/logical_modules/beta/contract.json", "parent": "PF-PROJECT", "bindings": [{"kind": "directory", "path": "src/shared"}]}
      ]
    }"#;
    assert!(matches!(
        ProjectConfiguration::from_json_str(source),
        Err(ProjectConfigurationLoadError::Model(
            ProjectConfigurationModelError::ConflictingBinding(_)
        ))
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
