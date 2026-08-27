//! Structural validation for versioned schemas and the draft standard bundle.
//!
//! This is a truthful bootstrap check of JSON structure, registered files,
//! dialect identity, unique schema IDs, and registry agreement. It does not
//! claim complete evaluation of the JSON Schema 2020-12 vocabulary.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::standard::StandardRegistry;
use serde_json::Value;

/// Returns the checked-out repository root.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Reads and parses one repository-relative JSON file.
fn read_json(relative_path: &str) -> Value {
    let path = repository_root().join(relative_path);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&source)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-001`
#[test]
fn registered_schemas_are_unique_json_schema_documents() {
    let manifest = read_json("schemas/manifest.json");
    let paths = manifest["schemas"]
        .as_array()
        .expect("schema manifest must contain a schemas array");
    let mut identities = HashSet::with_capacity(paths.len());

    assert_eq!(paths.len(), 11);
    for path in paths {
        let relative = path.as_str().expect("schema path must be a string");
        let schema = read_json(&format!("schemas/{relative}"));
        assert_eq!(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "unexpected JSON Schema dialect for {relative}"
        );
        let identity = schema["$id"]
            .as_str()
            .unwrap_or_else(|| panic!("schema {relative} has no string $id"));
        assert!(
            identities.insert(identity.to_owned()),
            "schema identity `{identity}` is duplicated"
        );
    }
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-002`
#[test]
fn draft_manifest_agrees_with_implemented_registry() {
    let manifest = read_json("standard/drafts/1.0.0/manifest.json");
    let registry = StandardRegistry::draft_1_0();
    assert_eq!(manifest["edition"], registry.edition());
    assert_eq!(manifest["status"], "draft");
    assert!(manifest["release_digest"].is_null());

    let declared_rules = manifest["rules"]
        .as_array()
        .expect("standard manifest must contain rules");
    assert_eq!(declared_rules.len(), registry.rules().len());
    for relative_path in declared_rules {
        let relative_path = relative_path
            .as_str()
            .expect("standard rule path must be a string");
        let rule = read_json(&format!("standard/drafts/1.0.0/{relative_path}"));
        let id = rule["id"].as_str().expect("rule must have a string ID");
        assert!(
            registry.find(id).is_some(),
            "declared rule `{id}` is not implemented"
        );
    }
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-003`
#[test]
fn rule_schema_allows_declared_instance_schema_references() {
    let schema = read_json("schemas/v1/rule.schema.json");
    assert!(schema["properties"]["$schema"].is_object());

    let manifest = read_json("standard/drafts/1.0.0/manifest.json");
    for relative_path in manifest["rules"]
        .as_array()
        .expect("standard manifest must contain rules")
    {
        let relative_path = relative_path
            .as_str()
            .expect("standard rule path must be a string");
        let rule = read_json(&format!("standard/drafts/1.0.0/{relative_path}"));
        assert!(rule["$schema"].is_string());
    }
}

/// `T-AF-PROJECT-MODEL-0001-R03-001`
#[test]
fn general_change_schema_does_not_require_bootstrap_provenance() {
    let schema = read_json("schemas/v1/change.schema.json");
    let required = schema["required"]
        .as_array()
        .expect("change schema required list must be an array");
    assert!(required.iter().any(|value| value == "authority_refs"));
    assert!(!required.iter().any(|value| value == "bootstrap_provenance"));
    assert!(schema["properties"]["bootstrap_provenance"].is_object());
}
