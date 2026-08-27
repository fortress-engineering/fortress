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
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
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
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn registered_schemas_are_unique_json_schema_documents() {
    let manifest = read_json("mods/engine/mods/standard_registry/data/schema_manifest.json");
    let paths = manifest["schemas"]
        .as_array()
        .expect("schema manifest must contain a schemas array");
    let mut identities = HashSet::with_capacity(paths.len());

    assert_eq!(paths.len(), 14);
    for path in paths {
        let relative = path.as_str().expect("schema path must be a string");
        let schema = read_json(relative);
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
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn draft_manifest_agrees_with_implemented_registry() {
    let manifest = read_json("mods/engine/mods/standard_registry/data/standard_manifest.json");
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
        let rule = read_json(relative_path);
        let id = rule["id"].as_str().expect("rule must have a string ID");
        assert!(
            registry.find(id).is_some(),
            "declared rule `{id}` is not implemented"
        );
    }
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-003`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn standard_instance_schemas_allow_declared_schema_references() {
    let rule_schema = read_json("mods/engine/mods/standard_registry/data/rule_schema_v1.json");
    assert!(rule_schema["properties"]["$schema"].is_object());
    let manifest_schema =
        read_json("mods/engine/mods/standard_registry/data/standard_manifest_schema_v1.json");
    assert!(manifest_schema["properties"]["$schema"].is_object());

    let manifest = read_json("mods/engine/mods/standard_registry/data/standard_manifest.json");
    assert!(manifest["$schema"].is_string());
    for relative_path in manifest["rules"]
        .as_array()
        .expect("standard manifest must contain rules")
    {
        let relative_path = relative_path
            .as_str()
            .expect("standard rule path must be a string");
        let rule = read_json(relative_path);
        assert!(rule["$schema"].is_string());
    }
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-004`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn local_schema_references_resolve_from_their_documents() {
    fn collect_json_documents(directory: &Path, documents: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| {
                panic!(
                    "failed to read entry under {}: {error}",
                    directory.display()
                )
            });
            let path = entry.path();
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("failed to inspect {}: {error}", path.display()));
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                let name = entry.file_name();
                if name != ".git" && name != "target" {
                    collect_json_documents(&path, documents);
                }
            } else if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                documents.push(path);
            }
        }
    }

    let root = repository_root();
    let mut documents = Vec::new();
    collect_json_documents(&root, &mut documents);
    documents.sort_unstable();

    for path in documents {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let document: Value = serde_json::from_str(&source)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
        let Some(reference) = document["$schema"].as_str() else {
            continue;
        };
        if reference.starts_with("https://") || reference.starts_with("urn:") {
            continue;
        }

        let resolved = path
            .parent()
            .expect("JSON document path must have a parent")
            .join(reference);
        assert!(
            resolved.is_file(),
            "local schema reference `{reference}` from {} does not resolve",
            path.display()
        );
    }
}
