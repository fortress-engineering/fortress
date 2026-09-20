//! Validate exact emitted artifacts after the canonical issuer has produced them.

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::Resource;
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn registered_schemas() -> BTreeMap<String, Value> {
    let root = root();
    let manifest: Value = serde_json::from_slice(
        &fs::read(root.join("engine/standard_registry/_data/schema_manifest.json"))
            .expect("schema manifest"),
    )
    .expect("schema manifest JSON");
    let mut schemas = BTreeMap::new();
    for path in manifest["schemas"].as_array().expect("schema paths") {
        let path = path.as_str().expect("schema path");
        let schema: Value =
            serde_json::from_slice(&fs::read(root.join(path)).expect("schema file"))
                .expect("schema JSON");
        let id = schema["$id"].as_str().expect("schema ID").to_owned();
        assert!(schemas.insert(id, schema).is_none(), "duplicate schema ID");
    }
    schemas
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-013`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn all_current_writers_validate_against_advertised_schema() {
    // The full artifact manifest exists only after certification has emitted
    // the exact candidate. The issuer invokes this target again at that point
    // and records a distinct required gate. Ordinary workspace tests exercise
    // schema registry and model fixtures before artifact generation.
    let Some(manifest_path) = env::var_os("FORTRESS_SCHEMA_ARTIFACT_MANIFEST") else {
        return;
    };
    let artifact_paths: BTreeMap<String, String> =
        serde_json::from_slice(&fs::read(manifest_path).expect("exact emitted artifact manifest"))
            .expect("artifact manifest JSON");
    assert_eq!(
        artifact_paths.len(),
        14,
        "all current issuer artifacts must be present"
    );
    let schemas = registered_schemas();
    let mut advertised = HashSet::new();
    for (logical_path, physical_path) in artifact_paths {
        let source = fs::read(&physical_path).unwrap_or_else(|error| {
            panic!("cannot read {logical_path} at {physical_path}: {error}")
        });
        let instance: Value = serde_json::from_slice(&source)
            .unwrap_or_else(|error| panic!("invalid JSON at {logical_path}: {error}"));
        let id = instance["$schema"]
            .as_str()
            .unwrap_or_else(|| panic!("missing advertised schema at {logical_path}"));
        let schema = schemas
            .get(id)
            .unwrap_or_else(|| panic!("unregistered advertised schema {id} at {logical_path}"));
        let mut options = jsonschema::draft202012::options();
        for (resource_id, resource_schema) in &schemas {
            let resource = Resource::from_contents(resource_schema.clone())
                .unwrap_or_else(|error| panic!("invalid schema resource {resource_id}: {error}"));
            options = options.with_resource(resource_id.clone(), resource);
        }
        let validator = options
            .build(schema)
            .unwrap_or_else(|error| panic!("cannot compile {id}: {error}"));
        if let Err(error) = validator.validate(&instance) {
            panic!("{logical_path} does not validate against {id}: {error}");
        }
        advertised.insert(id.to_owned());
        println!(
            "validated {logical_path} under {id} ({} bytes)",
            source.len()
        );
    }
    assert_eq!(
        advertised.len(),
        14,
        "each emitted artifact has one distinct schema"
    );
}
