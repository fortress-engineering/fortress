//! Structural validation for versioned schemas and the draft standard bundle.
//!
//! This validates the live manifest and registered JSON Schema 2020-12 files.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::proof::{EvidenceReference, ProofExpression, ProofGraph, ProofOperator};
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
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn registered_schemas_are_unique_json_schema_documents() {
    let manifest = read_json("engine/standard_registry/_data/schema_manifest.json");
    let paths = manifest["schemas"]
        .as_array()
        .expect("schema manifest must contain a schemas array");
    let mut identities = HashSet::with_capacity(paths.len());

    assert_eq!(paths.len(), 70);
    let manifest_schema =
        read_json("engine/standard_registry/_data/schema_manifest_schema_v2.json");
    jsonschema::draft202012::validate(&manifest_schema, &manifest)
        .expect("live schema manifest must validate under its advertised version");
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
        jsonschema::draft202012::meta::validate(&schema)
            .unwrap_or_else(|error| panic!("invalid JSON Schema at {relative}: {error}"));
    }
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-010`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn proof_writer_validates_against_advertised_schema() {
    let schema = read_json("engine/finding_model/_data/proof_graph_schema_v1.json");
    let graph = ProofGraph::new(
        "root",
        vec![ProofExpression {
            node_id: "root".to_owned(),
            operator: ProofOperator::Leaf,
            required_refs: vec![EvidenceReference::new("evidence:a").expect("stable evidence ID")],
            children: Vec::new(),
        }],
    );
    let instance = serde_json::to_value(graph).expect("proof graph serializes");
    jsonschema::draft202012::validate(&schema, &instance)
        .expect("emitted proof graph must match its advertised schema");
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-011`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn local_certificate_writer_validates_against_advertised_schema() {
    let schema = read_json("engine/snapshot_governance/_data/quality_certificate_schema_v3.json");
    let digest = format!("sha256:{}", "a".repeat(64));
    let certificate = serde_json::json!({
        "$schema": "urn:fortress:derived:v3:local-quality-certificate",
        "schema_version": 3,
        "semantic_version": "quality-certificate-v3.0",
        "project": "PF-FORTRESS",
        "profile": "fortress-complete-local-v1",
        "claim": "LOCAL_QUALITY_GATES_PASS",
        "trust": {
            "level": "untrusted-local",
            "tamper_evidence": "SHA-256",
            "authenticity": "UNVERIFIED",
            "limitation": "local digest evidence is not an authenticated signature"
        },
        "source": {
            "fingerprint": digest.clone(),
            "file_count": 1,
            "excluded_self": "quality-certificate",
            "excluded_derived_artifacts": ["ccg"]
        },
        "toolchain": {
            "rust": "1.97.1",
            "cargo_config": "_data/cargo_config.toml",
            "resolver_lockfile": "_info/Cargo.lock",
            "build_artifacts": "external-temporary-directory",
            "derived_projections": "external-subject-addressed-cache"
        },
        "gates": [{"id": "FORMAT", "status": "PASS", "command": "cargo fmt --check"}],
        "artifacts": [{"id": "ccg", "digest": digest.clone(), "bytes": 1, "storage": "LOCAL_MATERIALIZATION"}],
        "audit_json_digest": digest.clone(),
        "certificate_stamp": digest
    });
    jsonschema::draft202012::validate(&schema, &certificate)
        .expect("emitted local certificate must match its advertised schema");
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-012`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn compatibility_catalog_covers_every_registered_schema_version() {
    let schema = read_json("engine/standard_registry/_data/compatibility_catalog_schema_v1.json");
    let catalog = read_json("engine/standard_registry/_data/compatibility_catalog_v1.json");
    jsonschema::draft202012::validate(&schema, &catalog).expect("catalog wire shape");
    let manifest = read_json("engine/standard_registry/_data/schema_manifest.json");
    let entries = catalog["entries"].as_array().expect("catalog entries");
    let paths = manifest["schemas"].as_array().expect("schema paths");
    assert_eq!(entries.len(), paths.len());
    let mut seen = HashSet::new();
    for entry in entries {
        let path = entry["schema_path"].as_str().expect("schema path");
        assert!(
            seen.insert(path.to_owned()),
            "duplicate catalog path {path}"
        );
        assert_eq!(entry["schema_id"], read_json(path)["$id"]);
        for role in ["writer", "reader"] {
            if let Some(source) = entry[role]["source"].as_str() {
                assert!(
                    repository_root().join(source).is_file(),
                    "missing {role} source {source}"
                );
            }
        }
        if entry["writer"]["status"] == "RETIRED" && entry["reader"]["status"] == "UNSUPPORTED" {
            assert_eq!(entry["migration"], "REQUIRED_BEFORE_USE");
        }
    }
    assert!(
        paths
            .iter()
            .all(|path| seen.contains(path.as_str().expect("path")))
    );
}

/// `T-AF-STANDARD-REGISTRY-0001-R05-001`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R05
#[test]
fn full_snapshot_certification_profile_cannot_hide_mandatory_evidence() {
    let profile = read_json("engine/standard_registry/_data/cert_full_snapshot_v1.json");
    assert_eq!(profile["id"], "CERT-FULL-SNAPSHOT-V1");
    for property in [
        "require_all_applicable_rules",
        "require_all_requirement_tests",
        "require_behavioral_realization",
        "require_generated_verification",
        "require_current_artifacts",
    ] {
        assert_eq!(
            profile[property], true,
            "full profile weakened `{property}`"
        );
    }
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-002`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn draft_manifest_agrees_with_implemented_registry() {
    let manifest = read_json("engine/standard_registry/_data/standard_manifest.json");
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
    let rule_schema = read_json("engine/standard_registry/_data/rule_schema_v1.json");
    assert!(rule_schema["properties"]["$schema"].is_object());
    let manifest_schema =
        read_json("engine/standard_registry/_data/standard_manifest_schema_v1.json");
    assert!(manifest_schema["properties"]["$schema"].is_object());

    let manifest = read_json("engine/standard_registry/_data/standard_manifest.json");
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
