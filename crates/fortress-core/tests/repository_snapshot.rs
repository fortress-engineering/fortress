//! Repository-level evidence for canonical stabilized Fortress snapshots.
//!
//! This test consumes Fortress's declared model and draft standard inputs. It
//! proves deterministic development snapshot construction, not certification.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::observation::ObservationPolicy;
use fortress_core::project::ProjectManifest;
use fortress_core::snapshot::{SnapshotDocuments, build_repository_snapshot};
use serde_json::Value;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_bytes(root: &Path, relative: &str) -> Vec<u8> {
    let path = root.join(relative);
    fs::read(&path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R01-004`
#[test]
fn fortress_self_snapshot_is_repeatable_and_binds_all_draft_rules() {
    let root = repository_root();
    let project_path = ".fortress/project.json";
    let project_bytes = read_bytes(&root, project_path);
    let project_source = String::from_utf8(project_bytes.clone()).expect("project JSON is UTF-8");
    let project = ProjectManifest::from_json_str(&project_source).expect("project must validate");

    let architecture_path = project.model().architecture();
    let architecture_bytes = read_bytes(&root, architecture_path);
    let feature_sources: Vec<(String, Vec<u8>)> = project
        .model()
        .features()
        .iter()
        .map(|path| (path.clone(), read_bytes(&root, path)))
        .collect();

    let standard_manifest_path = "standard/drafts/1.0.0/manifest.json";
    let standard_manifest_bytes = read_bytes(&root, standard_manifest_path);
    let standard_manifest: Value = serde_json::from_slice(&standard_manifest_bytes)
        .expect("standard manifest must be valid JSON");
    let standard_root = Path::new(standard_manifest_path)
        .parent()
        .expect("standard manifest has a parent");
    let rule_sources: Vec<(String, Vec<u8>)> = standard_manifest["rules"]
        .as_array()
        .expect("standard manifest rules must be an array")
        .iter()
        .map(|value| {
            let relative = value.as_str().expect("rule path must be a string");
            let path = standard_root
                .join(relative)
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = read_bytes(&root, &path);
            (path, bytes)
        })
        .collect();

    let documents = SnapshotDocuments::new(
        standard_manifest_path,
        &standard_manifest_bytes,
        rule_sources
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
        &project_bytes,
        &architecture_bytes,
        feature_sources
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
    );
    let policy = ObservationPolicy::new([".git", "target", ".fortress/state"])
        .expect("self observation policy must validate");

    let first = build_repository_snapshot(&root, &policy, &project, &documents)
        .expect("first self snapshot must succeed");
    let second = build_repository_snapshot(&root, &policy, &project, &documents)
        .expect("second self snapshot must succeed");

    assert_eq!(first, second);
    assert_eq!(first.project_id(), "PF-FORTRESS");
    assert_eq!(first.standard_edition(), "1.0.0-draft.1");
    assert_eq!(first.standard_status(), "draft");
    assert!(first.declared_standard_digest().is_none());
    assert!(first.standard_input_fingerprint().starts_with("sha256:"));
    assert_eq!(first.to_json_pretty().ok(), second.to_json_pretty().ok());
}
