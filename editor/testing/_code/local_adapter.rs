//! Canonical registration checks for the desktop extension.

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

/// `T-TF-EDITOR-0001-R01-001`
/// Fortress requirement: TF-EDITOR-0001-R01
#[test]
fn local_editor_manifest_and_lock_preserve_the_declared_boundary() {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../editor/_data");
    let read = |name: &str| -> Value {
        serde_json::from_slice(&fs::read(data.join(name)).unwrap()).unwrap()
    };
    let manifest = read("editor_manifest.json");
    let lock = read("npm_lock.json");
    assert_eq!(manifest["main"], "./out/_code/extension.js");
    assert_eq!(manifest["extensionKind"], json!(["workspace"]));
    assert_eq!(
        manifest["capabilities"]["untrustedWorkspaces"]["supported"],
        false
    );
    assert_eq!(
        manifest["capabilities"]["virtualWorkspaces"]["supported"],
        false
    );
    let executable = &manifest["contributes"]["configuration"]["properties"]["fortress.executable"];
    assert_eq!(executable["scope"], "machine");
    assert_eq!(executable["default"], "");
    assert!(manifest.get("dependencies").is_none());
    assert_eq!(
        manifest["devDependencies"],
        lock["packages"][""]["devDependencies"]
    );
    for (name, version) in manifest["devDependencies"].as_object().unwrap() {
        let package = &lock["packages"][format!("node_modules/{name}")];
        assert_eq!(&package["version"], version);
        assert!(
            package["integrity"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha512-"))
        );
    }
}
