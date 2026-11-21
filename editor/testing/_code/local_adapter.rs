//! Canonical registration checks for the desktop extension.

use serde_json::{Value, json};

/// `T-TF-EDITOR-0001-R01-001`
/// Fortress requirement: TF-EDITOR-0001-R01
#[test]
fn local_editor_manifest_and_lock_preserve_the_declared_boundary() {
    let manifest: Value =
        serde_json::from_str(include_str!("../../_data/editor_manifest.json")).unwrap();
    let lock: Value = serde_json::from_str(include_str!("../../_data/npm_lock.json")).unwrap();
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
