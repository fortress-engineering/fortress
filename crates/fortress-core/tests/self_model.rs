//! Repository-level evidence for Fortress's initial self-governance model.
//!
//! These tests prove structural agreement among current declarations and code.
//! They do not create content-addressed certification evidence or a PASS claim.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::command::CommandRegistry;
use fortress_core::project::ProjectManifest;
use serde_json::Value;

/// Returns the checked-out repository root for integration fixtures.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Reads and parses a repository-relative JSON document.
fn read_json(relative_path: &str) -> Value {
    let path = repository_root().join(relative_path);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&source)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

/// Returns an object member as an array or fails with its model location.
fn array_member<'a>(document: &'a Value, name: &str) -> &'a [Value] {
    document[name]
        .as_array()
        .unwrap_or_else(|| panic!("self-model member `{name}` must be an array"))
}

/// `T-AF-BOOTSTRAP-GOVERNANCE-0001-R01-001`
#[test]
fn declared_project_loads_and_references_existing_documents() {
    let source = fs::read_to_string(repository_root().join(".fortress/project.json"))
        .expect("self project manifest must be readable");
    let project =
        ProjectManifest::from_json_str(&source).expect("self project model must validate");

    let referenced = std::iter::once(project.model().architecture())
        .chain(project.model().features().iter().map(String::as_str))
        .chain(std::iter::once(project.model().commands()))
        .chain(std::iter::once(project.model().certifications()))
        .chain(project.model().active_changes().iter().map(String::as_str));

    for relative_path in referenced {
        assert!(
            repository_root().join(relative_path).is_file(),
            "declared model document is missing: {relative_path}"
        );
    }
}

/// `T-AF-BOOTSTRAP-GOVERNANCE-0001-R01-002`
#[test]
fn declared_commands_match_the_implemented_registry() {
    let declared = read_json(".fortress/commands/core.json");
    let declared_commands = array_member(&declared, "commands");
    let registry = CommandRegistry::builtin();

    assert_eq!(declared_commands.len(), registry.commands().len());
    for implemented in registry.commands() {
        let declaration = declared_commands
            .iter()
            .find(|candidate| candidate["id"] == implemented.id())
            .unwrap_or_else(|| panic!("command {} is not declared", implemented.id()));
        assert_eq!(declaration["name"], implemented.name());
        let aliases: Vec<&str> = declaration["aliases"]
            .as_array()
            .expect("command aliases must be an array")
            .iter()
            .map(|value| value.as_str().expect("command alias must be a string"))
            .collect();
        assert_eq!(aliases, implemented.aliases());
    }
}

/// `T-AF-BOOTSTRAP-GOVERNANCE-0001-R01-003`
#[test]
fn certification_scaffold_makes_no_false_pass_claim() {
    let certification = read_json(".fortress/certifications/bootstrap.json");
    assert_eq!(certification["claim"], "NOT CERTIFIED");
    assert!(
        array_member(&certification, "units")
            .iter()
            .all(|unit| unit["status"] == "MISSING" && unit["evidence"].is_null())
    );
}

/// `T-AF-BOOTSTRAP-GOVERNANCE-0001-R01-004`
#[test]
fn recorded_packet_digests_are_canonical_sha256_identities() {
    let change = read_json(".fortress/changes/archive/2026/CHG-BOOTSTRAP-0001.json");
    let digests = array_member(&change["bootstrap_provenance"], "digests");
    assert_eq!(digests.len(), 28);
    for record in digests {
        let value = record["sha256"]
            .as_str()
            .expect("packet digest must be a string");
        let digest = value
            .strip_prefix("sha256:")
            .expect("packet digest must name its algorithm");
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}
