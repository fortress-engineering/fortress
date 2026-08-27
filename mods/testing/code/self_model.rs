//! Repository-level evidence for Fortress's initial self-governance model.
//!
//! These tests prove structural agreement among current declarations and code.
//! They do not create content-addressed certification evidence or a PASS claim.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fortress_cli::command::CommandRegistry;
use fortress_core::architecture::ArchitectureManifest;
use fortress_core::module_contract::{ContractStandardIndex, resolve_contracts};
use fortress_core::observation::{ObservationPolicy, observe_repository};
use fortress_core::project::ProjectConfiguration;
use fortress_core::rust_test_analyzer::analyze_rust_source;
use serde_json::Value;

/// Returns the checked-out repository root for integration fixtures.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
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
    let source = fs::read_to_string(repository_root().join("data/project.json"))
        .expect("self project configuration must be readable");
    let project = ProjectConfiguration::from_json_str(&source)
        .expect("self project configuration must validate");
    assert_eq!(project.observation_exclusions(), [".git"]);
    assert!(repository_root().join("contract.json").is_file());
}

/// `T-AF-BOOTSTRAP-GOVERNANCE-0001-R01-002`
#[test]
fn declared_commands_match_the_implemented_registry() {
    let declared = read_json("mods/cli/data/commands.json");
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
    let certification = read_json("data/certification.json");
    assert_eq!(certification["claim"], "NOT CERTIFIED");
    assert!(
        array_member(&certification, "units")
            .iter()
            .all(|unit| unit["status"] == "MISSING" && unit["evidence"].is_null())
    );
}

/// `T-AF-BOOTSTRAP-GOVERNANCE-0001-R02-001`
#[test]
fn live_contract_v2_ecosystem_resolves_completely() {
    let root = repository_root();
    let policy = ObservationPolicy::new([".git"]).expect("policy validates");
    let observation = observe_repository(&root, &policy).expect("repository observes");
    let files: BTreeMap<String, Vec<u8>> = observation
        .files()
        .iter()
        .map(|file| {
            (
                file.path().to_owned(),
                fs::read(root.join(file.path())).expect("observed file reads"),
            )
        })
        .collect();
    let mut test_ids = BTreeSet::new();
    for (path, bytes) in &files {
        if Path::new(path)
            .extension()
            .is_some_and(|extension| extension == "rs")
        {
            let source = std::str::from_utf8(bytes).expect("Rust source is UTF-8");
            for fact in analyze_rust_source(path, source).expect("Rust test facts analyze") {
                assert!(test_ids.insert(fact.id().to_owned()));
            }
        }
    }
    let resolution = resolve_contracts(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            [
                "ARCH-DEPENDENCY-001",
                "ARCH-OWNERSHIP-001",
                "CONTRACT-COHERENCY-001",
                "REPO-DOCS-001",
                "REPO-MODULE-001",
                "STD-ID-001",
                "TEST-TRACEABILITY-001",
            ],
        ),
        Some(&test_ids),
    );
    let resolved = resolution
        .resolved()
        .unwrap_or_else(|| panic!("live contracts resolve: {:#?}", resolution.violations()));
    assert_eq!(resolved.modules().len(), 15);
    assert_eq!(resolved.capabilities().len(), 7);
    assert_eq!(resolved.features().len(), 7);
    assert_eq!(resolved.requirements().len(), 25);
    assert_eq!(resolved.guarantees().len(), 3);
    assert_eq!(resolved.checkpoints().len(), 0);
    assert_eq!(resolved.direct_requirements().len(), 22);
    assert_eq!(resolved.relationships().len(), 7);
    assert!(resolved.modules().values().all(|module| {
        module.contract().behavior().is_empty() && module.digest().starts_with("sha256:")
    }));
    assert!(
        resolved
            .effective_constraints()
            .values()
            .all(|values| values.len() == 4)
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R02-001`
#[test]
fn declared_self_architecture_is_acyclic() {
    let root = repository_root();
    let policy = ObservationPolicy::new([".git"]).expect("policy validates");
    let observation = observe_repository(&root, &policy).expect("repository observes");
    let files = observation
        .files()
        .iter()
        .map(|file| {
            (
                file.path().to_owned(),
                fs::read(root.join(file.path())).expect("observed file reads"),
            )
        })
        .collect();
    let resolution = resolve_contracts(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            [
                "ARCH-DEPENDENCY-001",
                "ARCH-OWNERSHIP-001",
                "CONTRACT-COHERENCY-001",
                "REPO-DOCS-001",
                "REPO-MODULE-001",
                "STD-ID-001",
                "TEST-TRACEABILITY-001",
            ],
        ),
        None,
    );
    let paths = observation
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect::<Vec<_>>();
    let resolved = resolution
        .resolved()
        .unwrap_or_else(|| panic!("self contracts resolve: {:#?}", resolution.violations()));
    let architecture = ArchitectureManifest::from_resolved_contracts(resolved, &paths);
    assert!(
        architecture
            .evaluate_acyclic_dependencies("1.0.0-draft.1")
            .expect("finding normalization must succeed")
            .is_none()
    );
}
