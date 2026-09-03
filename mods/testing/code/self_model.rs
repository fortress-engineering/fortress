//! Repository-level evidence for Fortress's initial self-governance model.
//!
//! These tests prove structural agreement among current declarations and code.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fortress_cli::command::CommandRegistry;
use fortress_core::certification::GENERATED_CERTIFICATION_PROJECTIONS;
use fortress_core::contract_coherency::{
    CcgObservedTestFact, ContractStandardIndex, compile_contract_coherency_graph,
};
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
/// Fortress requirement: AF-BOOTSTRAP-GOVERNANCE-0001-R01
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
/// Fortress requirement: AF-BOOTSTRAP-GOVERNANCE-0001-R01
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
/// Fortress requirement: AF-BOOTSTRAP-GOVERNANCE-0001-R01
#[test]
fn generated_certification_is_not_authored_project_data() {
    assert!(!repository_root().join("data/certification.json").exists());
    assert!(GENERATED_CERTIFICATION_PROJECTIONS.contains(&"info/certification.json"));
}

/// `T-AF-BOOTSTRAP-GOVERNANCE-0001-R02-001`
/// Fortress requirement: AF-BOOTSTRAP-GOVERNANCE-0001-R02
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
    let mut test_facts = Vec::new();
    for (path, bytes) in &files {
        if Path::new(path)
            .extension()
            .is_some_and(|extension| extension == "rs")
        {
            let source = std::str::from_utf8(bytes).expect("Rust source is UTF-8");
            for fact in analyze_rust_source(path, source).expect("Rust test facts analyze") {
                assert!(test_ids.insert(fact.id().to_owned()));
                test_facts.push(CcgObservedTestFact::from(&fact));
            }
        }
    }
    let resolution = compile_contract_coherency_graph(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            [
                "ARCH-DEPENDENCY-001",
                "ARCH-OWNERSHIP-001",
                "ARCH-REALIZATION-001",
                "BEHAVIOR-BYPASS-001",
                "BEHAVIOR-FLOW-001",
                "BEHAVIOR-REALIZATION-001",
                "CONTRACT-COHERENCY-001",
                "PROGRAM-DOMAIN-001",
                "PROGRAM-EFFECT-001",
                "PROGRAM-ENVIRONMENT-001",
                "PROGRAM-INFOFLOW-001",
                "PROGRAM-RECOVERY-001",
                "PROGRAM-RETRY-001",
                "PROGRAM-STATE-001",
                "REPO-DOCS-001",
                "REPO-MODULE-001",
                "REPO-REFERENCE-001",
                "SOURCE-ARTIFACT-001",
                "SOURCE-PROFILE-001",
                "STD-ID-001",
                "TEST-BOUNDARY-001",
                "TEST-TRACEABILITY-001",
            ],
        ),
        Some(&test_facts),
    );
    let resolved = resolution
        .graph()
        .unwrap_or_else(|| panic!("live contracts resolve: {:#?}", resolution.violations()));
    assert!(
        resolution.is_success(),
        "live CCG must be coherent: {:#?}",
        resolution.violations()
    );
    assert_eq!(resolved.modules().len(), 40);
    assert_eq!(resolved.capabilities().len(), 20);
    assert_eq!(resolved.features().len(), 20);
    assert_eq!(resolved.requirements().len(), 95);
    assert_eq!(resolved.guarantees().len(), 9);
    assert_eq!(resolved.checkpoints().len(), 10);
    assert_eq!(resolved.direct_requirements().len(), 145);
    assert_eq!(resolved.relationships().len(), 19);
    assert!(
        resolved
            .modules()
            .values()
            .all(|module| module.digest().starts_with("sha256:"))
    );
    assert!(
        resolved
            .effective_constraints()
            .values()
            .all(|values| values.len() == 9)
    );
}
