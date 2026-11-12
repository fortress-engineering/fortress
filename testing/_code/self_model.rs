//! Repository-level evidence for Fortress's initial self-governance model.
//!
//! These tests prove structural agreement among current declarations and code.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fortress_cli::command::CommandRegistry;
use fortress_core::contract_coherency::{
    CcgObservedTestFact, ContractStandardIndex, compile_contract_coherency_graph,
};
use fortress_core::control_layout::ControlLayout;
use fortress_core::observation::{ObservationPolicy, observe_repository};
use fortress_core::project::ProjectConfiguration;
use fortress_core::rust_test_analyzer::analyze_rust_source;
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
/// Fortress requirement: AF-BOOTSTRAP-GOVERNANCE-0001-R01
#[test]
fn declared_project_loads_and_references_existing_documents() {
    let source = fs::read_to_string(repository_root().join("__fortress/.fsconfig"))
        .expect("self project configuration must be readable");
    let project = ProjectConfiguration::from_json_str(&source)
        .expect("self project configuration must validate");
    assert_eq!(project.observation_exclusions(), [".git", "target"]);
    assert!(repository_root().join("contract.json").is_file());
}

/// `T-AF-BOOTSTRAP-GOVERNANCE-0001-R01-002`
/// Fortress requirement: AF-BOOTSTRAP-GOVERNANCE-0001-R01
#[test]
fn declared_commands_match_the_implemented_registry() {
    let declared = read_json("cli/_data/commands.json");
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
    assert!(!repository_root().join("_data/certification.json").exists());
    assert!(
        ControlLayout::standard()
            .artifact_logical_paths()
            .contains(&"_info/certification.json")
    );
}

/// `T-AF-BOOTSTRAP-GOVERNANCE-0001-R02-001`
/// Fortress requirement: AF-BOOTSTRAP-GOVERNANCE-0001-R02
#[test]
fn live_contract_v2_v3_ecosystem_resolves_completely() {
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
            "1.0.0-draft.2",
            [
                "ARCH-DEPENDENCY-001",
                "ARCH-OWNERSHIP-001",
                "ARCH-REALIZATION-001",
                "ARCH-SEMANTIC-001",
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
    assert_eq!(resolved.modules().len(), 51);
    assert_eq!(resolved.capabilities().len(), 25);
    assert_eq!(resolved.features().len(), 26);
    assert_eq!(resolved.requirements().len(), 158);
    assert!(
        resolved
            .requirements()
            .contains_key("AF-STATE-EFFECT-ANALYSIS-0001-R06")
    );
    for id in REQUIRED_SELF_MODEL_REQUIREMENTS {
        assert!(resolved.requirements().contains_key(*id));
    }
    assert_eq!(resolved.guarantees().len(), 17);
    assert_eq!(resolved.checkpoints().len(), 10);
    assert_eq!(resolved.direct_requirements().len(), 211);
    assert_eq!(resolved.relationships().len(), 25);
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

/// `T-AF-BOOTSTRAP-GOVERNANCE-0001-R02-002`
/// Fortress requirement: AF-BOOTSTRAP-GOVERNANCE-0001-R02
#[test]
fn real_reference_scope_has_authored_purity_and_nonvacuous_semantic_support() {
    use fortress_core::semantic_conformance::{PolicyDisposition, SemanticConformanceState};
    let root = repository_root();
    let source = fs::read_to_string(root.join("testing/semantic_oracle/contract.json")).unwrap();
    let contract =
        fortress_core::contract_coherency::ModuleContract::from_json_str(&source).unwrap();
    let policy = contract
        .semantic_policy()
        .expect("pure responsibility deliberately authors policy");
    assert_eq!(
        policy.effects().deny(),
        ["filesystem.write", "process.spawn"]
    );
    let reference =
        fs::read_to_string(root.join("testing/semantic_oracle/_code/oracle.rs")).unwrap();
    assert!(!reference.contains("use fortress_core"));
    let evaluated = fortress_core::audit::compile_repository_semantic_conformance(&root).unwrap();
    let module = evaluated
        .model()
        .module("AF-SEMANTIC-ORACLE-0001")
        .expect("real owned helper scope");
    assert_eq!(module.coverage().governed_source_files(), 1);
    assert_eq!(module.coverage().analysed_source_files(), 1);
    assert_eq!(module.conclusions().len(), 2);
    let defeaters = evaluated
        .model()
        .defeaters()
        .iter()
        .filter(|defeater| module.defeater_refs().contains(&defeater.id().to_owned()))
        .collect::<Vec<_>>();
    for claim in module.conclusions() {
        assert_eq!(claim.disposition(), PolicyDisposition::Deny);
        assert_eq!(
            claim.conformance(),
            Some(SemanticConformanceState::NoSupportedViolation),
            "authored purity requires complete independent semantic support: {claim:#?}; {defeaters:#?}"
        );
        assert_eq!(claim.coverage().ratio(), Some("1/1"));
    }
    for id in [
        "TF-CLI-0001",
        "AF-SNAPSHOT-GOVERNANCE-0001",
        "TEST-FORTRESS-0001",
    ] {
        assert!(
            evaluated
                .model()
                .module(id)
                .unwrap()
                .effective_policy()
                .is_none(),
            "I/O-owning responsibility stays deliberately undeclared: {id}"
        );
    }
}

const REQUIRED_SELF_MODEL_REQUIREMENTS: &[&str] = &[
    "AF-SNAPSHOT-GOVERNANCE-0001-R23",
    "TF-CLI-0001-R28",
    "AF-MIGRATION-GOVERNANCE-0001-R01",
    "AF-MIGRATION-GOVERNANCE-0001-R02",
    "AF-MIGRATION-GOVERNANCE-0001-R03",
    "AF-MIGRATION-GOVERNANCE-0001-R04",
    "AF-MIGRATION-GOVERNANCE-0001-R05",
    "AF-MIGRATION-GOVERNANCE-0001-R06",
    "AF-MIGRATION-GOVERNANCE-0001-R07",
    "AF-DEVELOPMENT-GOVERNANCE-0001-R02",
    "TF-CLI-0001-R26",
    "AF-CERTIFICATION-0001-R05",
    "TF-CLI-0001-R19",
    "AF-SNAPSHOT-GOVERNANCE-0001-R21",
    "TF-CLI-0001-R21",
    "AF-STATE-GOVERNANCE-0001-R01",
    "AF-STATE-GOVERNANCE-0001-R02",
    "AF-STATE-GOVERNANCE-0001-R03",
    "AF-STATE-GOVERNANCE-0001-R04",
    "AF-STATE-GOVERNANCE-0001-R05",
    "AF-STATE-GOVERNANCE-0001-R06",
    "TF-CLI-0001-R22",
];
