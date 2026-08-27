//! Process-level evidence for the canonical Fortress CLI entrypoints.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fortress_cli::command::{CommandDescriptor, CommandRegistry};
use fortress_cli::{EXIT_SUCCESS, EXIT_USAGE};
use fortress_core::contract_coherency::ModuleContract;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fortress"))
        .args(arguments)
        .output()
        .expect("Fortress CLI process must start")
}

fn run_owned(arguments: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fortress"))
        .args(arguments)
        .output()
        .expect("Fortress CLI process must start")
}

struct AuditFixture {
    root: PathBuf,
}

impl AuditFixture {
    #[allow(clippy::too_many_lines)]
    fn new() -> Self {
        let identity = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fortress-cli-audit-{}-{identity}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("fixture root creates");
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        fs::write(root.join("README.md"), module_readme("Fixture")).expect("root README writes");
        fs::write(
            root.join("contract.json"),
            module_contract("PF-FIXTURE", "Fixture"),
        )
        .expect("root contract writes");
        fs::create_dir_all(root.join("data")).expect("root data creates");
        fs::create_dir_all(root.join("docs")).expect("root docs creates");
        fs::write(root.join("docs/data_docs.md"), data_docs(&["project.json"]))
            .expect("root data documentation writes");
        fs::write(
            root.join("docs/mods_docs.md"),
            modules_docs(&[("engine", "Fixture Engine")]),
        )
        .expect("root Module documentation writes");
        fs::create_dir_all(root.join("mods/engine/mods")).expect("engine Module creates");
        fs::write(
            root.join("mods/engine/README.md"),
            module_readme("Fixture Engine"),
        )
        .expect("engine README writes");
        fs::write(
            root.join("mods/engine/contract.json"),
            module_contract("AF-FIXTURE-ENGINE-0001", "Fixture Engine"),
        )
        .expect("engine contract writes");
        fs::create_dir_all(root.join("mods/engine/docs")).expect("engine docs creates");
        fs::write(
            root.join("mods/engine/docs/mods_docs.md"),
            modules_docs(&[
                ("architecture_evaluation", "Architecture Evaluation"),
                ("snapshot_governance", "Snapshot Governance"),
                ("standard_registry", "Standard Registry"),
            ]),
        )
        .expect("engine Module documentation writes");
        for (module, identity, display) in [
            (
                "standard_registry",
                "AF-FIXTURE-STANDARD-0001",
                "Standard Registry",
            ),
            (
                "architecture_evaluation",
                "AF-FIXTURE-ARCHITECTURE-0001",
                "Architecture Evaluation",
            ),
            (
                "snapshot_governance",
                "AF-FIXTURE-SNAPSHOT-0001",
                "Snapshot Governance",
            ),
        ] {
            let module_root = root.join("mods/engine/mods").join(module);
            fs::create_dir_all(module_root.join("code")).expect("Module code creates");
            fs::create_dir_all(module_root.join("data")).expect("Module data creates");
            fs::create_dir_all(module_root.join("docs")).expect("Module docs creates");
            fs::write(module_root.join("README.md"), module_readme(display))
                .expect("Module README writes");
            fs::write(
                module_root.join("contract.json"),
                module_contract(identity, display),
            )
            .expect("Module contract writes");
            fs::write(module_root.join("code/marker.txt"), "fixture")
                .expect("Module code marker writes");
            fs::write(
                module_root.join("docs/code_docs.md"),
                code_docs(&["marker.txt"]),
            )
            .expect("Module code documentation writes");
        }
        for relative in [
            "mods/engine/mods/standard_registry/data/standard_manifest.json",
            "mods/engine/mods/standard_registry/data/std_id_rule.json",
            "mods/engine/mods/architecture_evaluation/data/dependency_rule.json",
            "mods/engine/mods/architecture_evaluation/data/realization_rule.json",
            "mods/engine/mods/snapshot_governance/data/ownership_rule.json",
            "mods/engine/mods/snapshot_governance/data/traceability_rule.json",
            "mods/engine/mods/snapshot_governance/data/test_boundary_rule.json",
            "mods/engine/mods/snapshot_governance/data/module_rule.json",
            "mods/engine/mods/snapshot_governance/data/documentation_rule.json",
            "mods/engine/mods/snapshot_governance/data/contract_rule.json",
        ] {
            fs::copy(repository.join(relative), root.join(relative)).expect("standard file copies");
        }
        fs::write(
            root.join("mods/engine/mods/standard_registry/docs/data_docs.md"),
            data_docs(&["standard_manifest.json", "std_id_rule.json"]),
        )
        .expect("standard Data documentation writes");
        fs::write(
            root.join("mods/engine/mods/architecture_evaluation/docs/data_docs.md"),
            data_docs(&["dependency_rule.json", "realization_rule.json"]),
        )
        .expect("architecture Data documentation writes");
        fs::write(
            root.join("mods/engine/mods/snapshot_governance/docs/data_docs.md"),
            data_docs(&[
                "documentation_rule.json",
                "contract_rule.json",
                "module_rule.json",
                "ownership_rule.json",
                "test_boundary_rule.json",
                "traceability_rule.json",
            ]),
        )
        .expect("snapshot Data documentation writes");
        fs::write(root.join("data/project.json"), project_json()).expect("project writes");
        Self { root }
    }

    fn argument(&self) -> String {
        self.root.to_string_lossy().into_owned()
    }
}

fn module_contract(identity: &str, display_name: &str) -> String {
    let ecosystem = (identity == "PF-FIXTURE").then(|| {
        serde_json::json!({
            "repository_grammar": 1,
            "standard": {
                "id": "STD-FORTRESS-ENGINEERING",
                "edition": "1.0.0-draft.1"
            }
        })
    });
    let mut value = serde_json::json!({
        "$schema": "urn:fortress:schema:v2:module-contract",
        "schema_version": 2,
        "id": identity,
        "display_name": display_name,
        "provides": [],
        "requires": [],
        "relationships": [],
        "constraints": [],
        "guarantees": [],
        "features": [],
        "behavior": []
    });
    if let Some(ecosystem) = ecosystem {
        value
            .as_object_mut()
            .expect("contract is object")
            .insert("ecosystem".into(), ecosystem);
    }
    let contract: ModuleContract =
        serde_json::from_value(value).expect("fixture contract deserializes");
    contract
        .to_canonical_json()
        .expect("fixture contract serializes")
}

fn module_readme(display_name: &str) -> String {
    format!(
        "# {display_name}\n\n## Purpose\n\nProvide a controlled repository audit fixture responsibility.\n\n## Responsibility\n\nSupply coherent declarations and Module surfaces for process-level CLI verification.\n\n## Scope\n\n### Includes\n\nOnly the direct fixture elements required by the audit scenario.\n\n### Excludes\n\nProduction repository meaning and persisted runtime evidence.\n\n## Relationships\n\nThis Module declares no outbound architectural relationships.\n\n## Guarantees\n\nFixture content is deterministic and isolated to one process-level test.\n"
    )
}

fn code_docs(files: &[&str]) -> String {
    let entries = files
        .iter()
        .map(|file| {
            format!(
                "### [`{file}`](../code/{file})\n\nProvides directly owned executable fixture behavior.\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "# Code\n\n## Role\n\nRealize the fixture Module responsibility.\n\n## Execution\n\nThe audit observes this direct Code element during one controlled invocation.\n\n## State\n\nThe fixture Code is immutable for the lifetime of the audit process.\n\n## Failure Semantics\n\nMissing or changed fixture Code causes explicit audit failure.\n\n## Files\n\n{entries}"
    )
}

fn data_docs(files: &[&str]) -> String {
    let entries = files
        .iter()
        .map(|file| {
            format!(
                "### [`{file}`](../data/{file})\n\nProvides an authored declaration consumed by the fixture audit.\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "# Data\n\n## Role\n\nPersist authored fixture inputs.\n\n## Origin\n\nThe process-level test authors these controlled declarations.\n\n## Semantics\n\nEach file supplies exact input meaning to one repository audit.\n\n## Validity\n\nInputs must remain valid JSON with canonical identities and paths.\n\n## Lifecycle\n\nThe disposable fixture creates the Data before audit and removes it after the test.\n\n## Files\n\n{entries}"
    )
}

fn modules_docs(children: &[(&str, &str)]) -> String {
    let entries = children
        .iter()
        .map(|(directory, display)| {
            format!(
                "### [{display}](../mods/{directory}/README.md)\n\nContributes one governed responsibility to the fixture parent.\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "# Modules\n\n## Composition\n\nThe fixture separates independently audited responsibilities into immediate child Modules.\n\n## Modules\n\n{entries}\n## Coordination\n\nThe child Modules collectively provide the declarations and governed files required by the fixture audit.\n"
    )
}

impl Drop for AuditFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn project_json() -> &'static str {
    r#"{
      "$schema":"urn:fortress:schema:v2:project-configuration","schema_version":2,
      "observation_exclusions":[".git"]
    }"#
}

/// `T-TF-CLI-0001-R03-001`
/// Fortress requirement: TF-CLI-0001-R03
#[test]
fn version_flag_reports_implementation_identity() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "fortress 0.1.0\n");
    assert!(output.stderr.is_empty());
}

/// `T-TF-CLI-0001-R03-002`
/// Fortress requirement: TF-CLI-0001-R03
#[test]
fn help_discovers_only_implemented_commands() {
    let output = run(&["help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("help"));
    assert!(stdout.contains("version"));
    assert!(
        stdout
            .lines()
            .any(|line| line.trim_start().starts_with("audit "))
    );
    assert!(
        !stdout
            .lines()
            .any(|line| line.trim_start().starts_with("certify "))
    );
}

/// `T-TF-CLI-0001-R03-003`
/// Fortress requirement: TF-CLI-0001-R03
#[test]
fn unsupported_certification_command_fails() {
    let output = run(&["certify"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported command `certify`"));
}

/// `T-TF-CLI-0001-R03-004`
/// Fortress requirement: TF-CLI-0001-R03
#[test]
fn version_rejects_extra_arguments() {
    let output = run(&["--version", "unexpected"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage: fortress --version"));
}

/// `T-TF-CLI-0001-R04-001`
/// Fortress requirement: TF-CLI-0001-R04
#[test]
fn audit_success_renders_human_snapshot_report() {
    let fixture = AuditFixture::new();
    let output = run_owned(&["audit".into(), fixture.argument()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("Fortress Snapshot Audit"));
    assert!(stdout.contains("PASS: 8"));
    assert!(stdout.contains("Unsupported: 1"));
    assert!(!stdout.contains("certification"));
}

/// `T-TF-CLI-0001-R04-002`
/// Fortress requirement: TF-CLI-0001-R04
#[test]
fn audit_rule_failure_returns_violation_status() {
    let fixture = AuditFixture::new();
    fs::create_dir_all(fixture.root.join("island")).expect("island creates");
    fs::write(fixture.root.join("island/file.txt"), "violation").expect("island writes");
    let output = run_owned(&["audit".into(), fixture.argument()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("FAIL:"));
}

/// `T-TF-CLI-0001-R04-003`
/// Fortress requirement: TF-CLI-0001-R04
#[test]
fn audit_malformed_project_state_is_non_success() {
    let fixture = AuditFixture::new();
    fs::write(fixture.root.join("data/project.json"), "{").expect("project corrupts");
    let output = run_owned(&["audit".into(), fixture.argument()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid project state"));
}

/// `T-TF-CLI-0001-R04-004`
/// Fortress requirement: TF-CLI-0001-R04
#[test]
fn audit_json_is_valid_and_repeatable() {
    let fixture = AuditFixture::new();
    let arguments = ["audit".into(), fixture.argument(), "--format=json".into()];
    let first = run_owned(&arguments);
    let second = run_owned(&arguments);
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    let value: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("audit output is JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["outcome"], "PASS");
}

/// `T-TF-CLI-0001-R04-005`
/// Fortress requirement: TF-CLI-0001-R04
#[test]
fn audit_rejects_unsupported_options() {
    let output = run(&["audit", "--format", "xml"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("human` or `json"));
}

/// `T-TF-CLI-0001-R05-001`
/// Fortress requirement: TF-CLI-0001-R05
#[test]
fn ccg_json_is_schema_versioned_and_repeatable() {
    let fixture = AuditFixture::new();
    let arguments = ["ccg".into(), fixture.argument(), "--format=json".into()];
    let first = run_owned(&arguments);
    let second = run_owned(&arguments);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(first.stdout, second.stdout);
    let value: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("CCG output is JSON");
    assert_eq!(
        value["$schema"],
        "urn:fortress:schema:v1:contract-coherency-graph"
    );
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["coherency"]["status"], "coherent");
}

/// `T-TF-CLI-0001-R05-002`
/// Fortress requirement: TF-CLI-0001-R05
#[test]
fn ccg_rejects_unsupported_formats() {
    let output = run(&["ccg", "--format", "dot"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--format json"));
}

/// `T-TF-CLI-0001-R01-001`
/// Fortress requirement: TF-CLI-0001-R01
#[test]
fn builtin_registry_is_valid() {
    assert!(CommandRegistry::builtin().validate().is_ok());
}

/// `T-TF-CLI-0001-R01-002`
/// Fortress requirement: TF-CLI-0001-R01
#[test]
fn aliases_resolve_to_registered_descriptors() {
    let registry = CommandRegistry::builtin();
    assert_eq!(
        registry.find("--version").map(CommandDescriptor::id),
        Some("CMD-CORE-VERSION")
    );
}

/// `T-TF-CLI-0001-R01-003`
/// Fortress requirement: TF-CLI-0001-R01
#[test]
fn unimplemented_operation_is_absent() {
    assert!(CommandRegistry::builtin().find("certify").is_none());
}

/// `T-TF-CLI-0001-R02-001`
/// Fortress requirement: TF-CLI-0001-R02
#[test]
fn no_arguments_render_help() {
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status =
        fortress_cli::run(Vec::<String>::new(), &mut output, &mut error).expect("write succeeds");
    assert_eq!(status, EXIT_SUCCESS);
    assert!(String::from_utf8_lossy(&output).contains("IMPLEMENTED COMMANDS"));
    assert!(error.is_empty());
}

/// `T-TF-CLI-0001-R02-002`
/// Fortress requirement: TF-CLI-0001-R02
#[test]
fn unknown_command_is_non_success() {
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status = fortress_cli::run(["certify"], &mut output, &mut error).expect("write succeeds");
    assert_eq!(status, EXIT_USAGE);
    assert!(output.is_empty());
    assert!(String::from_utf8_lossy(&error).contains("unsupported command `certify`"));
}
