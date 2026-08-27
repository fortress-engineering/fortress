//! Process-level evidence for the canonical Fortress CLI entrypoints.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

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
    fn new() -> Self {
        let identity = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fortress-cli-audit-{}-{identity}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("fixture root creates");
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        fs::write(root.join("README.md"), "# Fixture\n").expect("root README writes");
        fs::create_dir_all(root.join("data")).expect("root data creates");
        fs::create_dir_all(root.join("docs")).expect("root docs creates");
        fs::write(root.join("docs/data_docs.md"), "# Fixture Data\n")
            .expect("root data documentation writes");
        fs::create_dir_all(root.join("mods/engine/mods")).expect("engine Module creates");
        fs::write(root.join("mods/engine/README.md"), "# Engine\n").expect("engine README writes");
        for module in [
            "standard_registry",
            "architecture_evaluation",
            "snapshot_governance",
        ] {
            let module_root = root.join("mods/engine/mods").join(module);
            fs::create_dir_all(module_root.join("code")).expect("Module code creates");
            fs::create_dir_all(module_root.join("data")).expect("Module data creates");
            fs::create_dir_all(module_root.join("docs")).expect("Module docs creates");
            fs::write(module_root.join("README.md"), format!("# {module}\n"))
                .expect("Module README writes");
            fs::write(module_root.join("code/marker.txt"), "fixture")
                .expect("Module code marker writes");
            fs::write(module_root.join("docs/code_docs.md"), "# Code\n")
                .expect("Module code documentation writes");
            fs::write(module_root.join("docs/data_docs.md"), "# Data\n")
                .expect("Module data documentation writes");
        }
        for relative in [
            "mods/engine/mods/standard_registry/data/standard_manifest.json",
            "mods/engine/mods/standard_registry/data/std_id_rule.json",
            "mods/engine/mods/architecture_evaluation/data/dependency_rule.json",
            "mods/engine/mods/snapshot_governance/data/ownership_rule.json",
            "mods/engine/mods/snapshot_governance/data/traceability_rule.json",
            "mods/engine/mods/snapshot_governance/data/module_rule.json",
        ] {
            fs::copy(repository.join(relative), root.join(relative)).expect("standard file copies");
        }
        fs::write(root.join("data/project.json"), project_json()).expect("project writes");
        fs::write(root.join("data/architecture.json"), architecture_json())
            .expect("architecture writes");
        fs::write(root.join("data/features.json"), feature_json()).expect("features write");
        Self { root }
    }

    fn argument(&self) -> String {
        self.root.to_string_lossy().into_owned()
    }
}

impl Drop for AuditFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn project_json() -> &'static str {
    r#"{
      "$schema":"urn:fortress:schema:v1:project","schema_version":1,
      "id":"PF-FIXTURE","name":"Fixture",
      "standard":{"id":"STD-FORTRESS-ENGINEERING","edition":"1.0.0-draft.1","status":"draft","digest":null,"manifest":"mods/engine/mods/standard_registry/data/standard_manifest.json"},
      "archetypes":["package.library"],"capabilities":[],"languages":["rust"],
      "model":{"architecture":"data/architecture.json","features":["data/features.json"],"commands":"data/commands.json","certifications":"data/certification.json","active_changes":[],"observation_exclusions":[".git"]}
    }"#
}

fn architecture_json() -> &'static str {
    r#"{
      "$schema":"urn:fortress:schema:v1:architecture","schema_version":1,"zones":["core"],
      "components":[{"id":"AF-MODEL-0001","title":"Model","zone":"core","paths":["README.md","data/","docs/","mods/"],"depends_on":[]}]
    }"#
}

fn feature_json() -> &'static str {
    r#"{
      "$schema":"urn:fortress:schema:v1:feature","schema_version":1,
      "features":[{"id":"AF-FIXTURE-0001","title":"Fixture","status":"active","parent":null,"owner":"AF-MODEL-0001","zone":"core","owned_paths":["mods/"],"dependencies":[],"requirements":[]}]
    }"#
}

/// `T-TF-CLI-0001-R03-001`
#[test]
fn version_flag_reports_implementation_identity() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "fortress 0.1.0\n");
    assert!(output.stderr.is_empty());
}

/// `T-TF-CLI-0001-R03-002`
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
#[test]
fn unsupported_certification_command_fails() {
    let output = run(&["certify"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported command `certify`"));
}

/// `T-TF-CLI-0001-R03-004`
#[test]
fn version_rejects_extra_arguments() {
    let output = run(&["--version", "unexpected"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage: fortress --version"));
}

/// `T-TF-CLI-0001-R04-001`
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
    assert!(stdout.contains("PASS: 4"));
    assert!(stdout.contains("Unsupported: 1"));
    assert!(!stdout.contains("certification"));
}

/// `T-TF-CLI-0001-R04-002`
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
#[test]
fn audit_malformed_project_state_is_non_success() {
    let fixture = AuditFixture::new();
    fs::write(fixture.root.join("data/project.json"), "{").expect("project corrupts");
    let output = run_owned(&["audit".into(), fixture.argument()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid project state"));
}

/// `T-TF-CLI-0001-R04-004`
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
#[test]
fn audit_rejects_unsupported_options() {
    let output = run(&["audit", "--format", "xml"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("human` or `json"));
}
