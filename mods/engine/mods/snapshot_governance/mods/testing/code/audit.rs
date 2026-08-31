//! End-to-end self-application evidence for the Snapshot Governance audit.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fortress_core::audit::{
    audit_repository, compile_repository_environmental_analysis, compile_repository_psm,
    compile_repository_source_artifact_model, compile_repository_state_effect_analysis,
    inspect_repository_modules,
};
use fortress_core::program_semantics::ExecutableSymbol;

static NEXT_REPOSITORY: AtomicU64 = AtomicU64::new(0);

struct TestRepository(PathBuf);

impl TestRepository {
    fn new(name: &str) -> Self {
        let sequence = NEXT_REPOSITORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fortress-observation-{name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("test repository must be created");
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("test parent must be created");
        }
        fs::write(path, contents).expect("test file must be written");
    }
}

fn minimal_contract(id: &str, name: &str, root: bool) -> String {
    let ecosystem = if root {
        ",\n  \"ecosystem\": {\n    \"repository_grammar\": 1,\n    \"standard\": {\n      \"id\": \"STD-FORTRESS-ENGINEERING\",\n      \"edition\": \"1.0.0-draft.1\"\n    }\n  }"
    } else {
        ""
    };
    format!(
        "{{\n  \"$schema\": \"urn:fortress:schema:v2:module-contract\",\n  \"schema_version\": 2,\n  \"id\": \"{id}\",\n  \"display_name\": \"{name}\"{ecosystem},\n  \"provides\": [],\n  \"requires\": [],\n  \"relationships\": [],\n  \"constraints\": [],\n  \"guarantees\": [],\n  \"features\": [],\n  \"behavior\": []\n}}\n"
    )
}

/// `T-LOGICAL-MODULE-INTEGRATION-001`
/// Fortress classification: infrastructure
#[test]
fn logical_contracts_and_native_paths_feed_one_semantic_ownership_relation() {
    let repository = TestRepository::new("logical-module");
    repository.write(
        "Cargo.toml",
        "[package]\nname='native'\nversion='0.1.0'\nedition='2021'\n[lib]\npath='src/lib.rs'\n",
    );
    repository.write(
        "contract.json",
        &minimal_contract("PF-FIXTURE", "Fixture", true),
    );
    repository.write(
        "data/project.json",
        "{\n  \"$schema\": \"urn:fortress:schema:v3:project-configuration\",\n  \"schema_version\": 3,\n  \"observation_exclusions\": [\n    \".git\"\n  ],\n  \"logical_modules\": [\n    {\n      \"module\": \"AF-API-0001\",\n      \"contract\": \"data/logical_modules/api/contract.json\",\n      \"parent\": \"PF-FIXTURE\",\n      \"bindings\": [\n        {\n          \"kind\": \"directory\",\n          \"path\": \"src/api\"\n        }\n      ]\n    },\n    {\n      \"module\": \"AF-CORE-0001\",\n      \"contract\": \"data/logical_modules/core/contract.json\",\n      \"parent\": \"PF-FIXTURE\",\n      \"bindings\": [\n        {\n          \"kind\": \"directory\",\n          \"path\": \"src/core\"\n        }\n      ]\n    }\n  ]\n}\n",
    );
    repository.write(
        "data/logical_modules/api/contract.json",
        &minimal_contract("AF-API-0001", "API", false),
    );
    repository.write(
        "data/logical_modules/core/contract.json",
        &minimal_contract("AF-CORE-0001", "Core", false),
    );
    repository.write(
        "src/lib.rs",
        "pub mod api;\npub mod core;\npub mod utility;\n",
    );
    repository.write("src/api/mod.rs", "pub fn submit() {}\n");
    repository.write("src/core/mod.rs", "pub fn calculate() {}\n");
    repository.write("src/utility.rs", "pub fn utility() {}\n");

    let inspection = inspect_repository_modules(repository.path()).expect("Modules inspect");
    assert_eq!(inspection.modules().len(), 3);
    assert_eq!(
        inspection
            .modules()
            .iter()
            .find(|module| module.module() == "AF-API-0001")
            .expect("API Module")
            .observed_sources(),
        1
    );
    assert_eq!(inspection.analysis_territories().len(), 1);
    assert_eq!(inspection.analysis_territories()[0].observed_sources(), 2);

    let psm = compile_repository_psm(repository.path()).expect("logical PSM compiles");
    let owners = psm
        .symbols()
        .iter()
        .map(ExecutableSymbol::fortress_module)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(owners.contains("AF-API-0001"));
    assert!(owners.contains("AF-CORE-0001"));
    assert!(
        owners
            .iter()
            .any(|owner| owner.starts_with("SRC-ANALYSIS-CARGO-"))
    );

    let source = compile_repository_source_artifact_model(repository.path())
        .expect("logical Source Artifact Model compiles");
    let document: serde_json::Value = serde_json::from_str(
        &source
            .to_canonical_json()
            .expect("Source Artifact Model serializes"),
    )
    .expect("Source Artifact Model parses");
    assert!(document["artifacts"].as_array().is_some_and(|artifacts| {
        artifacts
            .iter()
            .any(|artifact| artifact["module_id"] == "AF-API-0001")
            && artifacts
                .iter()
                .any(|artifact| artifact["module_id"] == "AF-CORE-0001")
    }));
}

impl Drop for TestRepository {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("test repository must be removed");
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R08-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R08
#[test]
fn fortress_self_audit_passes_every_implemented_rule() {
    let result = audit_repository(repository_root()).expect("Fortress self-audit completes");
    assert!(result.is_success());
    assert_eq!(result.summary().rules_evaluated(), 22);
    assert_eq!(result.summary().passed(), 22);
    assert_eq!(result.summary().failed(), 0);
    assert_eq!(result.summary().unsupported(), 0);
    assert!(result.findings().is_empty());
    assert!(
        result
            .unsupported_analysis()
            .contains(&"capability_to_symbol_realization".to_owned())
    );
    assert_eq!(result.is_success(), result.findings().is_empty());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R14-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R14
#[test]
fn filesystem_boundary_success_and_failure_scenarios_are_current() {
    let evaluation = compile_repository_environmental_analysis(repository_root())
        .expect("self environmental analysis compiles");
    let ids = evaluation
        .model()
        .failure_test_obligations()
        .iter()
        .map(|obligation| {
            serde_json::to_value(obligation).expect("obligation serializes")["id"]
                .as_str()
                .expect("obligation ID")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, ["SCN-5A016EDD618E626E", "SCN-E881A0DBF2A76CE4"]);
    assert!(evaluation.environment_findings().is_empty());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R13-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R13
#[test]
fn self_audit_reuses_one_applicable_intended_behavior_evaluation() {
    let result = audit_repository(repository_root()).expect("Fortress self-audit completes");
    let executions = result
        .rules()
        .iter()
        .filter(|rule| rule.rule_id() == "BEHAVIOR-FLOW-001")
        .collect::<Vec<_>>();
    assert_eq!(executions.len(), 1);
    assert!(executions[0].applicable());
    assert_eq!(executions[0].finding_count(), 0);
    assert!(executions[0].detail().contains("1 modeled Feature"));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R08-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R08
#[test]
fn ungoverned_cargo_repository_reaches_semantic_observation_without_admission_files() {
    let repository = TestRepository::new("ungoverned-cargo");
    repository.write(
        "Cargo.toml",
        "[package]\nname='ordinary'\nversion='0.1.0'\nedition='2021'\n[lib]\npath='src/lib.rs'\n",
    );
    repository.write(
        "src/lib.rs",
        "pub mod runtime;\npub fn run(value: bool) -> bool { runtime::flip(value) }\n",
    );
    repository.write(
        "src/runtime/mod.rs",
        "pub fn flip(value: bool) -> bool { !value }\n",
    );
    repository.write("tests/plain.rs", "#[test]\nfn ordinary_test() {}\n");

    let psm =
        compile_repository_psm(repository.path()).expect("PSM observes ordinary Cargo layout");
    assert_eq!(psm.project_id(), None);
    let psm_json: serde_json::Value =
        serde_json::from_str(&psm.to_canonical_json().expect("PSM serializes"))
            .expect("PSM JSON parses");
    assert_eq!(psm_json["coverage"]["source_files"], 2);
    assert!(
        psm.symbols()
            .iter()
            .any(|symbol| symbol.qualified_name().ends_with("::flip"))
    );
    assert!(
        psm.symbols()
            .iter()
            .all(|symbol| symbol.fortress_module().starts_with("SRC-ANALYSIS-CARGO-"))
    );

    let source = compile_repository_source_artifact_model(repository.path())
        .expect("Source Architecture observes ordinary Cargo layout");
    let source_json: serde_json::Value =
        serde_json::from_str(&source.to_canonical_json().expect("source model serializes"))
            .expect("source model JSON parses");
    assert!(source_json["project_id"].is_null());
    assert_eq!(
        source_json["artifacts"]
            .as_array()
            .expect("artifacts")
            .len(),
        3
    );

    let state = compile_repository_state_effect_analysis(repository.path())
        .expect("State/Effect analysis consumes the observation-only PSM");
    assert!(state.model().coverage().functions() >= 2);

    let audit = audit_repository(repository.path())
        .expect("audit reports missing governance after semantic observation");
    assert!(!audit.is_success());
    let audit_json: serde_json::Value =
        serde_json::from_str(&audit.to_json_pretty().expect("audit serializes"))
            .expect("audit JSON parses");
    assert_eq!(audit_json["outcome"], "MISSING");
    assert_eq!(audit_json["governance"]["project_authority"], "ABSENT");
    assert_eq!(
        audit_json["governance"]["standard_authority"],
        "INSTALLED_UNBOUND"
    );
    assert_eq!(audit_json["governance"]["tests_missing_stable_id"], 1);
    assert!(
        audit_json["observation"]["psm_symbols"]
            .as_u64()
            .is_some_and(|count| count >= 2)
    );
}
