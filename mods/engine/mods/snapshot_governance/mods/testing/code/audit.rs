//! End-to-end self-application evidence for the Snapshot Governance audit.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fortress_core::audit::{
    audit_repository, compile_repository_environmental_analysis, compile_repository_psm,
    compile_repository_source_artifact_model, compile_repository_state_effect_analysis,
};

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
