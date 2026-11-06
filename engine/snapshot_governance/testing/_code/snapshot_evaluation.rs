//! Repository-level evidence for truthful Snapshot Governance rule execution.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use fortress_core::architecture::{ArchitectureManifest, ComponentDeclaration};
use fortress_core::audit::audit_repository;
use fortress_core::evaluation::RuleExecutionState;
use serde::Deserialize;

#[derive(Deserialize)]
struct ArchitectureWire {
    components: Vec<ComponentWire>,
}

#[derive(Deserialize)]
struct ComponentWire {
    id: String,
    title: String,
    paths: Vec<String>,
    depends_on: Vec<String>,
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// These read-only assertions inspect the same immutable fresh fixture.
// Independent generator, cold/determinism, and mutation controls still execute
// their own evaluations; this fixture does not substitute for those controls.
fn self_audit() -> &'static fortress_core::audit::AuditResult {
    static AUDIT: OnceLock<fortress_core::audit::AuditResult> = OnceLock::new();
    AUDIT.get_or_init(|| audit_repository(repository_root()).expect("self audit completes"))
}

fn no_policy_audit() -> &'static fortress_core::audit::AuditResult {
    static AUDIT: OnceLock<fortress_core::audit::AuditResult> = OnceLock::new();
    AUDIT.get_or_init(|| {
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("temporary root resolves");
        let root = parent.join(format!("fortress-no-policy-{}", std::process::id()));
        fs::create_dir(&root).expect("no-policy fixture is exclusively created");
        fs::create_dir(root.join("__fortress")).expect("fixture governance root creates");
        fs::write(
            root.join("__fortress/.fsconfig"),
            concat!(
                "{\n  \"$schema\": \"urn:fortress:schema:v3:project-configuration\",\n",
                "  \"schema_version\": 3,\n  \"observation_exclusions\": [],\n",
                "  \"logical_modules\": []\n}\n"
            ),
        )
        .expect("fixture explicitly selects governance");
        fs::write(
            root.join("contract.json"),
            concat!(
                "{\n  \"$schema\": \"urn:fortress:schema:v2:module-contract\",\n",
                "  \"schema_version\": 2,\n  \"id\": \"PF-NO-POLICY\",\n",
                "  \"display_name\": \"No policy fixture\",\n",
                "  \"ecosystem\": {\n    \"repository_grammar\": 1,\n",
                "    \"standard\": {\n      \"id\": \"STD-FORTRESS-ENGINEERING\",\n",
                "      \"edition\": \"1.0.0-draft.2\"\n    }\n  },\n",
                "  \"provides\": [],\n  \"requires\": [],\n  \"relationships\": [],\n",
                "  \"constraints\": [],\n  \"guarantees\": [],\n",
                "  \"features\": [],\n  \"behavior\": []\n}\n"
            ),
        )
        .expect("no-policy contract writes");
        let audit = audit_repository(&root);
        let resolved = root.canonicalize().expect("owned fixture resolves");
        assert_eq!(resolved.parent(), Some(parent.as_path()));
        assert_eq!(resolved.file_name(), root.file_name());
        fs::remove_dir_all(&resolved).expect("owned no-policy fixture is removed");
        audit.expect("no-policy audit completes")
    })
}

fn invalid_architecture() -> ArchitectureManifest {
    let path = repository_root()
        .join("engine/architecture_evaluation/testing/_data/dependency_invalid.json");
    let source = fs::read_to_string(path).expect("negative fixture reads");
    let wire: ArchitectureWire = serde_json::from_str(&source).expect("fixture parses");
    ArchitectureManifest::from_components(
        wire.components
            .into_iter()
            .map(|component| {
                ComponentDeclaration::new(
                    component.id,
                    component.title,
                    component.paths,
                    component.depends_on,
                )
            })
            .collect(),
    )
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R04-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R04
#[test]
fn registered_architecture_evaluator_distinguishes_pass_and_failure() {
    let audit = self_audit();
    let execution = audit
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "ARCH-DEPENDENCY-001")
        .expect("dependency rule executes");
    assert_eq!(execution.state(), RuleExecutionState::Passed);

    let finding = invalid_architecture()
        .evaluate_acyclic_dependencies("1.0.0-draft.1")
        .expect("negative evaluation completes");
    assert!(finding.is_some());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R04-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R04
#[test]
fn stable_identity_rule_uses_loaded_canonical_identity_evidence() {
    let audit = self_audit();
    let execution = audit
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "STD-ID-001")
        .expect("STD-ID-001 execution is reported");
    assert_eq!(execution.state(), RuleExecutionState::Passed);
    assert_eq!(execution.finding_count(), 0);
    assert_eq!(audit.summary().unsupported(), 0);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R06-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R06
#[test]
fn fortress_active_requirements_have_complete_snapshot_bound_rust_evidence() {
    let audit = self_audit();
    let execution = audit
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "TEST-TRACEABILITY-001")
        .expect("traceability execution is reported");
    assert_eq!(execution.state(), RuleExecutionState::Passed);
    assert_eq!(execution.finding_count(), 0);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R11-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R11
#[test]
fn contract_coherency_passes_without_overclaiming_semantic_closure() {
    let audit = self_audit();
    let execution = audit
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "CONTRACT-COHERENCY-001")
        .expect("contract coherency execution is reported");
    assert_eq!(execution.state(), RuleExecutionState::Passed);
    assert_eq!(execution.finding_count(), 0);
    assert!(
        execution
            .detail()
            .contains("arbitrary_natural_language_requirement_contradiction")
    );
    assert!(
        execution
            .detail()
            .contains("source_code_dependency_realization")
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R12-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R12
#[test]
fn recursive_testing_boundaries_pass_for_fortress_itself() {
    let audit = self_audit();
    let execution = audit
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "TEST-BOUNDARY-001")
        .expect("testing-boundary execution is reported");
    assert_eq!(execution.state(), RuleExecutionState::Passed);
    assert_eq!(execution.finding_count(), 0);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R04-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R04
#[test]
fn non_applicable_rule_has_canonical_state_and_reason() {
    let audit = no_policy_audit();
    let execution = audit
        .rules()
        .iter()
        .find(|execution| execution.rule_id() == "ARCH-SEMANTIC-001")
        .expect("semantic rule execution is reported");
    assert!(!execution.applicable());
    assert_eq!(execution.state(), RuleExecutionState::NotApplicable);
    assert_eq!(
        execution.applicability_reason(),
        Some("NO_EVALUATIVE_MODULE_SEMANTIC_POLICY")
    );
    assert!(
        audit
            .to_human()
            .contains("[ARCH-SEMANTIC-001] NOT_APPLICABLE: NO_EVALUATIVE_MODULE_SEMANTIC_POLICY")
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R04-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R04
#[test]
fn canonical_audit_never_serializes_non_applicable_as_passed() {
    let audit = no_policy_audit();
    let document: serde_json::Value =
        serde_json::from_str(&audit.to_json_pretty().unwrap()).expect("audit JSON parses");
    let rules = document["rules"].as_array().expect("rules array");
    assert!(audit.summary().not_applicable() > 0);
    for rule in rules {
        if rule["applicable"] == false {
            assert_eq!(rule["state"], "NOT_APPLICABLE");
            assert!(rule["applicability_reason"].as_str().is_some());
        }
    }
    assert_eq!(
        audit.summary().rules_evaluated()
            + audit.summary().unsupported()
            + audit.summary().not_applicable(),
        rules.len()
    );
    assert_eq!(
        audit.summary().passed() + audit.summary().failed(),
        audit.summary().rules_evaluated()
    );
}
