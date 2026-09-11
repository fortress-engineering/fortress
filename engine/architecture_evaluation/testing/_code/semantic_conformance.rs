//! Module semantic-policy conformance fixtures.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use fortress_core::architecture_realization::reconcile_implementation;
use fortress_core::contract_coherency::{
    ContractStandardIndex, ModuleContract, compile_contract_coherency_graph,
};
use fortress_core::finding::{DefeaterKind, DefeaterStrength};
use fortress_core::finding_governance::{
    FindingGovernanceDocument, FindingLifecycle, evaluate_finding_governance,
};
use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile, observe_rust_implementation,
};
use fortress_core::program_semantics::{ProgramSemanticInput, compile_program_semantic_model};
use fortress_core::semantic_analysis::{analyze_program_domains, load_function_contracts};
use fortress_core::semantic_conformance::{
    AuthorizationState, BlockingEligibility, NO_SEMANTIC_COVERAGE, PolicyDisposition,
    SemanticConformanceEvaluation, SemanticConformanceState, TEST_ONLY_EVIDENCE,
    UNKNOWN_EXECUTION_PROVENANCE, evaluate_semantic_conformance,
};
use fortress_core::state_effect_analysis::{analyze_state_effects, load_state_contracts};

const EDITION: &str = "1.0.0-draft.1";
static NEXT_CHECKOUT: AtomicU64 = AtomicU64::new(0);

struct CoverageCheckout(PathBuf);

impl CoverageCheckout {
    fn new(label: &str) -> Self {
        let sequence = NEXT_CHECKOUT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fortress-semantic-coverage-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("checkout root creates");
        Self(path)
    }

    fn write(&self, relative: &str, bytes: &[u8]) {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("checkout parent creates");
        }
        fs::write(path, bytes).expect("checkout file writes");
    }

    fn read(&self, relative: &str) -> Vec<u8> {
        fs::read(self.0.join(relative)).expect("checkout file reads")
    }
}

impl Drop for CoverageCheckout {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("checkout removes");
    }
}

fn canonical_contract(document: serde_json::Value) -> String {
    let contract: ModuleContract = serde_json::from_value(document).expect("contract shape parses");
    contract.to_canonical_json().expect("contract serializes")
}

fn root_contract() -> String {
    canonical_contract(serde_json::json!({
        "$schema": "urn:fortress:schema:v2:module-contract",
        "schema_version": 2,
        "id": "PF-SEMANTIC-FIXTURE",
        "display_name": "Semantic Fixture",
        "ecosystem": {
            "repository_grammar": 1,
            "standard": {
                "id": "STD-FORTRESS-ENGINEERING",
                "edition": "1.0.0-draft.1"
            }
        },
        "provides": [],
        "requires": [],
        "relationships": [],
        "constraints": [],
        "guarantees": [],
        "features": [],
        "behavior": []
    }))
}

fn module_contract(
    id: &str,
    capability_allow: &[&str],
    capability_deny: &[&str],
    effect_allow: &[&str],
    effect_deny: &[&str],
) -> String {
    canonical_contract(serde_json::json!({
        "$schema": "urn:fortress:schema:v3:module-contract",
        "schema_version": 3,
        "id": id,
        "display_name": id,
        "provides": [],
        "requires": [],
        "relationships": [],
        "constraints": [],
        "guarantees": [],
        "features": [],
        "behavior": [],
        "semantic_policy": {
            "default": "UNDECLARED",
            "capabilities": {
                "allow": capability_allow,
                "deny": capability_deny
            },
            "effects": {
                "allow": effect_allow,
                "deny": effect_deny
            }
        }
    }))
}

fn evaluate(source: &str, contract: String) -> SemanticConformanceEvaluation {
    let files = BTreeMap::from([
        ("contract.json".to_owned(), root_contract().into_bytes()),
        (
            "sample/contract.json".to_owned(),
            contract.into_bytes(),
        ),
        (
            "sample/_data/Cargo.toml".to_owned(),
            b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n"
                .to_vec(),
        ),
        (
            "sample/_code/lib.rs".to_owned(),
            source.as_bytes().to_vec(),
        ),
    ]);
    evaluate_files(&files)
}

fn evaluate_files(files: &BTreeMap<String, Vec<u8>>) -> SemanticConformanceEvaluation {
    let standard =
        ContractStandardIndex::new("STD-FORTRESS-ENGINEERING", EDITION, ["ARCH-SEMANTIC-001"]);
    let compilation = compile_contract_coherency_graph(files, &standard, None);
    let ccg = compilation
        .graph()
        .unwrap_or_else(|| panic!("fixture CCG compiles: {:#?}", compilation.violations()));
    let territories = ccg
        .modules()
        .iter()
        .map(|(id, module)| ModuleTerritory::new(id, module.path()))
        .collect();
    let input = ImplementationObservationInput::new(
        "sha256:semantic-conformance-fixture",
        files
            .iter()
            .map(|(path, bytes)| SnapshotBoundFile::from_bytes(path, bytes.clone()))
            .collect(),
        territories,
    );
    let observed = observe_rust_implementation(&input).expect("implementation observes");
    let ownerships = input.ownerships().to_vec();
    let psm = compile_program_semantic_model(&ProgramSemanticInput::new(
        "PF-SEMANTIC-FIXTURE",
        input,
        Vec::<String>::new(),
        observed.module_dependencies().iter().map(|dependency| {
            (
                dependency.source_module().to_owned(),
                dependency.target_module().to_owned(),
            )
        }),
    ))
    .expect("PSM compiles");
    let functions = load_function_contracts(&psm, Vec::new()).expect("empty functions load");
    let semantic = analyze_program_domains(&psm, &functions, EDITION).expect("domains analyze");
    let states = load_state_contracts(&psm, Vec::new()).expect("empty states load");
    let state_effect = analyze_state_effects(&psm, &semantic, &states, &functions, EDITION)
        .expect("effects analyze");
    let realization =
        reconcile_implementation(ccg, &observed, EDITION).expect("realization reconciles");
    evaluate_semantic_conformance(
        ccg,
        &psm,
        state_effect.model(),
        &realization,
        &ownerships,
        EDITION,
    )
    .expect("semantic conformance evaluates")
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R05-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R05
#[test]
fn module_contract_versions_distinguish_undeclared_and_explicit_policy() {
    let legacy = ModuleContract::from_json_str(&root_contract()).expect("v2 remains supported");
    assert!(legacy.semantic_policy().is_none());

    let source = module_contract(
        "AF-SAMPLE-0001",
        &["filesystem"],
        &["network.server"],
        &["environment.read"],
        &["environment.write", "filesystem.write"],
    );
    let current = ModuleContract::from_json_str(&source).expect("v3 policy validates");
    let policy = current.semantic_policy().expect("policy is authored");
    assert_eq!(policy.capabilities().allow(), ["filesystem"]);
    assert_eq!(
        policy.effects().deny(),
        ["environment.write", "filesystem.write"]
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R05-002`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R05
#[test]
fn semantic_policy_rejects_unknown_or_contradictory_authority() {
    let unknown = module_contract("AF-SAMPLE-0001", &["database"], &[], &[], &[]);
    assert!(ModuleContract::from_json_str(&unknown).is_err());
    let conflict = module_contract("AF-SAMPLE-0001", &["filesystem"], &["filesystem"], &[], &[]);
    assert!(ModuleContract::from_json_str(&conflict).is_err());
}

/// `T-ARCH-SEMANTIC-001-R01-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn refined_policy_preserves_allowance_and_blocks_direct_and_transitive_write() {
    let source = r#"
pub fn read_file() { let _ = std::fs::read("input"); }
pub fn write_file() { let _ = std::fs::write("output", b"x"); }
pub fn entry() { write_file(); }
"#;
    let policy = module_contract(
        "AF-SAMPLE-0001",
        &["filesystem"],
        &[],
        &[],
        &["filesystem.write"],
    );
    let first = evaluate(source, policy.clone());
    let second = evaluate(source, policy);
    let module = first
        .model()
        .module("AF-SAMPLE-0001")
        .expect("Module concludes");
    assert_eq!(module.state(), SemanticConformanceState::Fail);
    assert_eq!(module.coverage().governed_source_files(), 1);
    assert_eq!(module.coverage().analysed_source_files(), 1);
    assert_eq!(module.coverage().ratio(), Some("1/1"));
    assert!(module.observations().iter().any(|observation| {
        observation.effect().stable_id() == "filesystem.read"
            && observation.policy_disposition()
                == Some(fortress_core::semantic_conformance::PolicyDisposition::Allow)
    }));
    let writes = module
        .observations()
        .iter()
        .filter(|observation| observation.effect().stable_id() == "filesystem.write")
        .collect::<Vec<_>>();
    assert!(
        writes
            .iter()
            .any(|observation| observation.call_chain().len() == 1)
    );
    assert!(
        writes
            .iter()
            .any(|observation| observation.call_chain().len() == 2)
    );
    for symbol in writes
        .iter()
        .flat_map(|observation| observation.call_chain())
    {
        assert!(
            first
                .symbol_display_name(symbol)
                .is_some_and(|name| name.starts_with("sample::"))
        );
    }
    assert_eq!(first.findings().len(), 1);
    assert_eq!(
        writes.len(),
        2,
        "direct and transitive evidence remain visible"
    );
    assert_eq!(
        first.model().to_canonical_json().unwrap(),
        second.model().to_canonical_json().unwrap()
    );
    assert_eq!(
        first
            .findings()
            .iter()
            .map(fortress_core::finding::CanonicalFinding::finding_id)
            .collect::<Vec<_>>(),
        second
            .findings()
            .iter()
            .map(fortress_core::finding::CanonicalFinding::finding_id)
            .collect::<Vec<_>>()
    );
}

/// `T-ARCH-SEMANTIC-001-R01-005`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn test_only_forbidden_effect_remains_fail_but_is_advisory() {
    let result = evaluate(
        r#"
#[cfg(test)] mod tests {
    fn write_fixture() { let _ = std::fs::write("output", b"x"); }
    fn entry() { write_fixture(); }
}
"#,
        module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
    );
    let module = result.model().module("AF-SAMPLE-0001").unwrap();
    let claim = &module.conclusions()[0];
    assert_eq!(claim.conformance(), Some(SemanticConformanceState::Fail));
    assert_eq!(
        claim.blocking_eligibility(),
        Some(BlockingEligibility::AdvisoryOnly)
    );
    assert!(claim.defeater_refs().iter().any(|reference| {
        result.model().defeater(reference).is_some_and(|defeater| {
            defeater.kind() == DefeaterKind::EvidenceProvenanceDoubt
                && defeater.strength() == DefeaterStrength::Limiting
                && defeater.reason() == TEST_ONLY_EVIDENCE
        })
    }));
    assert_eq!(
        claim
            .evidence_provenance()
            .production_capable_observations(),
        0
    );
    assert_eq!(claim.evidence_provenance().test_only_observations(), 2);
    assert_eq!(result.findings().len(), 1);
    assert!(result.findings().iter().all(|finding| {
        finding.enforcement_eligibility()
            == fortress_core::finding::FindingEnforcementEligibility::AdvisoryOnly
            && finding.enforcement_reason() == Some(TEST_ONLY_EVIDENCE)
    }));
    assert_eq!(result.model().summary().blocking_findings(), 0);
    assert_eq!(result.model().summary().advisory_findings(), 1);
}

/// `T-ARCH-SEMANTIC-001-R01-007`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn cosmetic_parameter_drift_preserves_symbol_operation_finding_and_baseline_identity() {
    let before = evaluate(
        "fn write_file(value: &[u8]) { let _ = std::fs::write(\"output\", value); }",
        module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
    );
    let after = evaluate(
        "// source position drift\nfn write_file(renamed: &[u8]) {\n    let _ = std::fs::write(\"output\", renamed);\n}",
        module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
    );
    let before_observation = &before
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .observations()[0];
    let after_observation = &after
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .observations()[0];
    assert_eq!(
        before_observation.entry_symbol(),
        after_observation.entry_symbol()
    );
    assert_eq!(
        before_observation.operation_site_id(),
        after_observation.operation_site_id()
    );
    assert_eq!(
        before.findings()[0].finding_id(),
        after.findings()[0].finding_id()
    );
    assert_ne!(
        before.findings()[0].legacy_finding_ids(),
        after.findings()[0].legacy_finding_ids(),
        "legacy token-stream identity records the drift being migrated"
    );

    let finding = &before.findings()[0];
    let authority = serde_json::json!({
        "$schema": "urn:fortress:schema:v1:finding-governance",
        "schema_version": 1,
        "baseline": {
            "standard_id": "STD-IDENTITY-0001",
            "standard_edition": EDITION,
            "active_entries": [{
                "finding_id": finding.finding_id(),
                "rule_id": finding.rule_id(),
                "subjects": finding.entities(),
                "violation_discriminator": finding.violation_discriminator().unwrap(),
                "rationale": "accepted historical residue"
            }],
            "retired_entries": []
        },
        "exceptions": []
    });
    let authority = FindingGovernanceDocument::from_json_str(&format!(
        "{}\n",
        serde_json::to_string_pretty(&authority).unwrap()
    ))
    .unwrap();
    let governed = evaluate_finding_governance(
        after.findings(),
        Some(&authority),
        "STD-IDENTITY-0001",
        EDITION,
    )
    .unwrap();
    assert_eq!(
        governed.findings()[0].lifecycle(),
        FindingLifecycle::Baselined
    );
    assert_eq!(governed.summary().new_blocking, 0);
}

/// `T-ARCH-SEMANTIC-001-R01-008`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn meaningful_signature_change_changes_symbol_operation_and_finding_identity() {
    let before = evaluate(
        "fn write_file(value: &[u8]) { let _ = std::fs::write(\"output\", value); }",
        module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
    );
    let after = evaluate(
        "fn write_file(value: &str) { let _ = std::fs::write(\"output\", value); }",
        module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
    );
    let before_observation = &before
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .observations()[0];
    let after_observation = &after
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .observations()[0];
    assert_ne!(
        before_observation.entry_symbol(),
        after_observation.entry_symbol()
    );
    assert_ne!(
        before_observation.operation_site_id(),
        after_observation.operation_site_id()
    );
    assert_ne!(
        before.findings()[0].finding_id(),
        after.findings()[0].finding_id()
    );
}

/// `T-ARCH-SEMANTIC-001-R01-009`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn caller_fan_in_changes_evidence_without_changing_underlying_finding() {
    let before = evaluate(
        "fn site() { let _ = std::fs::write(\"output\", b\"x\"); }\nfn one() { site(); }",
        module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
    );
    let after = evaluate(
        "fn site() { let _ = std::fs::write(\"output\", b\"x\"); }\nfn one() { site(); }\nfn two() { site(); }",
        module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
    );
    assert_eq!(before.findings().len(), 1);
    assert_eq!(after.findings().len(), 1);
    assert_eq!(
        before.findings()[0].finding_id(),
        after.findings()[0].finding_id()
    );
    let before_paths = before
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .observations()
        .iter()
        .filter(|observation| observation.effect().stable_id() == "filesystem.write")
        .count();
    let after_paths = after
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .observations()
        .iter()
        .filter(|observation| observation.effect().stable_id() == "filesystem.write")
        .count();
    assert_eq!(before_paths, 2);
    assert_eq!(after_paths, 3);
}

/// `T-ARCH-SEMANTIC-001-R01-010`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn thousands_of_causal_paths_retain_one_operation_site_finding() {
    let mut source = String::from("fn site() { let _ = std::fs::write(\"output\", b\"x\"); }\n");
    for index in 0..2_000 {
        writeln!(source, "fn caller_{index:04}() {{ site(); }}").unwrap();
    }
    let started = Instant::now();
    let result = evaluate(
        &source,
        module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
    );
    assert!(started.elapsed().as_secs() < 120);
    assert_eq!(result.findings().len(), 1);
    assert_eq!(
        result
            .model()
            .module("AF-SAMPLE-0001")
            .unwrap()
            .observations()
            .iter()
            .filter(|observation| observation.effect().stable_id() == "filesystem.write")
            .count(),
        2_001
    );
}

/// `T-ARCH-SEMANTIC-001-R01-006`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn unknown_only_evidence_is_advisory_while_production_evidence_is_sufficient() {
    let unknown = evaluate(
        "#[cfg(platform(test))] fn uncertain() { let _ = std::fs::write(\"x\", b\"x\"); }",
        module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
    );
    let unknown_claim = &unknown
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .conclusions()[0];
    assert_eq!(
        unknown_claim.blocking_eligibility(),
        Some(BlockingEligibility::AdvisoryOnly)
    );
    assert!(unknown_claim.defeater_refs().iter().any(|reference| {
        unknown.model().defeater(reference).is_some_and(|defeater| {
            defeater.kind() == DefeaterKind::EvidenceProvenanceDoubt
                && defeater.reason() == UNKNOWN_EXECUTION_PROVENANCE
        })
    }));

    let mixed = evaluate(
        r#"
fn production_write() { let _ = std::fs::write("production", b"x"); }
#[cfg(test)] mod tests {
    fn test_write() { let _ = std::fs::write("test", b"x"); }
}
"#,
        module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
    );
    let mixed_claim = &mixed
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .conclusions()[0];
    assert_eq!(
        mixed_claim.blocking_eligibility(),
        Some(BlockingEligibility::BlockSupported)
    );
    assert!(mixed_claim.defeater_refs().iter().all(|reference| {
        mixed
            .model()
            .defeater(reference)
            .is_some_and(|defeater| defeater.kind() != DefeaterKind::EvidenceProvenanceDoubt)
    }));
    assert_eq!(
        mixed_claim
            .evidence_provenance()
            .production_capable_observations(),
        1
    );
    assert_eq!(
        mixed_claim.evidence_provenance().test_only_observations(),
        1
    );
    assert!(mixed.findings().iter().any(|finding| {
        finding.enforcement_eligibility()
            == fortress_core::finding::FindingEnforcementEligibility::BlockSupported
    }));
    assert!(mixed.findings().iter().any(|finding| {
        finding.enforcement_eligibility()
            == fortress_core::finding::FindingEnforcementEligibility::AdvisoryOnly
    }));
}

/// `T-ARCH-SEMANTIC-001-R01-002`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn claim_relative_uncertainty_is_unknown_without_fabricated_capability() {
    let result = evaluate(
        "pub fn invoke<F: Fn()>(f: F) { f(); } pub fn arithmetic() -> u32 { 2 + 2 }",
        module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]),
    );
    let module = result.model().module("AF-SAMPLE-0001").unwrap();
    assert_eq!(module.state(), SemanticConformanceState::Unknown);
    assert_eq!(result.model().summary().blocking_findings(), 0);
    assert_eq!(result.model().summary().not_evaluable_findings(), 1);
    assert!(result.findings().is_empty());
    assert_eq!(result.coverage_findings().len(), 1);
    let claim = &module.conclusions()[0];
    assert!(claim.defeater_refs().iter().any(|reference| {
        result.model().defeater(reference).is_some_and(|defeater| {
            defeater.kind() == DefeaterKind::UnresolvedCallPath
                && defeater.strength() == DefeaterStrength::Defeating
        })
    }));
    assert!(module.observations().iter().all(|observation| {
        observation
            .capability()
            .map(fortress_core::state_effect_analysis::EffectCapability::stable_id)
            != Some("filesystem")
    }));
}

/// `T-ARCH-SEMANTIC-001-R01-012`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn unclassified_operation_is_structured_without_fabricated_capability() {
    let result = evaluate(
        "pub fn residual() { std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst); }",
        module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]),
    );
    let claim = &result
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .conclusions()[0];
    assert_eq!(claim.conformance(), Some(SemanticConformanceState::Unknown));
    assert!(claim.defeater_refs().iter().any(|reference| {
        result.model().defeater(reference).is_some_and(|defeater| {
            defeater.kind() == DefeaterKind::UnclassifiedOperation
                && defeater.strength() == DefeaterStrength::Defeating
                && defeater.retirement_condition()
                    == fortress_core::finding::DefeaterRetirementCondition::OperationClassified
        })
    }));
    assert!(result.findings().is_empty());
    assert!(
        result
            .model()
            .module("AF-SAMPLE-0001")
            .unwrap()
            .observations()
            .iter()
            .all(|observation| observation.capability().is_none())
    );
}

/// `T-ARCH-SEMANTIC-001-R01-013`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn unsupported_qualified_call_is_structured_without_fabricated_conformance() {
    let result = evaluate(
        r"
pub trait Callable { fn invoke(); }
pub struct Thing;
impl Callable for Thing { fn invoke() {} }
pub fn qualified_call() { <Thing as Callable>::invoke(); }
",
        module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]),
    );
    let claim = &result
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .conclusions()[0];
    assert_eq!(claim.conformance(), Some(SemanticConformanceState::Unknown));
    assert!(claim.defeater_refs().iter().any(|reference| {
        result.model().defeater(reference).is_some_and(|defeater| {
            defeater.kind() == DefeaterKind::UnsupportedConstruct
                && defeater.strength() == DefeaterStrength::Defeating
                && defeater.retirement_condition()
                    == fortress_core::finding::DefeaterRetirementCondition::ConstructSupported
        })
    }));
    assert!(result.findings().is_empty());
    assert!(
        result
            .model()
            .module("AF-SAMPLE-0001")
            .unwrap()
            .observations()
            .iter()
            .all(|observation| observation.capability().is_none())
    );
}

/// `T-ARCH-SEMANTIC-001-R01-011`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn proven_production_violation_survives_unrelated_defeating_uncertainty() {
    let result = evaluate(
        r#"
pub fn write() { let _ = std::fs::write("output", b"x"); }
pub fn invoke<F: Fn()>(f: F) { f(); }
"#,
        module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
    );
    let claim = &result
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .conclusions()[0];
    assert_eq!(claim.conformance(), Some(SemanticConformanceState::Fail));
    assert_eq!(
        claim.blocking_eligibility(),
        Some(BlockingEligibility::BlockSupported)
    );
    assert!(claim.defeater_refs().iter().any(|reference| {
        result.model().defeater(reference).is_some_and(|defeater| {
            defeater.kind() == DefeaterKind::UnresolvedCallPath
                && defeater.strength() == DefeaterStrength::Defeating
        })
    }));
    assert_eq!(result.findings().len(), 1);
}

/// `T-ARCH-SEMANTIC-001-R01-003`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn panic_unsafe_and_residual_external_remain_independent_policy_targets() {
    let source = r#"
pub unsafe fn raw() {}
pub fn panic_path() { panic!("stop"); }
pub fn residual() { std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst); }
"#;
    let result = evaluate(
        source,
        module_contract(
            "AF-SAMPLE-0001",
            &[],
            &[],
            &[],
            &["external_interaction", "may_panic", "unsafe_execution"],
        ),
    );
    let targets = result
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .conclusions()
        .iter()
        .filter(|conclusion| conclusion.conformance() == Some(SemanticConformanceState::Fail))
        .map(fortress_core::semantic_conformance::SemanticPolicyConclusion::target)
        .collect::<Vec<_>>();
    assert_eq!(
        targets,
        ["external_interaction", "may_panic", "unsafe_execution"]
    );
    assert!(result.findings().len() >= 3);
}

/// `T-ARCH-SEMANTIC-001-R01-004`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R06
#[test]
fn indexed_evaluation_scales_to_one_thousand_policies_and_ten_thousand_effects() {
    let mut files = BTreeMap::new();
    files.insert("contract.json".into(), root_contract().into_bytes());
    for index in 0..1_000 {
        let id = format!("AF-STRESS-{index:04}");
        let (contract, source) = match index % 3 {
            0 => (
                module_contract(&id, &[], &["filesystem"], &[], &[]),
                "pub struct Marker;\n".to_owned(),
            ),
            1 => (
                module_contract(&id, &[], &["filesystem"], &[], &[]),
                format!("pub fn pure_{index:04}() {{}}\n"),
            ),
            _ => (
                module_contract(&id, &[], &[], &[], &["filesystem.write"]),
                format!(
                    "#[cfg(test)] pub fn write_{index:04}() {{ let _ = std::fs::write(\"x\", b\"x\"); }}\n"
                ),
            ),
        };
        files.insert(format!("m{index:04}/contract.json"), contract.into_bytes());
        files.insert(
            format!("m{index:04}/_data/Cargo.toml"),
            format!(
                "[package]\nname='stress-{index:04}'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n"
            )
            .into_bytes(),
        );
        files.insert(format!("m{index:04}/_code/lib.rs"), source.into_bytes());
    }
    files.insert(
        "sample/contract.json".into(),
        module_contract("AF-SAMPLE-0001", &["filesystem"], &[], &[], &[]).into_bytes(),
    );
    files.insert(
        "sample/_data/Cargo.toml".into(),
        b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n"
            .to_vec(),
    );
    let mut source = String::new();
    for index in 0..10_000 {
        writeln!(
            source,
            "pub fn f{index:05}() {{ let _ = std::fs::read(\"x\"); }}"
        )
        .expect("String writes cannot fail");
    }
    files.insert("sample/_code/lib.rs".into(), source.into_bytes());
    let started = Instant::now();
    let result = evaluate_files(&files);
    assert!(started.elapsed().as_secs() < 120);
    assert_eq!(result.model().summary().modules_with_policy(), 1_001);
    assert!(result.model().summary().governed_observations() >= 10_000);
    assert!(result.model().defeaters().iter().any(|defeater| {
        defeater.kind() == DefeaterKind::NoSemanticCoverage
            && defeater.strength() == DefeaterStrength::Defeating
    }));
    assert!(result.model().defeaters().iter().any(|defeater| {
        defeater.kind() == DefeaterKind::EvidenceProvenanceDoubt
            && defeater.strength() == DefeaterStrength::Limiting
    }));
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R07-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R07
#[test]
fn deny_claim_with_governed_source_and_zero_symbols_is_not_evaluable() {
    let result = evaluate(
        "pub struct Marker;",
        module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]),
    );
    let module = result.model().module("AF-SAMPLE-0001").unwrap();
    let conclusion = &module.conclusions()[0];
    assert_eq!(module.coverage().governed_source_files(), 1);
    assert_eq!(module.coverage().analysed_source_files(), 0);
    assert_eq!(module.coverage().ratio(), Some("0/1"));
    assert_eq!(module.state(), SemanticConformanceState::Unknown);
    assert_eq!(
        conclusion.conformance(),
        Some(SemanticConformanceState::Unknown)
    );
    assert_eq!(
        conclusion.blocking_eligibility(),
        Some(BlockingEligibility::NotEvaluable)
    );
    assert!(conclusion.defeater_refs().iter().any(|reference| {
        result.model().defeater(reference).is_some_and(|defeater| {
            defeater.kind() == DefeaterKind::NoSemanticCoverage
                && defeater.strength() == DefeaterStrength::Defeating
                && defeater.reason() == NO_SEMANTIC_COVERAGE
        })
    }));
    assert_eq!(result.findings().len(), 0);
    assert_eq!(result.coverage_findings().len(), 1);
    assert_eq!(result.model().summary().no_semantic_coverage_claims(), 1);

    let covered = evaluate(
        "pub fn pure() {}",
        module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]),
    );
    for evaluation in [&result, &covered] {
        for module in evaluation.model().modules() {
            for claim in module.conclusions().iter().filter(|claim| {
                claim.disposition() == PolicyDisposition::Deny
                    && claim.conformance() == Some(SemanticConformanceState::Pass)
                    && claim.coverage().governed_source_files() > 0
            }) {
                assert!(
                    claim.coverage().analysed_source_files() > 0,
                    "favorable DENY claim must reference symbol-bearing governed source"
                );
            }
        }
    }
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R07-002`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R07
#[test]
fn covered_deny_claim_preserves_current_favorable_semantics_without_violation() {
    let result = evaluate(
        "pub fn pure(value: u32) -> u32 { value + 1 }",
        module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]),
    );
    let module = result.model().module("AF-SAMPLE-0001").unwrap();
    assert_eq!(module.state(), SemanticConformanceState::Pass);
    assert_eq!(module.coverage().governed_source_files(), 1);
    assert_eq!(module.coverage().analysed_source_files(), 1);
    assert_eq!(module.coverage().ratio(), Some("1/1"));
    assert!(result.findings().is_empty());
    assert!(result.coverage_findings().is_empty());
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R07-003`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R07
#[test]
fn partial_coverage_records_distinct_symbol_bearing_source_paths() {
    let files = BTreeMap::from([
        ("contract.json".to_owned(), root_contract().into_bytes()),
        (
            "sample/contract.json".to_owned(),
            module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]).into_bytes(),
        ),
        (
            "sample/_data/Cargo.toml".to_owned(),
            b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n"
                .to_vec(),
        ),
        (
            "sample/_code/lib.rs".to_owned(),
            b"mod declarations_only; pub fn covered() {}\n".to_vec(),
        ),
        (
            "sample/_code/declarations_only.rs".to_owned(),
            b"pub struct Marker;\n".to_vec(),
        ),
    ]);
    let first = evaluate_files(&files);
    let second = evaluate_files(&files);
    let module = first.model().module("AF-SAMPLE-0001").unwrap();
    assert_eq!(module.state(), SemanticConformanceState::Pass);
    assert_eq!(module.coverage().governed_source_files(), 2);
    assert_eq!(module.coverage().analysed_source_files(), 1);
    assert_eq!(module.coverage().ratio(), Some("1/2"));
    assert!(module.defeater_refs().iter().any(|reference| {
        first.model().defeater(reference).is_some_and(|defeater| {
            defeater.kind() == DefeaterKind::PartialSemanticCoverage
                && defeater.strength() == DefeaterStrength::Limiting
        })
    }));
    assert_eq!(
        first.model().to_canonical_json().unwrap(),
        second.model().to_canonical_json().unwrap()
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R07-004`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R07
#[test]
fn policy_without_governed_source_has_no_subject_and_no_ratio() {
    let files = BTreeMap::from([
        ("contract.json".to_owned(), root_contract().into_bytes()),
        (
            "sample/contract.json".to_owned(),
            module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]).into_bytes(),
        ),
    ]);
    let result = evaluate_files(&files);
    let module = result.model().module("AF-SAMPLE-0001").unwrap();
    assert_eq!(module.state(), SemanticConformanceState::NotApplicable);
    assert_eq!(module.coverage().governed_source_files(), 0);
    assert_eq!(module.coverage().analysed_source_files(), 0);
    assert_eq!(module.coverage().ratio(), None);
    assert!(module.conclusions().iter().all(|conclusion| {
        conclusion.conformance() == Some(SemanticConformanceState::NotApplicable)
            && conclusion.coverage().ratio().is_none()
    }));
    assert!(result.coverage_findings().is_empty());
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R07-005`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R07
#[test]
fn semantic_coverage_is_checkout_root_independent() {
    fn evaluate_checkout(root: &CoverageCheckout) -> SemanticConformanceEvaluation {
        let files = [
            ("contract.json", root_contract().into_bytes()),
            (
                "sample/contract.json",
                module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]).into_bytes(),
            ),
            (
                "sample/_data/Cargo.toml",
                b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n"
                    .to_vec(),
            ),
            (
                "sample/_code/lib.rs",
                b"pub struct Marker;\n".to_vec(),
            ),
        ];
        for (relative, bytes) in &files {
            root.write(relative, bytes);
        }
        let observed = files
            .iter()
            .map(|(relative, _)| ((*relative).to_owned(), root.read(relative)))
            .collect::<BTreeMap<_, _>>();
        evaluate_files(&observed)
    }

    let first_root = CoverageCheckout::new("first-root");
    let second_root = CoverageCheckout::new("second-root");
    assert_ne!(&first_root.0, &second_root.0);
    let first = evaluate_checkout(&first_root);
    let second = evaluate_checkout(&second_root);
    let coverage = first
        .model()
        .module("AF-SAMPLE-0001")
        .expect("coverage Module")
        .coverage();
    assert_eq!(coverage.governed_source_files(), 1);
    assert_eq!(coverage.analysed_source_files(), 0);
    assert_eq!(coverage.ratio(), Some("0/1"));
    assert_eq!(
        first.model().to_canonical_json().unwrap(),
        second.model().to_canonical_json().unwrap()
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R08-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R08
#[test]
fn allow_entries_are_authorizations_with_independent_observed_usage() {
    let used = evaluate(
        "pub fn read_file() { let _ = std::fs::read(\"input\"); }",
        module_contract("AF-SAMPLE-0001", &["filesystem"], &[], &[], &[]),
    );
    let used_module = used.model().module("AF-SAMPLE-0001").unwrap();
    let authorization = &used_module.conclusions()[0];
    assert_eq!(used_module.state(), SemanticConformanceState::NotApplicable);
    assert_eq!(authorization.disposition(), PolicyDisposition::Allow);
    assert_eq!(
        authorization.authorization(),
        Some(AuthorizationState::Authorised)
    );
    assert_eq!(authorization.conformance(), None);
    assert_eq!(authorization.blocking_eligibility(), None);
    assert!(authorization.matching_observation_count() > 0);
    assert_eq!(used.model().summary().authored_authorizations(), 1);
    assert_eq!(
        used.model().summary().authorizations_with_observed_usage(),
        1
    );
    assert!(used.model().summary().authorization_observations() > 0);
    assert_eq!(used.model().summary().evaluative_deny_claims(), 0);
    assert!(used.findings().is_empty());

    let unused = evaluate(
        "pub fn pure() -> u32 { 42 }",
        module_contract("AF-SAMPLE-0001", &["filesystem"], &[], &[], &[]),
    );
    let unused_authorization = &unused
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .conclusions()[0];
    assert_eq!(
        unused_authorization.authorization(),
        Some(AuthorizationState::Authorised)
    );
    assert_eq!(unused_authorization.conformance(), None);
    assert_eq!(unused_authorization.matching_observation_count(), 0);
    assert_eq!(
        unused
            .model()
            .summary()
            .authorizations_with_observed_usage(),
        0
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R08-002`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R08
#[test]
fn allow_authorization_survives_zero_coverage_without_becoming_pass() {
    let result = evaluate(
        "pub struct Marker;",
        module_contract("AF-SAMPLE-0001", &["filesystem"], &[], &[], &[]),
    );
    let module = result.model().module("AF-SAMPLE-0001").unwrap();
    let authorization = &module.conclusions()[0];
    assert_eq!(module.coverage().ratio(), Some("0/1"));
    assert_eq!(module.state(), SemanticConformanceState::NotApplicable);
    assert_eq!(
        authorization.authorization(),
        Some(AuthorizationState::Authorised)
    );
    assert_eq!(authorization.conformance(), None);
    assert_eq!(authorization.matching_observation_count(), 0);
    assert!(result.coverage_findings().is_empty());
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R08-003`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R08
#[test]
fn module_conformance_aggregates_only_evaluative_deny_claims() {
    let result = evaluate(
        "pub fn read_file() { let _ = std::fs::read(\"input\"); } pub fn panic_path() { panic!(\"stop\"); }",
        module_contract("AF-SAMPLE-0001", &["filesystem"], &[], &[], &["may_panic"]),
    );
    let module = result.model().module("AF-SAMPLE-0001").unwrap();
    assert_eq!(module.state(), SemanticConformanceState::Fail);
    assert!(module.conclusions().iter().any(|entry| {
        entry.disposition() == PolicyDisposition::Allow
            && entry.authorization() == Some(AuthorizationState::Authorised)
            && entry.conformance().is_none()
    }));
    assert!(module.conclusions().iter().any(|entry| {
        entry.disposition() == PolicyDisposition::Deny
            && entry.conformance() == Some(SemanticConformanceState::Fail)
    }));
    assert_eq!(result.model().summary().authored_authorizations(), 1);
    assert_eq!(result.model().summary().evaluative_deny_claims(), 1);
    assert_eq!(result.model().summary().deny_claims_failed(), 1);
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R08-004`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R08
#[test]
fn canonical_output_never_represents_allow_as_conformance_pass() {
    let result = evaluate(
        "pub fn read_file() { let _ = std::fs::read(\"input\"); }",
        module_contract("AF-SAMPLE-0001", &["filesystem"], &[], &[], &[]),
    );
    let document: serde_json::Value =
        serde_json::from_str(&result.model().to_canonical_json().unwrap()).unwrap();
    for module in document["modules"].as_array().unwrap() {
        for entry in module["conclusions"].as_array().unwrap() {
            if entry["disposition"] == "ALLOW" {
                assert_eq!(entry["authorization"], "AUTHORISED");
                assert!(entry["conformance"].is_null());
                assert!(entry["blocking_eligibility"].is_null());
            }
        }
    }
}
