//! Module semantic-policy conformance fixtures.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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
    AuthoredClaimScope, AuthorizationState, BlockingEligibility, NO_SEMANTIC_COVERAGE,
    PolicyDisposition, PolicyTargetKind, SemanticConformanceEvaluation, SemanticConformanceState,
    TEST_ONLY_EVIDENCE, UNKNOWN_EXECUTION_PROVENANCE, evaluate_semantic_conformance_with_scopes,
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
    evaluate_with_scope(source, contract, None)
}

fn evaluate_with_scope(
    source: &str,
    contract: String,
    selected_entry: Option<&str>,
) -> SemanticConformanceEvaluation {
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
    evaluate_files_with_scope(&files, selected_entry)
}

fn evaluate_files(files: &BTreeMap<String, Vec<u8>>) -> SemanticConformanceEvaluation {
    evaluate_files_with_scope(files, None)
}

fn evaluate_files_with_scope(
    files: &BTreeMap<String, Vec<u8>>,
    selected_entry: Option<&str>,
) -> SemanticConformanceEvaluation {
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
    let scopes = selected_entry.map_or_else(Vec::new, |suffix| {
        let entry = psm
            .symbols()
            .iter()
            .find(|symbol| symbol.qualified_name().ends_with(suffix))
            .expect("selected entry exists");
        vec![
            AuthoredClaimScope::new(
                "AF-SAMPLE-0001",
                PolicyTargetKind::Capability,
                "filesystem",
                [entry.id().to_owned()],
                "sha256:fixture-profile",
            )
            .expect("fixture scope"),
        ]
    });
    evaluate_semantic_conformance_with_scopes(
        ccg,
        &psm,
        state_effect.model(),
        &realization,
        &ownerships,
        EDITION,
        &scopes,
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
    assert_eq!(module.state(), SemanticConformanceState::SupportedViolation);
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
    assert_eq!(
        claim.conformance(),
        Some(SemanticConformanceState::SupportedViolation)
    );
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

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R05-003`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R05
#[test]
fn production_witness_order_does_not_change_enforcement() {
    let sources = [
        r#"
fn site() { let _ = std::fs::write("output", b"x"); }
pub fn production_entry() { site(); }
#[cfg(test)] mod tests {
    pub fn test_entry() { super::site(); }
}

"#,
        r#"
fn site() { let _ = std::fs::write("output", b"x"); }
#[cfg(test)] mod tests {
    pub fn test_entry() { super::site(); }
}
pub fn production_entry() { site(); }

"#,
    ];
    let mut finding_ids = BTreeSet::new();
    for source in sources {
        let result = evaluate(
            source,
            module_contract("AF-SAMPLE-0001", &[], &[], &[], &["filesystem.write"]),
        );
        let module = result.model().module("AF-SAMPLE-0001").unwrap();
        let paths = module
            .observations()
            .iter()
            .filter(|observation| observation.effect().stable_id() == "filesystem.write")
            .collect::<Vec<_>>();
        assert!(paths.iter().any(|observation| {
            observation.entry_execution_provenance()
                == fortress_core::program_semantics::ExecutionProvenance::ProductionCapable
        }));
        assert!(paths.iter().any(|observation| {
            observation.entry_execution_provenance()
                == fortress_core::program_semantics::ExecutionProvenance::TestOnly
        }));
        assert_eq!(result.findings().len(), 1);
        assert_eq!(result.model().summary().blocking_findings(), 1);
        assert_eq!(result.model().summary().advisory_findings(), 0);
        let graph = module.conclusions()[0]
            .evaluation()
            .proof_graph()
            .expect("witness alternatives");
        assert_eq!(graph.nodes.len(), paths.len() + 1);
        assert_eq!(
            result.findings()[0].enforcement_eligibility(),
            fortress_core::finding::FindingEnforcementEligibility::BlockSupported
        );
        finding_ids.insert(result.findings()[0].finding_id().to_owned());
    }
    assert_eq!(finding_ids.len(), 1);
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R05-004`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R05
#[test]
fn capability_effect_override_matrix_is_total() {
    let source = "pub fn write() { let _ = std::fs::write(\"out\", b\"x\"); }\n";
    let policy = module_contract(
        "AF-SAMPLE-0001",
        &[],
        &["filesystem"],
        &[],
        &["filesystem.write"],
    );
    let result = evaluate(source, policy);
    let module = result.model().module("AF-SAMPLE-0001").unwrap();
    let capability = module
        .conclusions()
        .iter()
        .find(|claim| claim.target() == "filesystem")
        .unwrap();
    let effect = module
        .conclusions()
        .iter()
        .find(|claim| claim.target() == "filesystem.write")
        .unwrap();
    // The capability still governs filesystem.read; the effect entry governs
    // filesystem.write. Neither declaration creates an empty favorable claim.
    assert_eq!(capability.matching_observation_count(), 0);
    assert_eq!(
        capability.conformance(),
        Some(SemanticConformanceState::NoSupportedViolation)
    );
    assert_eq!(
        effect.conformance(),
        Some(SemanticConformanceState::SupportedViolation)
    );
    let policy = module.effective_policy().expect("policy compiles");
    let capability_entry = policy
        .entries()
        .iter()
        .find(|entry| entry.target() == "filesystem")
        .unwrap();
    assert_eq!(capability_entry.status().as_str(), "PARTIALLY_OVERRIDDEN");
    assert_eq!(capability_entry.effective_effects(), ["filesystem.read"]);
    assert_eq!(result.findings().len(), 1);

    let reversed = evaluate(
        source,
        module_contract(
            "AF-SAMPLE-0001",
            &["filesystem"],
            &[],
            &["filesystem.read"],
            &["filesystem.write"],
        ),
    );
    let policy = reversed
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .effective_policy()
        .unwrap();
    assert_eq!(
        policy
            .entries()
            .iter()
            .find(|entry| entry.target() == "filesystem")
            .unwrap()
            .status()
            .as_str(),
        "OVERRIDDEN"
    );
    assert_eq!(
        policy
            .entries()
            .iter()
            .find(|entry| entry.target() == "filesystem")
            .unwrap()
            .effective_effects()
            .len(),
        0
    );
    assert!(
        reversed
            .model()
            .module("AF-SAMPLE-0001")
            .unwrap()
            .conclusions()
            .iter()
            .all(|claim| claim.target() != "filesystem")
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R05-006`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R05
#[test]
fn claim_slot_survives_disposition_change_but_instance_does_not() {
    let source = "pub fn pure() {}";
    let allow = evaluate(
        source,
        module_contract("AF-SAMPLE-0001", &["filesystem"], &[], &[], &[]),
    );
    let deny = evaluate(
        source,
        module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]),
    );
    let authorized = &allow
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .conclusions()[0];
    let evaluated = &deny.model().module("AF-SAMPLE-0001").unwrap().conclusions()[0];
    assert_eq!(authorized.slot().id(), evaluated.slot().id());
    assert_ne!(authorized.instance().id(), evaluated.instance().id());
    assert_eq!(authorized.conformance(), None);
    assert_eq!(
        evaluated.conformance(),
        Some(SemanticConformanceState::NoSupportedViolation)
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R05-007`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R05
#[test]
fn operation_inventory_barrier_limits_favorable_claim() {
    let result = evaluate(
        "pub fn hidden() { mystery!(); }",
        module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]),
    );
    let claim = &result
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .conclusions()[0];
    assert_eq!(
        claim.conformance(),
        Some(SemanticConformanceState::NotEvaluable)
    );
    assert!(claim.defeater_refs().iter().any(|id| {
        result.model().defeater(id).is_some_and(|defeater| {
            defeater.kind() == DefeaterKind::AnalyserLimit
                && defeater
                    .detail()
                    .get("uncertainty")
                    .is_some_and(|reason| reason.starts_with("analyser_limit:syntax_inventory:"))
        })
    }));
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R05-008`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R05
#[test]
fn unrelated_opacity_does_not_poison_explicit_scope() {
    let source = "pub fn pure() {} pub fn opaque() { mystery!(); } pub fn reaches() { opaque(); }";
    let contract = module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]);
    let whole = evaluate(source, contract.clone());
    let pure = evaluate_with_scope(source, contract.clone(), Some("pure"));
    let reachable = evaluate_with_scope(source, contract, Some("reaches"));
    assert_eq!(
        whole.model().module("AF-SAMPLE-0001").unwrap().state(),
        SemanticConformanceState::NotEvaluable
    );
    assert_eq!(
        pure.model().module("AF-SAMPLE-0001").unwrap().state(),
        SemanticConformanceState::NoSupportedViolation
    );
    assert_eq!(
        reachable.model().module("AF-SAMPLE-0001").unwrap().state(),
        SemanticConformanceState::NotEvaluable
    );
    let whole_slot = whole
        .model()
        .module("AF-SAMPLE-0001")
        .unwrap()
        .conclusions()[0]
        .slot()
        .id();
    let pure_slot = pure.model().module("AF-SAMPLE-0001").unwrap().conclusions()[0]
        .slot()
        .id();
    assert_ne!(
        whole_slot, pure_slot,
        "authored scope is part of claim identity"
    );
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R05-009`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R05
#[test]
fn semantic_v7_model_validates_against_advertised_schema() {
    let result = evaluate(
        "pub fn write() { let _ = std::fs::write(\"out\", b\"x\"); }",
        module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]),
    );
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../architecture_evaluation/_data/semantic_conformance_schema_v7.json");
    let schema: serde_json::Value =
        serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
    let model: serde_json::Value =
        serde_json::from_str(&result.model().to_canonical_json().unwrap()).unwrap();
    jsonschema::draft202012::validate(&schema, &model).expect("v7 model validates");
    let claim = &model["modules"][0]["conclusions"][0];
    assert_eq!(claim["instance_ref"], claim["instance"]["id"]);
    assert_eq!(claim["slot"]["id"], claim["instance"]["slot_id"]);
}

fn fixture_count(value: &serde_json::Value) -> usize {
    usize::try_from(value.as_u64().expect("fixture count is unsigned"))
        .expect("fixture count fits the host")
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R05-005`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R05
#[test]
#[allow(clippy::too_many_lines)]
fn qualification_corpus_replays_authored_cases() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/_data/qualification_cases.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("qualification corpus reads"))
            .expect("qualification corpus parses");
    let ledger_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/_data/regression_ledger.json");
    let ledger: serde_json::Value =
        serde_json::from_slice(&fs::read(ledger_path).expect("regression ledger reads"))
            .expect("regression ledger parses");
    assert_eq!(manifest["historical_population"]["status"], "UNREPRODUCED");
    assert!(manifest["historical_population"]["original_case_count"].is_null());
    assert_eq!(ledger["upstream_reproduction"]["status"], "UNREPRODUCED");
    assert_eq!(
        manifest["cases"].as_array().unwrap().len(),
        ledger["cases"].as_array().unwrap().len()
    );
    let ids = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["case_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), manifest["cases"].as_array().unwrap().len());
    for subject in manifest["upstream_subjects"].as_array().unwrap() {
        assert_eq!(
            subject["adjudication_status"],
            "PINNED_REPRESENTATIVE_NOT_HISTORICAL_REPRODUCTION"
        );
        assert_eq!(subject["upstream_sha"].as_str().unwrap().len(), 40);
        assert!(subject["governance_files"].as_array().unwrap().is_empty());
        assert!(subject["expected_claims"].is_null());
    }
    let mut output_digest_drifts = Vec::new();
    for case in manifest["cases"].as_array().unwrap() {
        let mut files = BTreeMap::new();
        let mut source_entries = Vec::new();
        for field in ["governance_files", "source_files"] {
            for entry in case[field].as_array().unwrap() {
                let path = entry["path"].as_str().unwrap();
                let bytes = entry["bytes"].as_str().unwrap().as_bytes().to_vec();
                assert_eq!(entry["byte_count"].as_u64().unwrap(), bytes.len() as u64);
                assert_eq!(
                    entry["digest"].as_str().unwrap(),
                    format!("sha256:{:x}", Sha256::digest(&bytes))
                );
                assert!(files.insert(path.to_owned(), bytes.clone()).is_none());
                if field == "source_files" {
                    source_entries.push((path.to_owned(), bytes));
                }
            }
        }
        source_entries.sort_by(|left, right| left.0.cmp(&right.0));
        let mut source_hash = Sha256::new();
        for (path, bytes) in source_entries {
            source_hash.update(path.as_bytes());
            source_hash.update([0]);
            source_hash.update(bytes.len().to_string().as_bytes());
            source_hash.update([0]);
            source_hash.update(Sha256::digest(&bytes));
            source_hash.update(b"\n");
        }
        assert_eq!(
            case["source_digest"].as_str().unwrap(),
            format!("sha256:{:x}", source_hash.finalize())
        );
        assert_eq!(case["expected_exit"], 0);
        let result = evaluate_files(&files);
        for expected in case["expected_claims"].as_array().unwrap() {
            let module = result
                .model()
                .module(expected["module_id"].as_str().unwrap())
                .expect("expected Module exists");
            let claim = module
                .conclusions()
                .iter()
                .find(|entry| entry.target() == expected["target"].as_str().unwrap())
                .expect("expected claim exists");
            let expected_verdict = match expected["verdict"].as_str().unwrap() {
                "FAIL" => SemanticConformanceState::SupportedViolation,
                "UNKNOWN" => SemanticConformanceState::NotEvaluable,
                "PASS" => SemanticConformanceState::NoSupportedViolation,
                other => panic!("unexpected fixture verdict {other}"),
            };
            let expected_eligibility = match expected["blocking_eligibility"].as_str().unwrap() {
                "BLOCK_SUPPORTED" => BlockingEligibility::BlockSupported,
                "NOT_EVALUABLE" => BlockingEligibility::NotEvaluable,
                "ADVISORY_ONLY" => BlockingEligibility::AdvisoryOnly,
                other => panic!("unexpected fixture eligibility {other}"),
            };
            assert_eq!(
                claim.conformance(),
                Some(expected_verdict),
                "case {}: claim {:?}, module coverage {:?}, defeaters {:?}",
                case["case_id"],
                claim,
                module.coverage(),
                module.defeater_refs()
            );
            assert_eq!(claim.blocking_eligibility(), Some(expected_eligibility));
            if expected_verdict == SemanticConformanceState::NotEvaluable {
                assert!(!claim.defeater_refs().is_empty());
            }
        }
        assert_eq!(
            result.findings().len(),
            fixture_count(&case["expected_findings"]["distinct_sites"])
        );
        assert_eq!(
            result.model().summary().blocking_findings(),
            fixture_count(&case["expected_findings"]["blocking"])
        );
        assert_eq!(
            result.model().summary().advisory_findings(),
            fixture_count(&case["expected_findings"]["advisory"])
        );
        let raw = serde_json::to_vec(&(
            result.model().to_canonical_json().unwrap(),
            result.findings(),
        ))
        .unwrap();
        let raw_digest = format!("sha256:{:x}", Sha256::digest(raw));
        let entry = ledger["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["case_id"] == case["case_id"])
            .expect("every replay case has a regression ledger entry");
        assert_eq!(entry["source_digest"], case["source_digest"]);
        assert_eq!(entry["configuration"], case["configuration"]);
        let governance_digests = case["governance_files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| serde_json::json!({"path": entry["path"], "digest": entry["digest"]}))
            .collect::<Vec<_>>();
        assert_eq!(
            entry["governance_digests"],
            serde_json::Value::Array(governance_digests)
        );
        if entry["raw_output_digest"] != raw_digest {
            output_digest_drifts.push((
                case["case_id"].as_str().unwrap().to_owned(),
                entry["raw_output_digest"].as_str().unwrap().to_owned(),
                raw_digest.clone(),
            ));
        }
        assert_eq!(entry["expected_claims"], case["expected_claims"]);
        assert_eq!(entry["expected_findings"], case["expected_findings"]);
        assert_eq!(entry["expected_limitations"], case["expected_limitations"]);
        assert_eq!(entry["distinct_source_sites"], result.findings().len());
        assert_eq!(
            entry["finding_lifecycle"],
            if result.findings().is_empty() {
                "NO_FINDING"
            } else {
                "UNBASELINED_CONTROL"
            }
        );
        assert_eq!(
            entry["propagated_paths"],
            result
                .model()
                .modules()
                .iter()
                .map(|module| module.observations().len())
                .sum::<usize>()
        );
        println!("{} {}", case["case_id"].as_str().unwrap(), raw_digest);
    }
    assert!(
        output_digest_drifts.is_empty(),
        "authored raw output digests changed: {output_digest_drifts:#?}"
    );
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
    assert_eq!(module.state(), SemanticConformanceState::NotEvaluable);
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
    assert_eq!(
        claim.conformance(),
        Some(SemanticConformanceState::NotEvaluable)
    );
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
    assert_eq!(
        claim.conformance(),
        Some(SemanticConformanceState::NotEvaluable)
    );
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
    assert_eq!(
        claim.conformance(),
        Some(SemanticConformanceState::SupportedViolation)
    );
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
        .filter(|conclusion| {
            conclusion.conformance() == Some(SemanticConformanceState::SupportedViolation)
        })
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
    assert_eq!(module.state(), SemanticConformanceState::NotEvaluable);
    assert_eq!(
        conclusion.conformance(),
        Some(SemanticConformanceState::NotEvaluable)
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
                    && claim.conformance() == Some(SemanticConformanceState::NoSupportedViolation)
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
        "pub fn pure() {}",
        module_contract("AF-SAMPLE-0001", &[], &["filesystem"], &[], &[]),
    );
    let module = result.model().module("AF-SAMPLE-0001").unwrap();
    assert_eq!(
        module.state(),
        SemanticConformanceState::NoSupportedViolation
    );
    assert_eq!(module.coverage().governed_source_files(), 1);
    assert_eq!(module.coverage().analysed_source_files(), 1);
    assert_eq!(module.coverage().ratio(), Some("1/1"));
    assert!(result.findings().is_empty());
    assert!(result.coverage_findings().is_empty());
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R07-003`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R07
#[test]
fn whole_module_partial_scope_never_passes_as_complete() {
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
    assert_eq!(module.state(), SemanticConformanceState::NotEvaluable);
    assert_eq!(module.coverage().governed_source_files(), 2);
    assert_eq!(module.coverage().analysed_source_files(), 1);
    assert_eq!(module.coverage().ratio(), Some("1/2"));
    assert!(module.defeater_refs().iter().any(|reference| {
        first.model().defeater(reference).is_some_and(|defeater| {
            defeater.kind() == DefeaterKind::PartialSemanticCoverage
                && defeater.strength() == DefeaterStrength::Defeating
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
    assert_eq!(module.state(), SemanticConformanceState::SupportedViolation);
    assert!(module.conclusions().iter().any(|entry| {
        entry.disposition() == PolicyDisposition::Allow
            && entry.authorization() == Some(AuthorizationState::Authorised)
            && entry.conformance().is_none()
    }));
    assert!(module.conclusions().iter().any(|entry| {
        entry.disposition() == PolicyDisposition::Deny
            && entry.conformance() == Some(SemanticConformanceState::SupportedViolation)
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
                assert!(entry["verdict"].is_null());
                assert!(entry["blocking_eligibility"].is_null());
            }
        }
    }
}
