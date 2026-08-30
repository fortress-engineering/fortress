//! Certification conformance tests.

use std::collections::{BTreeMap, BTreeSet};

use fortress_core::certification::{
    ArtifactEvidenceInput, BehavioralProjectionInput, BehavioralRealizationEvidenceInput,
    CertificationInput, CertificationProfile, CertificationStatus, EvidenceClass, EvidenceGraph,
    EvidenceNode, EvidenceResult, GeneratedVerificationInput, GeneratedVerificationKind,
    MANDATORY_SEMANTIC_ARTIFACTS, ProfileIdentity, RequirementEvidenceInput, RuleEvidenceInput,
    RustSuiteExecution, StandardIdentity, TrustedAssertionInput, VerificationBinding,
    VerifiedBehavioralState, certification_source_digest, compile_certification,
    test_inventory_digest,
};

fn input() -> CertificationInput {
    let source_digest = "sha256:subject".to_owned();
    let eligible_test_ids = vec!["T-AF-CERTIFICATION-0001-R01-001".to_owned()];
    CertificationInput {
        project_id: "PF-FORTRESS-0001".into(),
        source_digest: source_digest.clone(),
        standard: StandardIdentity {
            id: "STD-FORTRESS-0001".into(),
            edition: "2026.1-draft".into(),
        },
        finding_governance_digest: None,
        profile: CertificationProfile::full_snapshot(),
        artifacts: MANDATORY_SEMANTIC_ARTIFACTS
            .iter()
            .map(|kind| ArtifactEvidenceInput {
                kind: (*kind).into(),
                digest: format!("sha256:{kind}"),
                schema: "v1".into(),
                current: true,
                input_refs: Vec::new(),
                evidence_class: match *kind {
                    "ccg" | "intended_bfg" => EvidenceClass::Authority,
                    "psm" => EvidenceClass::Observation,
                    _ => EvidenceClass::StaticProof,
                },
                unsupported: Vec::new(),
            })
            .collect(),
        applicable_rules: vec!["STD-ID-001".into()],
        rules: vec![RuleEvidenceInput {
            rule_id: "STD-ID-001".into(),
            result: EvidenceResult::Pass,
            current: true,
            finding_fingerprints: Vec::new(),
            finding_governance: Vec::new(),
            input_refs: Vec::new(),
        }],
        requirements: vec![RequirementEvidenceInput {
            feature_id: "AF-CERTIFICATION-0001".into(),
            requirement_id: "AF-CERTIFICATION-0001-R01".into(),
            test_ids: eligible_test_ids.clone(),
        }],
        suite_execution: RustSuiteExecution {
            executor: "fortress-local-rust-executor".into(),
            executor_version: "1.0.0".into(),
            toolchain: "1.97.1".into(),
            certification_source_digest: source_digest,
            test_inventory_digest: test_inventory_digest(&eligible_test_ids, &[]),
            canonical_unfiltered: true,
            passed: true,
            eligible_test_ids,
            ignored_test_ids: Vec::new(),
        },
        behavioral_realizations: Vec::new(),
        generated_verification: Vec::new(),
        verification_bindings: Vec::new(),
        trusted_assertions: Vec::new(),
        behavioral_projection: Vec::new(),
    }
}

/// `T-AF-CERTIFICATION-0001-R01-001`
/// Fortress requirement: AF-CERTIFICATION-0001-R01
#[test]
fn content_addressed_dag_is_deterministic_and_valid() {
    let first = compile_certification(&input()).expect("compile");
    let second = compile_certification(&input()).expect("compile");
    assert_eq!(first.evidence_graph, second.evidence_graph);
    assert_eq!(
        first.certification.certification_digest(),
        second.certification.certification_digest()
    );
    assert_eq!(
        first.evidence_graph.to_json_pretty().unwrap(),
        second.evidence_graph.to_json_pretty().unwrap()
    );
    assert_eq!(first.certification.status(), CertificationStatus::Pass);
    first.evidence_graph.validate().expect("valid graph");
}

/// `T-AF-CERTIFICATION-0001-R01-002`
/// Fortress requirement: AF-CERTIFICATION-0001-R01
#[test]
fn node_identity_excludes_its_own_id() {
    let a = EvidenceNode::new(
        "proof",
        "subject",
        EvidenceResult::Pass,
        Vec::new(),
        "producer",
        "1",
        EvidenceClass::StaticProof,
        serde_json::json!({"x": 1}),
    )
    .unwrap();
    let b = EvidenceNode::new(
        "proof",
        "subject",
        EvidenceResult::Pass,
        Vec::new(),
        "producer",
        "1",
        EvidenceClass::StaticProof,
        serde_json::json!({"x": 1}),
    )
    .unwrap();
    assert_eq!(a.id(), b.id());
}

/// `T-AF-CERTIFICATION-0001-R01-003`
/// Fortress requirement: AF-CERTIFICATION-0001-R01
#[test]
fn affected_closure_preserves_independent_evidence() {
    let products = compile_certification(&input()).unwrap();
    let source = products
        .evidence_graph
        .nodes()
        .iter()
        .find(|node| node.kind() == "certification_source_snapshot")
        .unwrap();
    let changed = BTreeSet::from([source.id().to_owned()]);
    let affected = products.evidence_graph.affected(&changed);
    assert!(affected.contains(products.certification.certification_digest()));
    assert!(affected.len() > 1);

    let changed = EvidenceNode::new(
        "authority",
        "changed",
        EvidenceResult::Observed,
        Vec::new(),
        "producer",
        "1",
        EvidenceClass::Authority,
        serde_json::json!({}),
    )
    .unwrap();
    let independent = EvidenceNode::new(
        "observation",
        "independent",
        EvidenceResult::Observed,
        Vec::new(),
        "producer",
        "1",
        EvidenceClass::Observation,
        serde_json::json!({}),
    )
    .unwrap();
    let dependent = EvidenceNode::new(
        "proof",
        "dependent",
        EvidenceResult::Pass,
        vec![changed.id().into()],
        "producer",
        "1",
        EvidenceClass::StaticProof,
        serde_json::json!({}),
    )
    .unwrap();
    let changed_id = changed.id().to_owned();
    let independent_id = independent.id().to_owned();
    let dependent_id = dependent.id().to_owned();
    let graph = EvidenceGraph::new(
        "sha256:subject",
        StandardIdentity {
            id: "STD-FORTRESS-0001".into(),
            edition: "1".into(),
        },
        ProfileIdentity {
            id: "CERT-FULL-SNAPSHOT-V1".into(),
            version: 1,
        },
        vec![changed, independent, dependent],
        vec![dependent_id.clone(), independent_id.clone()],
        Vec::new(),
    )
    .unwrap();
    let affected = graph.affected(&BTreeSet::from([changed_id]));
    assert!(affected.contains(&dependent_id));
    assert!(!affected.contains(&independent_id));
}

/// `T-AF-CERTIFICATION-0001-R02-001`
/// Fortress requirement: AF-CERTIFICATION-0001-R02
#[test]
fn certification_status_precedence_is_canonical() {
    assert_eq!(
        CertificationStatus::aggregate([CertificationStatus::Pass, CertificationStatus::Missing]),
        CertificationStatus::Missing
    );
    assert_eq!(
        CertificationStatus::aggregate([CertificationStatus::Stale, CertificationStatus::Fail]),
        CertificationStatus::Fail
    );
    assert_eq!(
        CertificationStatus::aggregate([CertificationStatus::Fail, CertificationStatus::Invalid]),
        CertificationStatus::Invalid
    );
}

/// `T-AF-CERTIFICATION-0001-R02-002`
/// Fortress requirement: AF-CERTIFICATION-0001-R02
#[test]
fn unsupported_rule_is_missing_not_pass() {
    let mut value = input();
    value.rules[0].result = EvidenceResult::Unsupported;
    assert_eq!(
        compile_certification(&value)
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Missing
    );
    let mut stale = input();
    stale.rules[0].current = false;
    assert_eq!(
        compile_certification(&stale)
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Stale
    );
    let mut absent = input();
    absent.rules.clear();
    assert_eq!(
        compile_certification(&absent)
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Missing
    );
    let mut stale_artifact = input();
    stale_artifact.artifacts[0].current = false;
    assert_eq!(
        compile_certification(&stale_artifact)
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Stale
    );
    let mut missing_artifact = input();
    missing_artifact.artifacts.remove(0);
    assert_eq!(
        compile_certification(&missing_artifact)
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Missing
    );
}

/// `T-AF-CERTIFICATION-0001-R02-003`
/// Fortress requirement: AF-CERTIFICATION-0001-R02
#[test]
fn failed_rule_precedes_missing_evidence() {
    let mut value = input();
    value.rules[0].result = EvidenceResult::Fail;
    value.requirements[0]
        .test_ids
        .push("T-AF-MISSING-0001-R01-001".into());
    assert_eq!(
        compile_certification(&value)
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Fail
    );
}

/// `T-AF-CERTIFICATION-0001-R03-001`
/// Fortress requirement: AF-CERTIFICATION-0001-R03
#[test]
fn filtered_or_ignored_test_cannot_verify_requirement() {
    assert_eq!(
        compile_certification(&input())
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Pass
    );
    let mut filtered = input();
    filtered.suite_execution.canonical_unfiltered = false;
    assert_eq!(
        compile_certification(&filtered)
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Missing
    );
    let mut ignored = input();
    let id = ignored.suite_execution.eligible_test_ids.remove(0);
    ignored.suite_execution.ignored_test_ids.push(id);
    ignored.suite_execution.test_inventory_digest = test_inventory_digest(
        &ignored.suite_execution.eligible_test_ids,
        &ignored.suite_execution.ignored_test_ids,
    );
    assert_eq!(
        compile_certification(&ignored)
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Missing
    );
    let mut failed = input();
    failed.suite_execution.passed = false;
    assert_eq!(
        compile_certification(&failed)
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Fail
    );
    let mut missing = input();
    missing.requirements[0]
        .test_ids
        .push("T-AF-CERTIFICATION-0001-R01-999".into());
    assert_eq!(
        compile_certification(&missing)
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Missing
    );
    let mut stale = input();
    stale.suite_execution.certification_source_digest = "sha256:prior-subject".into();
    assert_eq!(
        compile_certification(&stale)
            .unwrap()
            .certification
            .status(),
        CertificationStatus::Stale
    );
    let mut corrupted_inventory = input();
    corrupted_inventory.suite_execution.test_inventory_digest = "sha256:forged".into();
    assert!(
        compile_certification(&corrupted_inventory)
            .unwrap_err()
            .to_string()
            .contains("inventory digest")
    );
}

/// `T-AF-CERTIFICATION-0001-R03-002`
/// Fortress requirement: AF-CERTIFICATION-0001-R03
#[test]
fn verification_binding_requires_responsible_testing_module() {
    let mut value = input();
    value
        .generated_verification
        .push(GeneratedVerificationInput {
            id: "VERIFY-ONE".into(),
            testing_module: "AF-ROOT-TESTING-0001".into(),
            kind: GeneratedVerificationKind::Behavioral,
            targets: vec!["CHK-ONE".into()],
        });
    value.verification_bindings.push(VerificationBinding {
        testing_module: "AF-FOREIGN-TESTING-0001".into(),
        obligation: "VERIFY-ONE".into(),
        tests: vec!["T-AF-CERTIFICATION-0001-R01-001".into()],
    });
    assert!(
        compile_certification(&value)
            .unwrap_err()
            .to_string()
            .contains("expected `AF-ROOT-TESTING-0001`")
    );
    let mut stale = input();
    stale.verification_bindings.push(VerificationBinding {
        testing_module: "AF-ROOT-TESTING-0001".into(),
        obligation: "VERIFY-STALE".into(),
        tests: vec!["T-AF-CERTIFICATION-0001-R01-001".into()],
    });
    assert!(
        compile_certification(&stale)
            .unwrap_err()
            .to_string()
            .contains("absent obligation")
    );
}

/// `T-AF-CERTIFICATION-0001-R03-003`
/// Fortress requirement: AF-CERTIFICATION-0001-R03
#[test]
fn trusted_assertion_remains_distinct_from_static_proof() {
    let mut value = input();
    value.trusted_assertions.push(TrustedAssertionInput {
        subject: "ASSERT-ATOMIC".into(),
        kind: "external_atomicity".into(),
        provenance: "mods/x/data/environment_contracts.json#/operations/0".into(),
    });
    let products = compile_certification(&value).unwrap();
    let assertion = products
        .evidence_graph
        .nodes()
        .iter()
        .find(|node| node.subject() == "ASSERT-ATOMIC")
        .unwrap();
    assert_eq!(assertion.evidence_class(), EvidenceClass::TrustedAssertion);
    assert_ne!(assertion.evidence_class(), EvidenceClass::StaticProof);
}

/// `T-AF-CERTIFICATION-0001-R04-001`
/// Fortress requirement: AF-CERTIFICATION-0001-R04
#[test]
fn generated_outputs_do_not_change_certification_source() {
    let mut files = BTreeMap::from([("code/lib.rs".into(), b"fn x() {}".to_vec())]);
    let first = certification_source_digest(&files);
    files.insert("info/certification.json".into(), b"old".to_vec());
    assert_eq!(first, certification_source_digest(&files));
    files.insert("info/evidence_graph.json".into(), b"changed".to_vec());
    files.insert(
        "info/verified_behavioral_flow_graph.json".into(),
        b"changed".to_vec(),
    );
    assert_eq!(first, certification_source_digest(&files));
    files.insert("code/lib.rs".into(), b"fn y() {}".to_vec());
    assert_ne!(first, certification_source_digest(&files));
}

/// `T-AF-CERTIFICATION-0001-R04-002`
/// Fortress requirement: AF-CERTIFICATION-0001-R04
#[test]
fn verified_bfg_preserves_intended_realized_and_executed_dimensions() {
    let mut value = input();
    value
        .behavioral_realizations
        .push(BehavioralRealizationEvidenceInput {
            feature: "AF-FLOW-0001".into(),
            coherent: true,
            evidence_ref: String::new(),
        });
    value
        .generated_verification
        .push(GeneratedVerificationInput {
            id: "VERIFY-CHK".into(),
            testing_module: "AF-TESTING-0001".into(),
            kind: GeneratedVerificationKind::Behavioral,
            targets: vec!["CHK-ONE".into()],
        });
    value.verification_bindings.push(VerificationBinding {
        testing_module: "AF-TESTING-0001".into(),
        obligation: "VERIFY-CHK".into(),
        tests: vec!["T-AF-CERTIFICATION-0001-R01-001".into()],
    });
    value.behavioral_projection.push(BehavioralProjectionInput {
        feature: "AF-FLOW-0001".into(),
        checkpoints: vec!["CHK-ONE".into()],
        intended_edges: Vec::new(),
        realized_checkpoints: vec!["CHK-ONE".into()],
        realized_edges: Vec::new(),
        contradicted: false,
    });
    let products = compile_certification(&value).unwrap();
    let checkpoint = &products.verified_bfg.features()[0].checkpoints[0];
    assert!(checkpoint.intended && checkpoint.realized);
    assert_eq!(
        checkpoint.verification,
        VerifiedBehavioralState::VerifiedStaticAndExecuted
    );
    assert_eq!(
        products
            .evidence_graph
            .nodes()
            .iter()
            .filter(|node| node.evidence_class() == EvidenceClass::ExecutedScenario)
            .count(),
        1
    );

    let mut stale = value;
    stale.suite_execution.certification_source_digest = "sha256:prior-subject".into();
    let stale_products = compile_certification(&stale).unwrap();
    assert_eq!(
        stale_products.verified_bfg.features()[0].checkpoints[0].verification,
        VerifiedBehavioralState::StaleEvidence
    );
}

/// `T-AF-CERTIFICATION-0001-R04-003`
/// Fortress requirement: AF-CERTIFICATION-0001-R04
#[test]
fn graph_constructor_rejects_missing_refs() {
    let node = EvidenceNode::new(
        "proof",
        "subject",
        EvidenceResult::Pass,
        vec!["sha256:missing".into()],
        "producer",
        "1",
        EvidenceClass::StaticProof,
        serde_json::json!({}),
    )
    .unwrap();
    let graph = EvidenceGraph::new(
        "sha256:subject",
        StandardIdentity {
            id: "STD-FORTRESS-0001".into(),
            edition: "1".into(),
        },
        ProfileIdentity {
            id: "CERT-FULL-SNAPSHOT-V1".into(),
            version: 1,
        },
        vec![node],
        Vec::new(),
        Vec::new(),
    );
    assert!(graph.unwrap_err().to_string().contains("missing input"));

    let products = compile_certification(&input()).unwrap();
    let mut corrupted = serde_json::to_value(&products.evidence_graph).unwrap();
    corrupted["nodes"][0]["subject"] = serde_json::json!("corrupted");
    let corrupted: EvidenceGraph = serde_json::from_value(corrupted).unwrap();
    assert!(
        corrupted
            .validate()
            .unwrap_err()
            .to_string()
            .contains("digest does not match")
    );

    let mut cyclic = serde_json::to_value(&products.evidence_graph).unwrap();
    let first = cyclic["nodes"][0]["id"].as_str().unwrap().to_owned();
    let second = cyclic["nodes"][1]["id"].as_str().unwrap().to_owned();
    cyclic["nodes"][0]["inputs"] = serde_json::json!([second]);
    cyclic["nodes"][1]["inputs"] = serde_json::json!([first]);
    let cyclic: EvidenceGraph = serde_json::from_value(cyclic).unwrap();
    assert!(cyclic.validate().unwrap_err().to_string().contains("cycle"));

    let one = EvidenceNode::new(
        "proof",
        "same-subject",
        EvidenceResult::Pass,
        Vec::new(),
        "producer",
        "1",
        EvidenceClass::StaticProof,
        serde_json::json!({"variant": 1}),
    )
    .unwrap();
    let two = EvidenceNode::new(
        "proof",
        "same-subject",
        EvidenceResult::Fail,
        Vec::new(),
        "producer",
        "1",
        EvidenceClass::StaticProof,
        serde_json::json!({"variant": 2}),
    )
    .unwrap();
    assert!(
        EvidenceGraph::new(
            "sha256:subject",
            StandardIdentity {
                id: "STD-FORTRESS-0001".into(),
                edition: "1".into(),
            },
            ProfileIdentity {
                id: "CERT-FULL-SNAPSHOT-V1".into(),
                version: 1,
            },
            vec![one, two],
            Vec::new(),
            Vec::new(),
        )
        .unwrap_err()
        .to_string()
        .contains("conflicting evidence nodes")
    );
}
