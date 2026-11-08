//! Independent truth-table and adversarial declaration conformance controls.

use fortress_core::assessment::*;
use fortress_core::certification::EvidenceClass;
use fortress_core::declaration::*;
use fortress_core::proof::ProofGraph;
use sha2::{Digest, Sha256};

fn digest() -> String {
    format!("sha256:{}", "a".repeat(64))
}

fn assert_advertised_schema(value: &impl serde::Serialize) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("engine/standard_registry/_data/schema_manifest.json")).unwrap(),
    )
    .unwrap();
    let mut options = jsonschema::draft202012::options();
    let instance = serde_json::to_value(value).unwrap();
    let id = instance["$schema"].as_str().unwrap();
    let mut selected = None;
    for path in manifest["schemas"].as_array().unwrap() {
        let schema: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(path.as_str().unwrap())).unwrap())
                .unwrap();
        let identity = schema["$id"].as_str().unwrap().to_owned();
        if identity == id {
            selected = Some(schema.clone());
        }
        options = options.with_resource(
            identity,
            jsonschema::Resource::from_contents(schema).unwrap(),
        );
    }
    options
        .build(&selected.unwrap())
        .unwrap()
        .validate(&instance)
        .unwrap();
}
fn semantic_detail(truth: DeclarationTruth, context: &str) -> SemanticClaimDetail {
    SemanticClaimDetail {
        instance_id: "scope".into(),
        slot_id: "fixture-slot".into(),
        module_id: "AF-FIXTURE".into(),
        scope_selector: "ALL_MODULE_OWNED_EXECUTABLE_ENTRIES".into(),
        context_family: "fixture".into(),
        policy_digest: digest(),
        context_digest: context.to_owned(),
        governed_universe_digest: digest(),
        producer_identity: "independent-fixture".into(),
        target_kind: "EFFECT".into(),
        target: "filesystem.write".into(),
        disposition: if truth == DeclarationTruth::Authorization {
            "ALLOW".into()
        } else {
            "DENY".into()
        },
        governed_source_files: 1,
        analysed_source_files: 1,
        production_observations: vec![],
        test_observations: vec![],
        unknown_observations: vec![],
        upstream_proof_refs: vec!["leaf".into()],
        proof_graph: None,
        blocking_eligibility: None,
    }
}

fn fixture(
    truth: DeclarationTruth,
) -> (
    ConformanceDeclaration,
    ExpectedProfileAssessment,
    Vec<AssessmentEvidence>,
    EvidenceAcceptancePolicy,
) {
    let binding = DeclarationBinding {
        subject_ref: digest(),
        context_ref: format!("sha256:{}", "b".repeat(64)),
        authority_ref: format!("sha256:{}", "c".repeat(64)),
    };
    let manifest = DimensionManifest {
        profiles: vec![ScopedProfileReference {
            module: None,
            id: "PROFILE".into(),
            version: "1.0.0".into(),
            digest: digest(),
        }],
        dimensions: vec![RequiredDimension {
            id: "SEMANTICS".into(),
            claim_refs: vec!["claim".into()],
        }],
    };
    let claim = DeclarationClaim {
        rule_result: None,
        kind: DeclarationClaimKind::SemanticPolicy,
        id: "claim".into(),
        scope_ref: "scope".into(),
        truth,
        proof_refs: vec!["leaf".into()],
        findings: vec![],
        defeater_refs: vec![],
        reason_codes: vec![],
        assumptions: vec![],
        semantic_claim: Some(semantic_detail(truth, &binding.context_ref)),
    };
    let declaration = ConformanceDeclaration::compose(
        binding.clone(),
        manifest.clone(),
        vec![claim],
        vec![],
        DeclarationResidue::default(),
    )
    .unwrap();
    let proof: ProofGraph = serde_json::from_value(serde_json::json!({"schema_version":1,"root_node_id":"root","nodes":[{"node_id":"root","operator":"LEAF","required_refs":["leaf"],"children":[]}]})).unwrap();
    let expected = ExpectedProfileAssessment {
        artifacts: vec![],
        binding: binding.clone(),
        dimensions: manifest,
        profile_digest: digest(),
        obligations: vec![ProfileObligation {
            id: "obligation".into(),
            scope_ref: "scope".into(),
            predicate: ObligationPredicate::Conformance,
            evidence_class: EvidenceClass::StaticProof,
            authenticated_producer_required: false,
            proof: Some(proof),
        }],
    };
    let leaf = AssessmentEvidence {
        id: "leaf".into(),
        source_ref: "leaf".into(),
        binding,
        scope_ref: "scope".into(),
        evidence_class: if matches!(
            truth,
            DeclarationTruth::SupportedViolation | DeclarationTruth::NoSupportedViolation
        ) {
            EvidenceClass::StaticProof
        } else {
            EvidenceClass::Observation
        },
        proposition: match truth {
            DeclarationTruth::SupportedViolation => EvidenceProposition::SupportedViolation,
            DeclarationTruth::NoSupportedViolation => EvidenceProposition::NoSupportedViolation,
            _ => EvidenceProposition::ObservationOnly,
        },
        payload_digest: digest(),
        assumptions: vec![],
        valid_until: None,
    };
    let mut policy = EvidenceAcceptancePolicy::default();
    policy.verified_payloads.insert("leaf".into(), digest());
    policy
        .verified_metadata
        .insert("leaf".into(), leaf.metadata_digest().unwrap());
    (declaration, expected, vec![leaf], policy)
}

/// `T-AF-CERTIFICATION-0001-R08-001`
/// Fortress requirement: AF-CERTIFICATION-0001-R08
#[test]
fn independent_public_consumer_replays_original_assessment_truth_and_admission() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let controls = root.join("testing/_code/portable_controls.py");
    let own = Command::new("python")
        .args(["-I", "-B"])
        .arg(&controls)
        .output()
        .unwrap();
    assert!(
        own.status.success(),
        "{}",
        String::from_utf8_lossy(&own.stderr)
    );
    let mut vectors = Vec::new();
    for truth in [
        DeclarationTruth::NoSupportedViolation,
        DeclarationTruth::SupportedViolation,
        DeclarationTruth::NotEvaluable,
        DeclarationTruth::NotApplicable,
        DeclarationTruth::Authorization,
    ] {
        for scenario in 0..9 {
            let (mut declaration, mut expected, mut evidence, mut policy) = fixture(truth);
            match scenario {
                1 => {
                    policy.verified_payloads.clear();
                }
                2 => {
                    expected.obligations[0].authenticated_producer_required = true;
                }
                3 => {
                    evidence[0].valid_until = Some(1);
                }
                4 => {
                    evidence[0].binding.context_ref = digest();
                }
                5 => {
                    expected.obligations[0].proof = None;
                }
                6 if truth == DeclarationTruth::SupportedViolation => {
                    declaration.claims[0].findings.push("finding".into());
                    declaration.residue_summary.accepted_baseline = vec!["finding".into()];
                }
                7 if truth == DeclarationTruth::SupportedViolation => {
                    declaration.claims[0].findings.push("finding".into());
                    declaration.residue_summary.accepted_exceptions = vec!["finding".into()];
                }
                8 => {
                    expected.obligations[0].predicate = ObligationPredicate::Evaluability;
                }
                _ => {}
            }
            let assessment =
                ProfileAssessment::evaluate(&declaration, &expected, &evidence, &policy).unwrap();
            vectors.push(serde_json::json!({"expected":assessment.decision,"declaration":declaration,"assessment":assessment,
                "replay":{"schema_version":1,"expected":{"artifacts":expected.artifacts,"binding":expected.binding,"dimensions":expected.dimensions,
                    "profile_digest":expected.profile_digest,"obligations":expected.obligations},"evidence":evidence,"acceptance":policy}}));
        }
    }
    let mut child = Command::new("python")
        .args(["-I", "-B"])
        .arg(controls)
        .arg("--rust-vectors")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&vectors).unwrap())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["checked"], 45);
    assert_eq!(result["status"], "PASS");
    assert_eq!(result["authenticity"], "UNVERIFIED");
}

/// `T-AF-CERTIFICATION-0001-R08-002`
/// Fortress requirement: AF-CERTIFICATION-0001-R08
#[test]
fn compact_captured_application_bundle_is_independently_checked_without_reexecution() {
    use fortress_core::bundle::PortableBundle;
    use fortress_core::portable_load::{load_portable_state, write_portable_bundle};
    use std::process::Command;
    let source = governed_checkout();
    let output = Checkout::new();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let predicate = "https://example.invalid/fortress/assurance/v1";
    for (name, code) in [
        (
            "negative",
            "pub fn write() { let _ = std::fs::write(\"output\",b\"x\"); }\n",
        ),
        ("clean", "pub fn write() {}\n"),
    ] {
        source.write("sample/_code/lib.rs", code);
        let view = fortress_core::audit::compile_repository_state_view(&source.0).unwrap();
        let expected =
            serde_json::to_value(view.application.as_ref().unwrap().assessment.decision).unwrap();
        let original = view.to_canonical_bytes().unwrap();
        let state_path = output.0.join(format!("{name}-state.json"));
        std::fs::write(&state_path, &original).unwrap();
        let artifacts = load_portable_state(&source.0, &state_path).unwrap();
        let bundle = PortableBundle::assemble(artifacts.clone(), None, predicate).unwrap();
        assert_eq!(
            bundle.members,
            PortableBundle::assemble(artifacts, None, predicate)
                .unwrap()
                .members
        );
        assert_advertised_schema(&bundle.manifest);
        for artifact in &bundle.manifest.artifacts {
            if artifact.media_type == "application/json" {
                let value: serde_json::Value =
                    serde_json::from_slice(&bundle.members[&artifact.member]).unwrap();
                if value.get("$schema").is_some() {
                    assert_advertised_schema(&value);
                }
            }
        }
        let destination = output.0.join(name);
        write_portable_bundle(&bundle, &destination).unwrap();
        assert_eq!(
            write_portable_bundle(&bundle, &destination)
                .unwrap_err()
                .code,
            "OUTPUT_EXISTS"
        );
        assert_eq!(std::fs::read(&state_path).unwrap(), original);
        assert_eq!(
            std::fs::read_to_string(source.0.join("sample/_code/lib.rs")).unwrap(),
            code
        );
        let result = Command::new(if cfg!(windows) { "python" } else { "python3" })
            .args(["-I", "-B"])
            .arg(root.join("testing/_code/verify_bundle.py"))
            .arg(&destination)
            .args(["--predicate-type", predicate])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let verified: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(verified["integrity"], "VERIFIED");
        assert_eq!(verified["assessment_replay"], expected);
        assert_eq!(verified["authenticity"], "UNVERIFIED");
        assert_eq!(verified["assurance"], "UNVERIFIED");
        assert_eq!(verified["freshness"], "UNKNOWN");
        assert_eq!(
            verified["certification_result_availability"],
            "NOT_APPLICABLE_APPLICATION"
        );
        verify_capture_references(&root, &destination, &state_path, predicate);
        if let Some(directory) = std::env::var_os("FORTRESS_RETAIN_BUNDLE_FIXTURES") {
            let retain = std::path::Path::new(&directory).join(name);
            write_portable_bundle(&bundle, &retain).unwrap();
        }
    }
}

/// `T-AF-CERTIFICATION-0001-R08-003`
/// Fortress requirement: AF-CERTIFICATION-0001-R08
#[test]
fn omitted_tampered_wrong_context_and_forged_unsigned_bundles_are_not_admitted() {
    deep_public_evidence_graph_uses_bounded_heap_traversal();
    let source = governed_checkout();
    let output = Checkout::new();
    let view = fortress_core::audit::compile_repository_state_view(&source.0).unwrap();
    let path = output.0.join("state.json");
    std::fs::write(&path, view.to_canonical_bytes().unwrap()).unwrap();
    let artifacts = fortress_core::portable_load::load_portable_state(&source.0, &path).unwrap();
    let predicate = "https://example.invalid/fortress/assurance/v1";
    let mut bundle =
        fortress_core::bundle::PortableBundle::assemble(artifacts, None, predicate).unwrap();
    let destination = output.0.join("valid");
    fortress_core::portable_load::write_portable_bundle(&bundle, &destination).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
        .args(["-I", "-B"])
        .arg(root.join("testing/_code/portable_controls.py"))
        .arg("--bundle-attacks")
        .arg(&destination)
        .arg(predicate)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["checked"], 12);
    bundle.members.insert(
        format!("artifacts/{}é.json", "a".repeat(62)),
        b"{}".to_vec(),
    );
    assert_eq!(
        fortress_core::portable_load::write_portable_bundle(&bundle, &output.0.join("unsafe"))
            .unwrap_err()
            .code,
        "UNSAFE_PATH"
    );
    assert!(!output.0.join("unsafe").exists());
}

fn deep_public_evidence_graph_uses_bounded_heap_traversal() {
    use fortress_core::certification::{
        EvidenceGraph, EvidenceNode, EvidenceResult, ProfileIdentity, StandardIdentity,
    };
    let mut nodes = Vec::new();
    let mut inputs = Vec::new();
    for index in 0..20_000 {
        let node = EvidenceNode::new(
            "bounded_observation",
            format!("subject:{index}"),
            EvidenceResult::Observed,
            inputs,
            "synthetic-control",
            "1.0.0",
            EvidenceClass::Observation,
            serde_json::json!({"index":index}),
        )
        .unwrap();
        inputs = vec![node.id().to_owned()];
        nodes.push(node);
    }
    let graph = EvidenceGraph::new(
        digest(),
        StandardIdentity {
            id: "STD-FIXTURE".into(),
            edition: "fixture".into(),
        },
        ProfileIdentity {
            id: "PROFILE".into(),
            version: 1,
        },
        nodes,
        inputs,
        vec![],
    )
    .unwrap();
    assert_eq!(graph.nodes().len(), 20_000);
    graph.validate().unwrap();
}

/// `T-AF-CERTIFICATION-0001-R05-001`
/// Fortress requirement: AF-CERTIFICATION-0001-R05
#[test]
fn complete_truth_table_preserves_authorization_uncertainty_and_violation() {
    for (truth, decision) in [
        (
            DeclarationTruth::NoSupportedViolation,
            AssessmentDecision::Satisfied,
        ),
        (
            DeclarationTruth::SupportedViolation,
            AssessmentDecision::NotSatisfied,
        ),
        (
            DeclarationTruth::NotEvaluable,
            AssessmentDecision::NotEvaluable,
        ),
        (
            DeclarationTruth::NotApplicable,
            AssessmentDecision::NotEvaluable,
        ),
        (
            DeclarationTruth::Authorization,
            AssessmentDecision::NotEvaluable,
        ),
    ] {
        let (d, e, leaves, p) = fixture(truth);
        assert_eq!(
            ProfileAssessment::evaluate(&d, &e, &leaves, &p)
                .unwrap()
                .decision,
            decision
        );
        let bytes = d.to_canonical_bytes().unwrap();
        assert_advertised_schema(&d);
        assert_eq!(
            ConformanceDeclaration::from_json_str(std::str::from_utf8(&bytes).unwrap()).unwrap(),
            d
        );
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("\"PASS\""));
    }
}

/// `T-AF-CERTIFICATION-0001-R05-002`
/// Fortress requirement: AF-CERTIFICATION-0001-R05
#[test]
fn omission_of_both_manifest_and_outcome_cannot_improve_assessment() {
    let (mut d, e, leaves, p) = fixture(DeclarationTruth::NotEvaluable);
    d.required_dimension_manifest
        .dimensions
        .push(RequiredDimension {
            id: "Z".into(),
            claim_refs: vec![],
        });
    assert!(d.validate().is_err());
    d.required_dimension_manifest.dimensions.pop();
    d.required_dimension_manifest.dimensions[0]
        .claim_refs
        .clear();
    d.dimensions[0].claim_refs.clear();
    d.dimensions[0].truth = DeclarationTruth::NotApplicable;
    d.claims.clear();
    assert!(d.validate().is_ok());
    assert_eq!(
        ProfileAssessment::evaluate(&d, &e, &leaves, &p)
            .unwrap()
            .decision,
        AssessmentDecision::Invalid
    );
    let (mut d, mut e, leaves, p) = fixture(DeclarationTruth::NoSupportedViolation);
    let artifact = DeclarationArtifact {
        id: "required-proof".into(),
        content_digest: digest(),
        byte_count: 1,
    };
    e.artifacts.push(artifact.clone());
    d.proof_manifest.push(artifact);
    assert_eq!(
        ProfileAssessment::evaluate(&d, &e, &leaves, &p)
            .unwrap()
            .decision,
        AssessmentDecision::Satisfied
    );
    d.proof_manifest.clear();
    assert_eq!(
        ProfileAssessment::evaluate(&d, &e, &leaves, &p)
            .unwrap()
            .decision,
        AssessmentDecision::Invalid
    );
}

/// `T-AF-CERTIFICATION-0001-R05-003`
/// Fortress requirement: AF-CERTIFICATION-0001-R05
#[test]
fn evidence_admission_checks_exact_bindings_class_predicate_trust_and_time() {
    let (d, e, leaves, p) = fixture(DeclarationTruth::NoSupportedViolation);
    for case in 0..9 {
        let mut changed = leaves.clone();
        let mut policy = p.clone();
        let code = match case {
            0 => {
                changed[0].binding.subject_ref = format!("sha256:{}", "b".repeat(64));
                AssessmentBlockerCode::StaleEvidence
            }
            1 => {
                changed[0].binding.context_ref = format!("sha256:{}", "d".repeat(64));
                AssessmentBlockerCode::IncompatibleContext
            }
            2 => {
                changed[0].evidence_class = EvidenceClass::Observation;
                AssessmentBlockerCode::IncompatibleEvidence
            }
            3 => {
                changed[0].proposition = EvidenceProposition::ExecutionSucceeded;
                AssessmentBlockerCode::IncompatibleEvidence
            }
            4 => {
                policy.verified_payloads.clear();
                AssessmentBlockerCode::UntrustedEvidence
            }
            5 => {
                changed[0].assumptions.push("conditional".into());
                AssessmentBlockerCode::AssumptionNotAccepted
            }
            6 => {
                changed[0].valid_until = Some(5);
                policy.assessment_time = Some(6);
                AssessmentBlockerCode::EvidenceExpiredOrTimeMissing
            }
            7 => {
                changed[0].scope_ref = "different-instance".into();
                AssessmentBlockerCode::IncompatibleEvidence
            }
            _ => {
                changed[0].proposition = EvidenceProposition::Unavailable;
                AssessmentBlockerCode::RequiredEvidenceMissing
            }
        };
        let result = ProfileAssessment::evaluate(&d, &e, &changed, &policy).unwrap();
        assert_eq!(result.decision, AssessmentDecision::NotEvaluable);
        assert_eq!(result.obligations[0].blockers, vec![code]);
    }
}

/// `T-AF-CERTIFICATION-0001-R05-004`
/// Fortress requirement: AF-CERTIFICATION-0001-R05
#[test]
fn residue_does_not_rewrite_truth_and_cache_availability_is_not_authority() {
    let (mut d, e, leaves, p) = fixture(DeclarationTruth::SupportedViolation);
    d.claims[0].findings.push("finding".into());
    d.residue_summary.accepted_baseline.push("finding".into());
    let before = d.to_canonical_bytes().unwrap();
    assert_eq!(
        ProfileAssessment::evaluate(&d, &e, &leaves, &p)
            .unwrap()
            .decision,
        AssessmentDecision::NotSatisfied
    );
    let mut missing = p;
    missing.verified_payloads.clear();
    assert_eq!(
        ProfileAssessment::evaluate(&d, &e, &leaves, &missing)
            .unwrap()
            .decision,
        AssessmentDecision::NotEvaluable
    );
    assert_eq!(d.to_canonical_bytes().unwrap(), before);

    let bytes = b"independently retained projection".to_vec();
    d.proof_manifest.push(DeclarationArtifact {
        id: "projection".into(),
        content_digest: format!("sha256:{:x}", Sha256::digest(&bytes)),
        byte_count: bytes.len() as u64,
    });
    let canonical = d.to_canonical_bytes().unwrap();
    let mut local = std::collections::BTreeMap::from([("projection".into(), bytes)]);
    assert_eq!(
        VerificationSessionReport::inspect(&d, &local)
            .unwrap()
            .materializations["projection"],
        MaterializationAvailability::Current
    );
    assert_eq!(
        VerificationSessionReport::inspect_subject(
            &d,
            &format!("sha256:{}", "b".repeat(64)),
            &local
        )
        .unwrap()
        .materializations["projection"],
        MaterializationAvailability::Stale
    );
    local.clear();
    assert_eq!(
        VerificationSessionReport::inspect(&d, &local)
            .unwrap()
            .materializations["projection"],
        MaterializationAvailability::Missing
    );
    local.insert("projection".into(), b"changed".to_vec());
    assert_eq!(
        VerificationSessionReport::inspect(&d, &local)
            .unwrap()
            .materializations["projection"],
        MaterializationAvailability::Invalid
    );
    assert_eq!(d.to_canonical_bytes().unwrap(), canonical);
}

/// `T-AF-CERTIFICATION-0001-R05-005`
/// Fortress requirement: AF-CERTIFICATION-0001-R05
#[test]
fn independently_specified_any_all_truth_tables_require_complete_admitted_alternatives() {
    for operator in ["ALL", "ANY"] {
        for mask in 0..4 {
            let (mut d, mut e, mut leaves, mut p) = fixture(DeclarationTruth::NoSupportedViolation);
            d.claims[0].proof_refs.push("other".into());
            let mut other = leaves[0].clone();
            other.id = "other".into();
            other.source_ref = "other".into();
            leaves.push(other);
            p.verified_payloads.insert("other".into(), digest());
            p.verified_metadata
                .insert("other".into(), leaves[1].metadata_digest().unwrap());
            e.obligations[0].proof = Some(
                serde_json::from_value(
                    serde_json::json!({"schema_version":1,"root_node_id":"root","nodes":[
                {"node_id":"a","operator":"LEAF","required_refs":["leaf"],"children":[]},
                {"node_id":"b","operator":"LEAF","required_refs":["other"],"children":[]},
                {"node_id":"root","operator":operator,"required_refs":[],"children":["a","b"]}]}),
                )
                .unwrap(),
            );
            if mask & 1 == 0 {
                p.verified_payloads.remove("leaf");
            }
            if mask & 2 == 0 {
                p.verified_payloads.remove("other");
            }
            let independently_expected = if operator == "ALL" {
                mask == 3
            } else {
                mask != 0
            };
            assert_eq!(
                ProfileAssessment::evaluate(&d, &e, &leaves, &p)
                    .unwrap()
                    .decision,
                if independently_expected {
                    AssessmentDecision::Satisfied
                } else {
                    AssessmentDecision::NotEvaluable
                }
            );
            if mask == 3 {
                e.obligations[0].proof.as_mut().unwrap().nodes[2]
                    .children
                    .push("root".into());
                assert_eq!(
                    ProfileAssessment::evaluate(&d, &e, &leaves, &p)
                        .unwrap()
                        .decision,
                    AssessmentDecision::Invalid
                );
            }
        }
    }
}

/// `T-AF-CERTIFICATION-0001-R05-006`
/// Fortress requirement: AF-CERTIFICATION-0001-R05
#[test]
fn rule_checks_metadata_forgery_and_override_relocation_do_not_discharge_semantic_claims() {
    let (mut d, mut e, mut leaves, mut p) = fixture(DeclarationTruth::NoSupportedViolation);
    d.claims[0].kind = DeclarationClaimKind::RuleCheck;
    let detail = d.claims[0].semantic_claim.take();
    d.claims[0].rule_result = Some(RuleClaimDetail {
        outcome: fortress_core::application::ApplicationRuleOutcome::Passed,
        applicable: true,
        applicability_reason: None,
        detail: "exact registered check".into(),
    });
    assert_eq!(
        ProfileAssessment::evaluate(&d, &e, &leaves, &p)
            .unwrap()
            .decision,
        AssessmentDecision::NotEvaluable
    );
    d.claims[0].kind = DeclarationClaimKind::SemanticPolicy;
    d.claims[0].semantic_claim = detail;
    d.claims[0].rule_result = None;
    leaves[0].valid_until = Some(5);
    p.assessment_time = Some(4);
    assert_eq!(
        ProfileAssessment::evaluate(&d, &e, &leaves, &p)
            .unwrap()
            .obligations[0]
            .blockers,
        vec![AssessmentBlockerCode::UntrustedEvidence]
    );
    p.verified_metadata
        .insert("leaf".into(), leaves[0].metadata_digest().unwrap());
    assert_eq!(
        ProfileAssessment::evaluate(&d, &e, &leaves, &p)
            .unwrap()
            .decision,
        AssessmentDecision::Satisfied
    );
    e.dimensions.profiles[0].module = Some("different-module".into());
    let invalid = ProfileAssessment::evaluate(&d, &e, &leaves, &p).unwrap();
    assert_eq!(invalid.decision, AssessmentDecision::Invalid);
    let bytes = invalid.to_canonical_bytes().unwrap();
    assert_eq!(
        ProfileAssessment::from_json_str(std::str::from_utf8(&bytes).unwrap()).unwrap(),
        invalid
    );
    let mut malformed = serde_json::to_value(&invalid).unwrap();
    malformed["decision"] = serde_json::json!("SATISFIED");
    assert!(ProfileAssessment::from_json_str(&malformed.to_string()).is_err());
    let mut duplicate = serde_json::to_value(&invalid).unwrap();
    duplicate["blockers"] =
        serde_json::json!(["TRUSTED_MANIFEST_MISMATCH", "TRUSTED_MANIFEST_MISMATCH"]);
    assert!(ProfileAssessment::from_json_str(&duplicate.to_string()).is_err());
    duplicate["blockers"] = serde_json::json!(["TRUSTED_MANIFEST_MISMATCH"]);
    duplicate["decision"] = serde_json::json!("NOT_SATISFIED");
    duplicate["obligations"][0]["decision"] = serde_json::json!("NOT_SATISFIED");
    duplicate["obligations"][0]["blockers"] = serde_json::json!(["SUPPORTED_VIOLATION"]);
    assert!(ProfileAssessment::from_json_str(&duplicate.to_string()).is_err());
}

struct Checkout(std::path::PathBuf);
impl Checkout {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fortress-declaration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, path: &str, content: &str) {
        let path = self.0.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
}
impl Drop for Checkout {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

/// `T-AF-CERTIFICATION-0001-R05-007`
/// Fortress requirement: AF-CERTIFICATION-0001-R05
#[test]
fn neutral_state_view_precedes_strict_governance_boundary() {
    use fortress_core::audit::{StateViewStatus, compile_repository_state_view};
    let checkout = Checkout::new();
    checkout.write("source.rs", "pub fn sample() {}\n");
    let absent = compile_repository_state_view(&checkout.0).unwrap();
    assert_eq!(absent.status, StateViewStatus::Ungoverned);
    assert!(absent.application.is_none());
    checkout.write("__fortress/.fsconfig", "{broken");
    let invalid = compile_repository_state_view(&checkout.0).unwrap();
    assert_eq!(invalid.status, StateViewStatus::Invalid);
    assert!(invalid.application.is_none());
    assert_ne!(absent.source_ref, invalid.source_ref);
}

fn governed_checkout() -> Checkout {
    let checkout = Checkout::new();
    checkout.write("__fortress/.fsconfig",r#"{"$schema":"urn:fortress:schema:v2:project-configuration","schema_version":2,"observation_exclusions":[".git"]}"#);
    let root = serde_json::json!({"$schema":"urn:fortress:schema:v2:module-contract","schema_version":2,"id":"PF-DECLARE-FIXTURE","display_name":"Declaration fixture",
        "ecosystem":{"repository_grammar":1,"standard":{"id":"STD-FORTRESS-ENGINEERING","edition":"1.0.0-draft.2"}},
        "provides":[],"requires":[],"relationships":[],"constraints":[],"guarantees":[],"features":[],"behavior":[]});
    let contract: fortress_core::contract_coherency::ModuleContract =
        serde_json::from_value(root.clone()).unwrap();
    let canonical = contract.to_canonical_json().unwrap();
    checkout.write("contract.json", &canonical);
    let mut child = root;
    child["$schema"] = serde_json::json!("urn:fortress:schema:v3:module-contract");
    child["schema_version"] = serde_json::json!(3);
    child["id"] = serde_json::json!("AF-SAMPLE-0001");
    child.as_object_mut().unwrap().remove("ecosystem");
    child["semantic_policy"] = serde_json::json!({"default":"UNDECLARED","capabilities":{"allow":[],"deny":[]},"effects":{"allow":[],"deny":["filesystem.write"]}});
    let contract: fortress_core::contract_coherency::ModuleContract =
        serde_json::from_value(child).unwrap();
    let canonical = contract.to_canonical_json().unwrap();
    checkout.write("sample/contract.json", &canonical);
    checkout.write("sample/_data/Cargo.toml","[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n");
    checkout.write(
        "sample/_code/lib.rs",
        "pub fn write() { let _ = std::fs::write(\"output\",b\"x\"); }\n",
    );
    checkout
}

/// `T-AF-CERTIFICATION-0001-R05-008`
/// Fortress requirement: AF-CERTIFICATION-0001-R05
#[test]
fn native_failed_application_preserves_claims_provenance_and_repeatable_canonical_reporting() {
    use fortress_core::audit::compile_repository_state_view;
    let checkout = governed_checkout();
    let view = compile_repository_state_view(&checkout.0).unwrap();
    assert!(
        view.application.is_some(),
        "neutral={view:?}; inspection={}",
        serde_json::to_string(
            &fortress_core::audit::inspect_repository_modules(&checkout.0).unwrap()
        )
        .unwrap()
    );
    let application = view.application.as_ref().unwrap();
    let claim = application
        .declaration
        .claims
        .iter()
        .find(|c| {
            c.semantic_claim
                .as_ref()
                .is_some_and(|s| s.module_id == "AF-SAMPLE-0001")
        })
        .unwrap();
    assert_eq!(claim.truth, DeclarationTruth::SupportedViolation);
    assert!(!claim.findings.is_empty());
    assert!(
        !claim
            .semantic_claim
            .as_ref()
            .unwrap()
            .production_observations
            .is_empty()
    );
    assert!(
        application
            .assessment
            .obligations
            .iter()
            .any(|o| o.decision == AssessmentDecision::NotSatisfied)
    );
    let first = view.to_canonical_bytes().unwrap();
    assert_advertised_schema(&view);
    assert_advertised_schema(&application.assessment);
    let read = fortress_core::audit::StateView::from_json_str(std::str::from_utf8(&first).unwrap())
        .unwrap();
    assert_eq!(read.to_canonical_bytes().unwrap(), first);
    assert_eq!(
        compile_repository_state_view(&checkout.0)
            .unwrap()
            .to_canonical_bytes()
            .unwrap(),
        first
    );
    assert!(
        !std::str::from_utf8(&first)
            .unwrap()
            .contains("RustSuiteExecution")
    );
    checkout.write(
        "sample/_code/lib.rs",
        "pub fn write() { unknown_operation(); }\n",
    );
    let unknown = compile_repository_state_view(&checkout.0).unwrap();
    let application = unknown.application.as_ref().unwrap();
    let observational = application
        .declaration
        .claims
        .iter()
        .filter(|claim| {
            matches!(
                claim.truth,
                DeclarationTruth::NotEvaluable
                    | DeclarationTruth::NotApplicable
                    | DeclarationTruth::Authorization
            )
        })
        .flat_map(|claim| {
            application
                .evidence
                .iter()
                .filter(move |leaf| leaf.scope_ref == claim.scope_ref)
        })
        .collect::<Vec<_>>();
    assert!(!observational.is_empty());
    assert!(observational.iter().all(|leaf| leaf.proposition
        == EvidenceProposition::ObservationOnly
        && leaf.evidence_class == EvidenceClass::Observation));
    assert!(application.declaration.claims.iter().any(|c| {
        c.semantic_claim
            .as_ref()
            .is_some_and(|s| s.module_id == "AF-SAMPLE-0001")
            && c.truth == DeclarationTruth::NotEvaluable
    }));
}

use fortress_core::qualification::{QualificationInputs, QualificationManifest, SupportedScope};
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn qualification_fixture_scope() -> SupportedScope {
    SupportedScope::from_json_str(&json!({
        "$schema":"urn:fortress:schema:v1:supported-qualification-scope","schema_version":1,
        "scope_id":"fixture-scope","effects":["filesystem.write","process.spawn"],
        "strata":["NEGATIVE","POSITIVE","UNKNOWN"],"exclusions":["No population or human validation."],
        "promotes_default_blocking":false,"human_validation":"RECOMMENDED_FUTURE_RESEARCH_NOT_PERFORMED"
    }).to_string()).unwrap()
}

fn qualification_fixture_record() -> (Value, QualificationInputs) {
    let mut identities = [
        "analyzer",
        "candidate_source",
        "catalog",
        "contexts",
        "corpus",
        "harness",
        "heldout_selection",
        "native_source",
        "oracle",
        "outcomes",
        "profiles",
        "protocol",
        "registry",
        "schemas",
        "staged_cli",
        "supported_scope",
        "toolchain",
    ]
    .into_iter()
    .map(|name| (name.to_owned(), format!("sha256:{}", "a".repeat(64))))
    .collect::<BTreeMap<_, _>>();
    identities.insert(
        "supported_scope".into(),
        qualification_fixture_scope().digest().unwrap(),
    );
    let inputs = QualificationInputs { identities };
    (
        json!({"$schema":"urn:fortress:derived:v1:semantic-qualification","schema_version":1,
        "status":"PASS","scope_id":"fixture-scope","inputs":inputs,
        "counts":{"declared_cases":12,"completed_cases":12,"required_cases":8,"required_passed":8,"mismatches":0,
            "positive":2,"negative":2,"conditional_negative":0,"unknown":2,"not_applicable":1,"invalid":1,"execution_failures":0,"authorization":2,"undeclared":2,
            "distinct_source_sites":2,"claims":8,"causal_paths":5,"declared_mutations":3,"exercised_mutations":3,
            "equal_differentials":11,"equal_metadata_controls":11,"invalid_port_equivalences":1,"external_positive_scopes":1},
        "limitations":{"independent_human_adjudication":false,"population_precision":null,
            "real_world_false_positive_rate":null,"statistical_confidence":null,"independent_external_assurance":false,
            "reasons":["Automated deterministic envelope only.","No independent human validation."]}}),
        inputs,
    )
}

/// `T-AF-CERTIFICATION-0001-R07-001`
/// Fortress requirement: AF-CERTIFICATION-0001-R07
#[test]
fn tool_qualification_scope_never_changes_application_truth_or_sufficiency() {
    let (record, current) = qualification_fixture_record();
    let report = QualificationManifest::from_json_str(&record.to_string()).unwrap();
    let scope = qualification_fixture_scope();
    for truth in [
        DeclarationTruth::SupportedViolation,
        DeclarationTruth::NoSupportedViolation,
        DeclarationTruth::NotEvaluable,
        DeclarationTruth::NotApplicable,
        DeclarationTruth::Authorization,
    ] {
        let (declaration, expected, evidence, policy) = fixture(truth);
        let before = declaration.to_canonical_bytes().unwrap();
        let assessment =
            ProfileAssessment::evaluate(&declaration, &expected, &evidence, &policy).unwrap();
        let observation = declaration
            .qualification_scope(&report, &current, &scope)
            .unwrap();
        assert_eq!(
            observation.declaration_digest,
            declaration.digest().unwrap()
        );
        assert_eq!(observation.subject_ref, declaration.binding.subject_ref);
        assert_eq!(observation.classification, "TOOL_CAPABILITY_METADATA");
        assert!(!observation.application_evidence);
        assert_eq!(observation.authenticity, "UNVERIFIED");
        assert_eq!(declaration.to_canonical_bytes().unwrap(), before);
        assert_eq!(
            ProfileAssessment::evaluate(&declaration, &expected, &evidence, &policy).unwrap(),
            assessment
        );
        assert!(
            serde_json::from_value::<AssessmentEvidence>(
                serde_json::to_value(&observation).unwrap()
            )
            .is_err()
        );
        assert_advertised_schema(&observation);
    }
    let (declaration, _, _, _) = fixture(DeclarationTruth::NotEvaluable);
    let mut stale = current;
    stale.identities.insert(
        "candidate_source".into(),
        format!("sha256:{}", "f".repeat(64)),
    );
    assert!(
        declaration
            .qualification_scope(&report, &stale, &scope)
            .is_err()
    );
}

fn verify_capture_references(
    root: &std::path::Path,
    destination: &std::path::Path,
    state_path: &std::path::Path,
    predicate: &str,
) {
    use std::process::Command;
    let matched = Command::new(if cfg!(windows) { "python" } else { "python3" })
        .args(["-I", "-B"])
        .arg(root.join("testing/_code/verify_bundle.py"))
        .arg(destination)
        .args(["--predicate-type", predicate, "--current-state"])
        .arg(state_path)
        .output()
        .unwrap();
    assert!(
        matched.status.success(),
        "{}",
        String::from_utf8_lossy(&matched.stdout)
    );
    let matched: serde_json::Value = serde_json::from_slice(&matched.stdout).unwrap();
    assert_eq!(matched["freshness"], "MATCHES_SUPPLIED_REFERENCES");
    assert_eq!(matched["assurance"], "UNVERIFIED");
    let stale = Command::new(if cfg!(windows) { "python" } else { "python3" })
        .args(["-I", "-B"])
        .arg(root.join("testing/_code/verify_bundle.py"))
        .arg(destination)
        .args([
            "--predicate-type",
            predicate,
            "--expected-subject",
            &digest(),
        ])
        .output()
        .unwrap();
    assert_eq!(stale.status.code(), Some(1));
    let stale: serde_json::Value = serde_json::from_slice(&stale.stdout).unwrap();
    assert_eq!(stale["freshness"], "STALE");
}
