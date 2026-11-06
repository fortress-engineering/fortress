//! Independent provider-admission vectors; no application result is its own oracle.

use fortress_core::assessment::AssessmentDecision;
use fortress_core::declaration::DeclarationBinding;
use fortress_core::provider::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn digest(letter: char) -> String {
    format!("sha256:{}", letter.to_string().repeat(64))
}
fn key(package: &str, name: &str) -> InventoryKey {
    InventoryKey {
        namespace: InventoryNamespace::NativeQualified,
        package: Some(package.into()),
        target: Some("unit".into()),
        qualified_name: name.into(),
    }
}
fn fixture() -> (
    EvidenceEnvelope,
    ProviderRequirementBinding,
    DeclarationBinding,
) {
    let binding = DeclarationBinding {
        subject_ref: digest('a'),
        context_ref: digest('b'),
        authority_ref: digest('c'),
    };
    let key = key("native-project", "test_math.MathTests.test_add");
    let invocation = InvocationOutcome {
        succeeded: Some(true),
        exit_code: Some(0),
    };
    let raw=b"<testsuite name=\"unit\" package=\"native-project\"><testcase name=\"test_math.MathTests.test_add\"/></testsuite>";
    let manifest = ProviderRunManifest {
        binding: binding.clone(),
        provider: "native-unit-runner".into(),
        provider_version: "1.0".into(),
        invocation_scope: "unit".into(),
        execution: ExecutionDescriptor {
            binary_digest: Some(digest('d')),
            tool_digest: Some(digest('e')),
            arguments: Some(vec!["-m".into(), "unittest".into()]),
            working_directory: Some(ExecutionDirectory::SubjectRoot),
            inputs: vec![ExecutionInput {
                name: "subject".into(),
                digest: binding.subject_ref.clone(),
            }],
            environment_dependencies: vec![],
            dependencies_complete: true,
        },
        inventory: vec![InventoryMember {
            key: key.clone(),
            enabled: true,
        }],
        inventory_complete: true,
        filters: vec![],
        filtering_known: true,
        attempts_complete: true,
        attempts: vec![AttemptCount {
            key: key.clone(),
            count: 1,
        }],
        invocation: invocation.clone(),
        payload_digest: format!("sha256:{:x}", Sha256::digest(raw)),
        assumptions: vec![],
    };
    let requirement = ProviderRequirementBinding {
        requirement_id: "AF-NATIVE-MATH-R01".into(),
        provider: manifest.provider.clone(),
        invocation_scope: "unit".into(),
        selectors: vec![NativeTestSelector {
            namespace: key.namespace,
            package: key.package.clone(),
            target: key.target.clone(),
            qualified_name: key.qualified_name.clone(),
        }],
        authenticated_producer_required: false,
    };
    let envelope = EvidenceEnvelope::compose(
        ProviderFormat::JunitXml,
        Some(manifest.provider.clone()),
        Some(manifest.provider_version.clone()),
        manifest.payload_digest.clone(),
        Some(manifest),
        vec![ProviderObservation {
            key,
            outcome: ProviderOutcome::Passed,
            attempts: None,
            retry_metadata_present: false,
            finding_count: None,
        }],
        invocation,
        InvocationBasis::CompanionManifest,
        vec![],
    )
    .unwrap();
    (envelope, requirement, binding)
}
fn policy(envelope: &EvidenceEnvelope) -> ProviderAcceptancePolicy {
    let digest = envelope.digest().unwrap();
    let mut policy = ProviderAcceptancePolicy::default();
    policy.admitted_envelopes = BTreeSet::from([digest.clone()]);
    policy.current_executions = BTreeMap::from([(
        digest,
        envelope.run_manifest.as_ref().unwrap().execution.clone(),
    )]);
    policy
}

fn input_set(
    envelope: &EvidenceEnvelope,
    binding: DeclarationBinding,
) -> fortress_core::provider_inputs::EvidenceInputSet {
    use fortress_core::provider_inputs::{EvidenceInputSet, ProviderInputIdentity};
    EvidenceInputSet::compose(
        binding,
        vec![ProviderInputIdentity {
            envelope_digest: envelope.digest().unwrap(),
            payload_digest: envelope.payload_digest.clone(),
            inventory_digest: Some(envelope.inventory_digest().unwrap()),
        }],
    )
    .unwrap()
}

/// `T-AF-CERTIFICATION-0001-R06-013`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn complete_external_manifest_survives_missing_bindings_and_deleted_report_bytes() {
    use fortress_core::provider_inputs::{ApplicationProviderEvidence, VerificationBindings};
    let (envelope, requirement, binding) = fixture();
    let selection = input_set(&envelope, binding);
    let required = BTreeSet::from([requirement.requirement_id.clone()]);
    let missing = ApplicationProviderEvidence::prepare(
        selection.clone(),
        &required,
        &VerificationBindings::compose(vec![]).unwrap(),
        &BTreeMap::new(),
        &mut ProviderAcceptancePolicy::default(),
    )
    .unwrap();
    assert_eq!(missing.obligations.len(), 1);
    assert!(missing.obligations[0].proof.is_none());
    let authored = VerificationBindings::compose(vec![requirement]).unwrap();
    let available = BTreeMap::from([(envelope.digest().unwrap(), envelope.clone())]);
    let supported = ApplicationProviderEvidence::prepare(
        selection.clone(),
        &required,
        &authored,
        &available,
        &mut policy(&envelope),
    )
    .unwrap();
    assert!(supported.obligations[0].proof.is_some());
    assert_eq!(
        supported.resolutions[0].decision,
        AssessmentDecision::Satisfied
    );
    let deleted = ApplicationProviderEvidence::prepare(
        selection.clone(),
        &required,
        &authored,
        &BTreeMap::new(),
        &mut policy(&envelope),
    )
    .unwrap();
    assert!(deleted.obligations[0].proof.is_none());
    assert_eq!(deleted.obligations[0].id, supported.obligations[0].id);
    assert_eq!(
        deleted.input_set.digest().unwrap(),
        supported.input_set.digest().unwrap()
    );
    assert_eq!(
        missing.input_set.digest().unwrap(),
        selection.digest().unwrap()
    );
}

/// `T-AF-CERTIFICATION-0001-R06-014`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn provider_selection_refuses_substitution_foreign_authoring_and_latest_green_fallback() {
    use fortress_core::provider_inputs::{ApplicationProviderEvidence, VerificationBindings};
    let (envelope, requirement, binding) = fixture();
    let mut selection = input_set(&envelope, binding);
    let authored = VerificationBindings::compose(vec![requirement.clone()]).unwrap();
    let required = BTreeSet::from([requirement.requirement_id]);
    let available = BTreeMap::from([(envelope.digest().unwrap(), envelope.clone())]);
    selection.selected[0].payload_digest = digest('a');
    assert!(
        ApplicationProviderEvidence::prepare(
            selection,
            &required,
            &authored,
            &available,
            &mut policy(&envelope)
        )
        .is_err()
    );
    let selection = input_set(
        &envelope,
        envelope.run_manifest.as_ref().unwrap().binding.clone(),
    );
    assert!(
        ApplicationProviderEvidence::prepare(
            selection.clone(),
            &BTreeSet::new(),
            &authored,
            &available,
            &mut policy(&envelope)
        )
        .is_err()
    );
    let empty = fortress_core::provider_inputs::EvidenceInputSet::compose(
        selection.binding.clone(),
        vec![],
    )
    .unwrap();
    assert!(
        ApplicationProviderEvidence::prepare(
            empty,
            &required,
            &authored,
            &available,
            &mut policy(&envelope)
        )
        .is_err()
    );
    let mut another = envelope.clone();
    another.provider_version = Some("2.0".into());
    another.run_manifest.as_mut().unwrap().provider_version = "2.0".into();
    let mut selected = selection.selected;
    selected.push(
        input_set(&another, selection.binding.clone())
            .selected
            .remove(0),
    );
    selected.sort();
    let selection =
        fortress_core::provider_inputs::EvidenceInputSet::compose(selection.binding, selected)
            .unwrap();
    let available = BTreeMap::from([
        (envelope.digest().unwrap(), envelope),
        (another.digest().unwrap(), another),
    ]);
    let result = ApplicationProviderEvidence::prepare(
        selection,
        &required,
        &authored,
        &available,
        &mut ProviderAcceptancePolicy::default(),
    )
    .unwrap();
    assert_eq!(result.obligations.len(), 1);
    assert!(result.obligations[0].proof.is_none());
}
fn decision(
    envelope: &EvidenceEnvelope,
    requirement: &ProviderRequirementBinding,
    binding: &DeclarationBinding,
) -> ProviderResolution {
    PreparedProvider::new(envelope, binding, &mut policy(envelope))
        .unwrap()
        .resolve_requirement(requirement)
        .unwrap()
}

/// `T-AF-CERTIFICATION-0001-R06-001`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn exact_admitted_native_members_preserve_unsigned_provenance_and_canonical_bytes() {
    let (envelope, requirement, binding) = fixture();
    assert!(envelope.full_success());
    let result = decision(&envelope, &requirement, &binding);
    assert_eq!(result.decision, AssessmentDecision::Satisfied);
    assert_eq!(
        result.members[0].qualified_name,
        "test_math.MathTests.test_add"
    );
    assert!(!result.members[0].qualified_name.starts_with("T-"));
    assert_eq!(envelope.authenticity, "UNVERIFIED");
    let bytes = envelope.to_canonical_bytes().unwrap();
    assert_eq!(
        EvidenceEnvelope::from_json_str(std::str::from_utf8(&bytes).unwrap()).unwrap(),
        envelope
    );
    assert_eq!(
        EvidenceEnvelope::from_json_str(std::str::from_utf8(&bytes).unwrap())
            .unwrap()
            .to_canonical_bytes()
            .unwrap(),
        bytes
    );
}

/// `T-AF-CERTIFICATION-0001-R06-002`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn every_exact_binding_axis_is_mandatory_even_when_other_digests_are_equal() {
    let (envelope, requirement, binding) = fixture();
    for axis in ["subject", "context", "authority"] {
        let mut altered = envelope.clone();
        let b = &mut altered.run_manifest.as_mut().unwrap().binding;
        match axis {
            "subject" => b.subject_ref = digest('b'),
            "context" => b.context_ref = digest('a'),
            _ => b.authority_ref = digest('a'),
        }
        let result = decision(&altered, &requirement, &binding);
        assert_eq!(result.decision, AssessmentDecision::NotEvaluable);
        assert!(result.blockers.contains(&ProviderBlocker::WrongBinding));
    }
}

/// `T-AF-CERTIFICATION-0001-R06-003`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn zero_missing_or_partial_inventory_never_manufactures_success() {
    let (mut envelope, requirement, binding) = fixture();
    envelope.observations.clear();
    assert!(!envelope.full_success());
    assert_eq!(
        decision(&envelope, &requirement, &binding).decision,
        AssessmentDecision::NotEvaluable
    );
    let manifest = envelope.run_manifest.as_mut().unwrap();
    manifest.inventory.clear();
    manifest.attempts.clear();
    assert!(!envelope.inventory_accounted());
    assert!(
        decision(&envelope, &requirement, &binding)
            .blockers
            .contains(&ProviderBlocker::IncompleteInventory)
    );
    envelope.run_manifest = None;
    envelope.invocation = InvocationOutcome::default();
    envelope.invocation_basis = InvocationBasis::Unknown;
    let result = PreparedProvider::new(
        &envelope,
        &binding,
        &mut ProviderAcceptancePolicy::default(),
    )
    .unwrap()
    .resolve_requirement(&requirement)
    .unwrap();
    assert_eq!(result.decision, AssessmentDecision::NotEvaluable);
}

/// `T-AF-CERTIFICATION-0001-R06-004`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn filters_ignored_unknown_and_retry_rows_cannot_satisfy_full_execution() {
    let (base, requirement, binding) = fixture();
    for kind in ["filter", "ignored", "unknown", "retry"] {
        let mut envelope = base.clone();
        match kind {
            "filter" => envelope
                .run_manifest
                .as_mut()
                .unwrap()
                .filters
                .push("test_add".into()),
            "ignored" => {
                envelope.run_manifest.as_mut().unwrap().inventory[0].enabled = false;
                envelope.observations[0].outcome = ProviderOutcome::Skipped;
            }
            "unknown" => envelope.observations[0].outcome = ProviderOutcome::Unknown,
            _ => {
                envelope.run_manifest.as_mut().unwrap().attempts[0].count = 2;
                envelope.observations[0].attempts = Some(2);
                envelope.observations[0].retry_metadata_present = true;
            }
        }
        assert!(!envelope.full_success(), "{kind}");
        assert_eq!(
            decision(&envelope, &requirement, &binding).decision,
            AssessmentDecision::NotEvaluable,
            "{kind}"
        );
    }
}

/// `T-AF-CERTIFICATION-0001-R06-005`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn native_selector_ambiguity_requires_explicit_authoring_review() {
    let (mut envelope, mut requirement, binding) = fixture();
    let other = key(
        "other-package",
        &envelope.observations[0].key.qualified_name,
    );
    let manifest = envelope.run_manifest.as_mut().unwrap();
    manifest.inventory.push(InventoryMember {
        key: other.clone(),
        enabled: true,
    });
    manifest.attempts.push(AttemptCount {
        key: other.clone(),
        count: 1,
    });
    envelope.observations.push(ProviderObservation {
        key: other,
        outcome: ProviderOutcome::Passed,
        attempts: Some(1),
        retry_metadata_present: false,
        finding_count: None,
    });
    requirement.selectors[0].package = None;
    requirement.selectors[0].target = None;
    let result = decision(&envelope, &requirement, &binding);
    assert!(
        result
            .blockers
            .contains(&ProviderBlocker::SelectorRequiresReview)
    );
    requirement.selectors[0].package = Some("native-project".into());
    requirement.selectors[0].target = Some("unit".into());
    assert_eq!(
        decision(&envelope, &requirement, &binding).decision,
        AssessmentDecision::Satisfied
    );
    envelope.observations.push(envelope.observations[0].clone());
    assert!(envelope.validate().is_err());
}

/// `T-AF-CERTIFICATION-0001-R06-006`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn producer_names_and_forged_fresh_or_authentication_fields_are_not_authority() {
    let (envelope, mut requirement, binding) = fixture();
    let result = PreparedProvider::new(
        &envelope,
        &binding,
        &mut ProviderAcceptancePolicy::default(),
    )
    .unwrap()
    .resolve_requirement(&requirement)
    .unwrap();
    assert!(
        result
            .blockers
            .contains(&ProviderBlocker::UntrustedEnvelope)
    );
    requirement.authenticated_producer_required = true;
    assert!(
        decision(&envelope, &requirement, &binding)
            .blockers
            .contains(&ProviderBlocker::ProducerNotAuthenticated)
    );
    let mut value = serde_json::to_value(&envelope).unwrap();
    value["authenticity"] = serde_json::json!("AUTHENTICATED");
    assert!(EvidenceEnvelope::from_json_str(&value.to_string()).is_err());
    value = serde_json::to_value(&envelope).unwrap();
    value["fresh"] = serde_json::json!(true);
    assert!(EvidenceEnvelope::from_json_str(&value.to_string()).is_err());
}

/// `T-AF-CERTIFICATION-0001-R06-007`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn unknown_dependencies_force_fresh_even_after_hash_admission() {
    let (mut envelope, requirement, binding) = fixture();
    envelope
        .run_manifest
        .as_mut()
        .unwrap()
        .execution
        .dependencies_complete = false;
    let mut host = policy(&envelope);
    host.authenticated_envelopes
        .insert(envelope.digest().unwrap());
    let result = PreparedProvider::new(&envelope, &binding, &mut host)
        .unwrap()
        .resolve_requirement(&requirement)
        .unwrap();
    assert_eq!(result.decision, AssessmentDecision::NotEvaluable);
    assert!(
        result
            .blockers
            .contains(&ProviderBlocker::FreshExecutionRequired)
    );
    let descriptor = &mut envelope.run_manifest.as_mut().unwrap().execution;
    descriptor.binary_digest = None;
    descriptor.arguments = None;
    descriptor.working_directory = None;
    assert!(envelope.validate().is_ok());
    assert!(
        !envelope
            .run_manifest
            .as_ref()
            .unwrap()
            .execution
            .reusable_for(host.current_executions.values().next().unwrap())
    );
}

/// `T-AF-CERTIFICATION-0001-R06-008`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn changed_binary_tool_input_argv_or_environment_refuses_reuse() {
    let (envelope, requirement, binding) = fixture();
    for axis in ["binary", "tool", "input", "argv", "environment"] {
        let mut host = policy(&envelope);
        let current = host.current_executions.values_mut().next().unwrap();
        match axis {
            "binary" => current.binary_digest = Some(digest('f')),
            "tool" => current.tool_digest = Some(digest('f')),
            "input" => current.inputs[0].digest = digest('f'),
            "argv" => current.arguments.as_mut().unwrap().push("--changed".into()),
            _ => current.environment_dependencies.push(ExecutionInput {
                name: "external-service".into(),
                digest: digest('f'),
            }),
        }
        let result = PreparedProvider::new(&envelope, &binding, &mut host)
            .unwrap()
            .resolve_requirement(&requirement)
            .unwrap();
        assert!(
            result.blockers.contains(&ProviderBlocker::StaleExecution),
            "{axis}"
        );
    }
}

/// `T-AF-CERTIFICATION-0001-R06-009`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn known_current_execution_failure_is_not_missing_or_a_module_violation() {
    let (mut envelope, requirement, binding) = fixture();
    envelope.observations[0].outcome = ProviderOutcome::Failed;
    envelope.invocation.succeeded = Some(false);
    envelope.invocation.exit_code = Some(1);
    envelope.run_manifest.as_mut().unwrap().invocation = envelope.invocation.clone();
    assert!(envelope.inventory_accounted());
    assert!(!envelope.full_success());
    let result = decision(&envelope, &requirement, &binding);
    assert_eq!(result.decision, AssessmentDecision::NotSatisfied);
    assert_eq!(result.blockers, vec![ProviderBlocker::ExecutionFailed]);
    assert!(
        result
            .evidence
            .iter()
            .any(|e| e.proposition
                == fortress_core::assessment::EvidenceProposition::ExecutionFailed)
    );
    let result = PreparedProvider::new(
        &envelope,
        &binding,
        &mut ProviderAcceptancePolicy::default(),
    )
    .unwrap()
    .resolve_requirement(&requirement)
    .unwrap();
    assert_eq!(result.decision, AssessmentDecision::NotEvaluable);
}

/// `T-AF-CERTIFICATION-0001-R06-010`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn conditional_provider_premises_are_explicit_and_do_not_authorize_static_assumptions() {
    let (mut envelope, requirement, binding) = fixture();
    envelope.run_manifest.as_mut().unwrap().assumptions = vec!["network-disabled".into()];
    assert!(
        decision(&envelope, &requirement, &binding)
            .blockers
            .contains(&ProviderBlocker::AssumptionNotAccepted)
    );
    let mut host = policy(&envelope);
    host.accepted_assumptions.insert("network-disabled".into());
    let result = PreparedProvider::new(&envelope, &binding, &mut host)
        .unwrap()
        .resolve_requirement(&requirement)
        .unwrap();
    assert_eq!(result.decision, AssessmentDecision::Satisfied);
    assert!(
        result
            .evidence
            .iter()
            .flat_map(|e| &e.assumptions)
            .all(|a| a.starts_with("provider-assumption:sha256:"))
    );
}

/// `T-AF-CERTIFICATION-0001-R06-011`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn completed_sarif_with_findings_never_becomes_executed_test_evidence() {
    let (mut envelope, requirement, binding) = fixture();
    envelope.format = ProviderFormat::Sarif210;
    envelope.media_type = envelope.format.media_type().into();
    envelope.invocation_basis = InvocationBasis::Payload;
    envelope.observations[0].outcome = ProviderOutcome::Failed;
    envelope.observations[0].finding_count = Some(1);
    assert!(envelope.inventory_accounted());
    assert_eq!(envelope.invocation.succeeded, Some(true));
    let result = decision(&envelope, &requirement, &binding);
    assert!(
        result
            .blockers
            .contains(&ProviderBlocker::IncompatibleEvidenceClass)
    );
    assert!(result.evidence.is_empty());
}

/// `T-AF-CERTIFICATION-0001-R06-012`
/// Fortress requirement: AF-CERTIFICATION-0001-R06
#[test]
fn duplicate_keys_inexact_counts_and_normalized_amplification_are_refused() {
    let (envelope, _, _) = fixture();
    let json = String::from_utf8(envelope.to_canonical_bytes().unwrap()).unwrap();
    let duplicate = json.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(EvidenceEnvelope::from_json_str(&duplicate).is_err());
    let large = json.replacen("\"count\":1", "\"count\":9007199254740992", 1);
    assert_ne!(large, json);
    assert!(EvidenceEnvelope::from_json_str(&large).is_err());
    let mut amplified = envelope.clone();
    let package = "p".repeat(60_000);
    let mut inventory = vec![];
    let mut attempts = vec![];
    let mut observations = vec![];
    for i in 0..500 {
        let key = key(&package, &format!("case_{i:04}"));
        inventory.push(InventoryMember {
            key: key.clone(),
            enabled: true,
        });
        attempts.push(AttemptCount {
            key: key.clone(),
            count: 1,
        });
        observations.push(ProviderObservation {
            key,
            outcome: ProviderOutcome::Passed,
            attempts: Some(1),
            retry_metadata_present: false,
            finding_count: None,
        });
    }
    let m = amplified.run_manifest.as_mut().unwrap();
    m.inventory = inventory;
    m.attempts = attempts;
    amplified.observations = observations;
    assert!(matches!(
        amplified.validate(),
        Err(ProviderError::ResourceLimit(_))
    ));
}
