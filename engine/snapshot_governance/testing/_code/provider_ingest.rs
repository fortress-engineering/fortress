//! Independent raw-provider controls; no report can authorize project execution.

use fortress_core::evidence_ingest::{ingest_junit_observations, ingest_sarif};
use fortress_core::provider::{InvocationOutcome, ProviderOutcome};

#[path = "provider_fixture.rs"]
mod provider_fixture;

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn junit_preserves_native_names_and_distinct_terminal_states_without_inventing_execution() {
    let xml=br#"<testsuite name="unit" tests="4" failures="1" errors="1" skipped="1"><testcase classname="tests.Math" name="add"/><testcase name="fail"><failure/></testcase><testcase name="error"><error/></testcase><testcase name="skip"><skipped/></testcase></testsuite>"#;
    let e = ingest_junit_observations(xml).unwrap();
    assert_eq!(e.observations.len(), 4);
    assert!(
        e.observations
            .iter()
            .any(|r| r.key.qualified_name == "tests.Math::add"
                && r.outcome == ProviderOutcome::Passed)
    );
    assert_eq!(
        e.observations
            .iter()
            .filter(|r| r.outcome == ProviderOutcome::Failed)
            .count(),
        2
    );
    assert!(e.observations.iter().all(|r| r.attempts.is_none()));
    assert_eq!(e.invocation, InvocationOutcome::default());
    assert!(e.provider.is_none());
    assert!(!e.full_success());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn junit_rejects_duplicate_ids_terminal_conflicts_counts_and_xml_authority_extensions() {
    for xml in [
        r#"<testsuite><testcase name="a"/><testcase name="a"/></testsuite>"#,
        r#"<testsuite><testcase name="a"><failure/><error/></testcase></testsuite>"#,
        r#"<!DOCTYPE testsuite [<!ENTITY x "evil">]><testsuite/>"#,
        r#"<testsuite xmlns="https://unregistered.example"/>"#,
        r#"<?xml version="1.1"?><testsuite/>"#,
        r"<testsuite/><testsuite/>",
    ] {
        assert!(ingest_junit_observations(xml.as_bytes()).is_err(), "{xml}");
    }
    let mismatch =
        ingest_junit_observations(br#"<testsuite tests="2"><testcase name="a"/></testsuite>"#)
            .unwrap();
    assert!(
        mismatch
            .limitations
            .iter()
            .any(|l| l == "JUNIT_DECLARED_COUNT_MISMATCH:tests")
    );
    assert!(!mismatch.full_success());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn junit_retry_metadata_and_empty_reports_cannot_establish_complete_success() {
    let e = ingest_junit_observations(
        br#"<testsuite><testcase name="native.test"><flakyFailure/></testcase></testsuite>"#,
    )
    .unwrap();
    assert!(e.observations[0].retry_metadata_present);
    assert!(e.observations[0].attempts.is_none());
    assert!(!e.full_success());
    assert!(
        !ingest_junit_observations(b"<testsuites/>")
            .unwrap()
            .inventory_accounted()
    );
}

fn sarif(results: &str, invocation: &str) -> Vec<u8> {
    format!(r#"{{"version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"independent-checker","version":"1","rules":[{{"id":"R1"}}]}}}},"invocations":[{invocation}],"results":{results}}}]}}"#).into_bytes()
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn sarif_success_with_findings_is_observation_and_empty_results_are_not_inventory() {
    let e = ingest_sarif(
        &sarif(
            r#"[{"ruleId":"R1","ruleIndex":0}]"#,
            r#"{"executionSuccessful":true,"exitCode":0}"#,
        ),
        None,
    )
    .unwrap();
    assert_eq!(e.invocation.succeeded, Some(true));
    assert_eq!(e.observations[0].outcome, ProviderOutcome::Failed);
    assert_eq!(e.observations[0].finding_count, Some(1));
    assert!(!e.full_success());
    let empty = ingest_sarif(&sarif("[]", r#"{"executionSuccessful":true}"#), None).unwrap();
    assert!(empty.observations.is_empty());
    assert!(!empty.inventory_accounted());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn sarif_missing_results_status_and_configuration_failure_remain_visible() {
    let e = ingest_sarif(&sarif("null", r#"{"exitCode":0}"#), None).unwrap();
    assert_eq!(e.invocation.succeeded, None);
    assert!(
        e.limitations
            .iter()
            .any(|l| l == "SARIF_RESULTS_UNAVAILABLE")
    );
    let e = ingest_sarif(
        &sarif(
            "[]",
            r#"{"executionSuccessful":true,"toolConfigurationNotifications":[{"level":"error"}]}"#,
        ),
        None,
    )
    .unwrap();
    assert_eq!(e.invocation.succeeded, Some(false));
    assert!(!e.full_success());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-006`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn sarif_rejects_ambiguous_scope_duplicate_keys_and_conflicting_rule_references() {
    for bytes in [
        sarif(r#"[{"ruleId":"OTHER","ruleIndex":0}]"#, r"{}"),
        sarif(r#"[{"ruleIndex":9007199254740992}]"#, r"{}"),
        br#"{"version":"2.1.0","version":"2.1.0","runs":[]}"#.to_vec(),
        br#"{"version":"2.1.0","runs":[{},{}]}"#.to_vec(),
    ] {
        assert!(ingest_sarif(&bytes, None).is_err());
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-007`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn retained_payload_reproduces_canonical_observations_and_exact_hash() {
    use sha2::{Digest, Sha256};
    let payload =
        "<testsuite name=\"unit\"><testcase name=\"native.é&amp;λ\"/></testsuite>".as_bytes();
    let a = ingest_junit_observations(payload).unwrap();
    let b = ingest_junit_observations(payload).unwrap();
    assert_eq!(
        a.to_canonical_bytes().unwrap(),
        b.to_canonical_bytes().unwrap()
    );
    assert_eq!(
        a.payload_digest,
        format!("sha256:{:x}", Sha256::digest(payload))
    );
    assert_eq!(a.observations[0].key.qualified_name, "native.é&λ");
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn parser_resource_limits_precede_unbounded_normalized_or_structural_growth() {
    let nested = format!(
        "{}{}",
        "<testsuites>".repeat(65),
        "</testsuites>".repeat(65)
    );
    assert!(ingest_junit_observations(nested.as_bytes()).is_err());
    let json = format!("{}0{}", "[".repeat(65), "]".repeat(65));
    assert!(ingest_sarif(json.as_bytes(), None).is_err());
    let long = "a".repeat(65_537);
    assert!(
        ingest_junit_observations(
            format!("<testsuite><testcase name=\"{long}\"/></testsuite>").as_bytes()
        )
        .is_err()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-009`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn selected_retained_pairs_replay_exact_raw_bytes_without_importing_project_code() {
    use fortress_core::evidence_ingest::load_selected_provider_inputs;
    use fortress_core::provider_inputs::{EvidenceInputSet, ProviderInputIdentity};
    let fixture = provider_fixture::NativeFixture::new();
    fixture.write(
        "tests/test_math.py",
        b"from pathlib import Path\nPath('executed').write_text('must never happen')\n",
    );
    let binding = fixture.binding();
    let payload=br#"<testsuite name="unit" package="native-project"><testcase name="native.case"/></testsuite>"#;
    let envelope = ingest_junit_observations(payload).unwrap();
    let id = envelope.digest().unwrap();
    let directory = format!(
        "__fortress/evidence/imports/{}",
        id.strip_prefix("sha256:").unwrap()
    );
    fixture.write(
        &format!("{directory}/envelope.json"),
        &envelope.to_canonical_bytes().unwrap(),
    );
    fixture.write(&format!("{directory}/payload.bin"), payload);
    let selection = EvidenceInputSet::compose(
        binding,
        vec![ProviderInputIdentity {
            envelope_digest: id.clone(),
            payload_digest: envelope.payload_digest.clone(),
            inventory_digest: None,
        }],
    )
    .unwrap();
    assert_eq!(
        load_selected_provider_inputs(&fixture.root, &selection).unwrap()[&id],
        envelope
    );
    assert!(!fixture.root.join("executed").exists());
    fixture.write(&format!("{directory}/payload.bin"), b"substituted");
    assert!(load_selected_provider_inputs(&fixture.root, &selection).is_err());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-010`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn actual_native_suite_needs_explicit_physical_trust_and_fresh_admission_preserving_source_paths() {
    use fortress_core::assessment::AssessmentDecision;
    use fortress_core::evidence_ingest::{ProjectExecutionTrust, execute_registered_junit};
    use fortress_core::provider::ProviderAcceptancePolicy;
    let fixture = provider_fixture::NativeFixture::new();
    let binding = fixture.binding();
    let command = fixture.command();
    let before = fortress_core::audit::compile_repository_state_view(&fixture.root)
        .unwrap()
        .application
        .unwrap()
        .declaration
        .to_canonical_bytes()
        .unwrap();
    let mut executor = provider_fixture::NativeRunner {
        binding: binding.clone(),
        key: provider_fixture::NativeFixture::key(),
        calls: 0,
        leave_child_record: false,
        last_reaped_pid: None,
    };
    let storage = fixture.directory.join("storage");
    assert!(
        execute_registered_junit(
            &fixture.root,
            None,
            &command,
            &binding,
            &storage,
            provider_fixture::NativeFixture::policy(),
            &mut executor
        )
        .is_err()
    );
    let wrong = ProjectExecutionTrust::authorize(&fixture.directory, &command).unwrap();
    assert!(
        execute_registered_junit(
            &fixture.root,
            Some(&wrong),
            &command,
            &binding,
            &storage,
            provider_fixture::NativeFixture::policy(),
            &mut executor
        )
        .is_err()
    );
    assert_eq!(executor.calls, 0);
    let grant = ProjectExecutionTrust::authorize(&fixture.root, &command).unwrap();
    let actual = execute_registered_junit(
        &fixture.root,
        Some(&grant),
        &command,
        &binding,
        &storage,
        provider_fixture::NativeFixture::policy(),
        &mut executor,
    )
    .unwrap();
    assert_eq!(executor.calls, 1);
    assert!(actual.envelope.full_success());
    assert_eq!(
        actual.envelope.observations[0].key.qualified_name,
        "test_math.MathTests.test_add"
    );
    assert_eq!(actual.envelope.authenticity, "UNVERIFIED");
    let selection = fixture.retain(&actual.envelope, &actual.payload);
    let mut fresh = ProviderAcceptancePolicy::default();
    fresh.admit_fresh(actual.fresh_receipt);
    let view = fortress_core::audit::compile_repository_state_view_with_evidence(
        &fixture.root,
        &selection,
        &mut fresh,
    )
    .unwrap();
    view.validate().unwrap();
    let application = view.application.unwrap();
    let obligation = application
        .assessment
        .obligations
        .iter()
        .find(|o| o.id == "external-verification:AF-NATIVE-0001-R01")
        .unwrap();
    assert_eq!(obligation.decision, AssessmentDecision::Satisfied);
    assert_eq!(
        application.provider_requirements[0].members[0].qualified_name,
        "test_math.MathTests.test_add"
    );
    assert_eq!(
        application.declaration.to_canonical_bytes().unwrap(),
        before
    );
    assert_retained_requires_fresh(
        &fixture,
        &selection,
        &actual.envelope,
        &before,
        &obligation.id,
    );
}

fn assert_retained_requires_fresh(
    fixture: &provider_fixture::NativeFixture,
    selection: &fortress_core::provider_inputs::EvidenceInputSet,
    envelope: &fortress_core::provider::EvidenceEnvelope,
    before: &[u8],
    obligation_id: &str,
) {
    use fortress_core::assessment::AssessmentDecision;
    use fortress_core::provider::ProviderAcceptancePolicy;
    let envelope_id = envelope.digest().unwrap();
    let descriptor = envelope.run_manifest.as_ref().unwrap().execution.clone();
    let mut replay = ProviderAcceptancePolicy::default();
    replay.admitted_envelopes.insert(envelope_id.clone());
    replay
        .current_executions
        .insert(envelope_id.clone(), descriptor);
    let view = fortress_core::audit::compile_repository_state_view_with_evidence(
        &fixture.root,
        selection,
        &mut replay,
    )
    .unwrap();
    let application = view.application.unwrap();
    assert_eq!(
        application
            .assessment
            .obligations
            .iter()
            .find(|o| o.id == obligation_id)
            .unwrap()
            .decision,
        AssessmentDecision::NotEvaluable
    );
    assert_eq!(
        application.declaration.to_canonical_bytes().unwrap(),
        before
    );
    std::fs::remove_file(fixture.root.join(format!(
        "__fortress/evidence/imports/{}/payload.bin",
        envelope_id.strip_prefix("sha256:").unwrap()
    )))
    .unwrap();
    let deleted = fortress_core::audit::compile_repository_state_view_with_evidence(
        &fixture.root,
        selection,
        &mut replay,
    )
    .unwrap()
    .application
    .unwrap();
    assert!(
        deleted
            .obligations
            .iter()
            .any(|o| o.id == obligation_id && o.proof.is_none())
    );
    assert_eq!(deleted.declaration.to_canonical_bytes().unwrap(), before);
    assert!(
        fixture.root.join("src/math_ops.py").is_file()
            && fixture.root.join("tests/test_math.py").is_file()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-011`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn unresolved_actual_child_record_withholds_completion_until_its_owner_confirms_reaping() {
    use fortress_core::evidence_ingest::TrustedProviderExecutor;
    let fixture = provider_fixture::NativeFixture::new();
    let binding = fixture.binding();
    let command = fixture.command();
    let mut executor = provider_fixture::NativeRunner {
        binding,
        key: provider_fixture::NativeFixture::key(),
        calls: 0,
        leave_child_record: true,
        last_reaped_pid: None,
    };
    let runtime = fortress_core::runtime_storage::RuntimeStorage::new(
        &fixture.root,
        &fixture.directory.join("storage"),
        provider_fixture::NativeFixture::policy(),
    )
    .unwrap();
    let mut workspace = runtime.acquire_workspace().unwrap();
    let output = executor
        .execute(&fixture.root, &command, &mut workspace)
        .unwrap();
    assert!(output.process_succeeded);
    assert_eq!(executor.calls, 1);
    assert!(
        workspace.ensure_children_closed().is_err(),
        "a process success flag cannot clear an unresolved record"
    );
    workspace
        .clear_child(executor.last_reaped_pid.unwrap())
        .unwrap();
    workspace.ensure_children_closed().unwrap();
    workspace.validating().unwrap();
    workspace.publish("native-child-closure-control").unwrap();
    let report = workspace.release().unwrap();
    assert_eq!(report.lifecycle, "CLEANUP_COMPLETE");
    assert_eq!(report.retained_bytes, 0);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R20-012`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R20
#[test]
fn mixed_legacy_mapping_cannot_hide_external_intent_from_rust_only_qualification() {
    use fortress_core::certification::{
        CertificationObligationKind, CertificationStatus, RustSuiteExecution,
    };
    use serde_json::{Value, json};
    let fixture = provider_fixture::NativeFixture::new();
    let owner_path = fixture
        .root
        .join("_data/logical_modules/native/contract.json");
    let mut owner: Value = serde_json::from_slice(&std::fs::read(owner_path).unwrap()).unwrap();
    owner["features"][0]["requirements"][0]["tests"] = json!(["T-AF-NATIVE-0001-R01-001"]);
    let owner: fortress_core::contract_coherency::ModuleContract =
        serde_json::from_value(owner).unwrap();
    fixture.write(
        "_data/logical_modules/native/contract.json",
        owner.to_canonical_json().unwrap().as_bytes(),
    );
    let mut configuration: Value =
        serde_json::from_slice(&std::fs::read(fixture.root.join("__fortress/.fsconfig")).unwrap())
            .unwrap();
    configuration["logical_modules"][1]["bindings"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind":"file","path":"tests/legacy_verification.rs"}));
    configuration["logical_modules"][1]["bindings"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    fixture.write(
        "__fortress/.fsconfig",
        &serde_json::to_vec_pretty(&configuration).unwrap(),
    );
    fixture.write("Cargo.toml",b"[package]\nname='mixed-native-fixture'\nversion='0.1.0'\nedition='2024'\n[[test]]\nname='legacy'\npath='tests/legacy_verification.rs'\n");
    fixture.write("tests/legacy_verification.rs",b"/// `T-AF-NATIVE-0001-R01-001`\n/// Fortress requirement: AF-NATIVE-0001-R01\n#[test]\nfn legacy_addition() { assert_eq!(2+3,5); }\n");
    let profile = "engine/standard_registry/_data/cert_full_snapshot_v1.json";
    fixture.write(
        profile,
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(profile),
        )
        .unwrap(),
    );
    let source =
        fortress_core::audit::prepare_repository_certification_source(&fixture.root).unwrap();
    assert!(
        source
            .eligible_test_ids
            .iter()
            .any(|id| id == "T-AF-NATIVE-0001-R01-001")
    );
    // Adversarial synthetic execution input: no Rust process is run or claimed
    // as genuine evidence by this test. Even an alleged green legacy suite
    // cannot erase separately authored required external verification.
    let alleged = RustSuiteExecution {
        executor: "fortress-local-rust-executor".into(),
        executor_version: "1.0.0".into(),
        toolchain: "1.97.1".into(),
        certification_source_digest: source.digest,
        test_inventory_digest: source.test_inventory_digest,
        canonical_unfiltered: true,
        passed: true,
        eligible_test_ids: source.eligible_test_ids,
        ignored_test_ids: source.ignored_test_ids,
    };
    let bundle =
        fortress_core::audit::compile_repository_certification_bundle(&fixture.root, alleged)
            .unwrap();
    let product = bundle.into_products();
    let requirement = product
        .certification
        .obligations()
        .iter()
        .find(|o| {
            o.kind == CertificationObligationKind::FeatureRequirement
                && o.subject == "AF-NATIVE-0001-R01"
        })
        .unwrap();
    assert_eq!(requirement.status, CertificationStatus::Missing);
    assert!(requirement.reason.contains("external native"));
}
