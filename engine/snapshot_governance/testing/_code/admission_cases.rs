//! Canonical producer controls for introducing an authored rule on pinned source.
use super::{Fixture, fs};
use fortress_core::admission_load::{evaluate_authorized_admission, preview_repository_admission};
use fortress_core::development_governance::{
    Action, AuthorizationRule, GrantRequest, GrantValidation, GrantValidator, HostAssertion,
    NoGrantValidator, ProtectedClass, TrustedBasePolicy, UnmediatedHost,
};
use fortress_core::finding_governance::{
    ADMISSION_REVIEW_SCHEMA, AdmissionAssessment, AdmissionClassification as Origin,
    AdmissionDisposition, AdmissionReview, AdmissionReviewItem, FindingDisposition,
    FindingEnforcement, FindingLifecycle, lifecycle_bytes,
};
use fortress_core::migration_adapter::{
    CanonicalAdmissionMigrationAuthority, CanonicalMigrationAuthority, CanonicalMigrationEvaluator,
    TrustedAdmissionHistory,
};
use fortress_core::migration_governance::{
    MigrationEvaluator, MigrationOperation, MigrationOptions, MigrationServices, NoMutationFaults,
    apply_migration, preview_migration,
};
use fortress_core::runtime_storage::{MigrationStorage, StoragePolicy};
use std::collections::BTreeSet;
use std::sync::atomic::AtomicBool;

fn fixture() -> (Fixture, MigrationOperation) {
    let fixture = Fixture::with_violation();
    let original = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let (path, mut contract) = original
        .iter()
        .filter_map(|(path, bytes)| {
            serde_json::from_slice::<serde_json::Value>(bytes)
                .ok()
                .map(|value| (path, value))
        })
        .find(|(_, doc)| {
            doc["semantic_policy"]["capabilities"]["deny"]
                .as_array()
                .is_some_and(|denied| denied.contains(&serde_json::json!("filesystem")))
        })
        .expect("filesystem fixture contract");
    contract["semantic_policy"]["capabilities"]["deny"] = serde_json::json!([]);
    let authored = |doc| {
        serde_json::from_value::<fortress_core::contract_coherency::ModuleContract>(doc)
            .unwrap()
            .to_canonical_json()
            .unwrap()
    };
    fs::write(fixture.root.join(path), authored(contract.clone())).unwrap();
    contract["semantic_policy"]["effects"]["deny"] = serde_json::json!(["filesystem.read"]);
    let policy = fixture.replace(path, authored(contract).as_bytes());
    (fixture, policy)
}

fn accepted(report: &AdmissionAssessment, expiry: Option<u64>) -> AdmissionReview {
    let eligible = report
        .findings
        .iter()
        .filter(|row| row.classification == Origin::NewlyGoverned)
        .collect::<Vec<_>>();
    assert_eq!(eligible.len(), 1, "{:#?}", report.findings);
    AdmissionReview {
        schema: ADMISSION_REVIEW_SCHEMA.into(),
        schema_version: 1,
        assessment_ref: report.digest().unwrap(),
        decisions: vec![AdmissionReviewItem {
            finding_id: eligible[0].finding_id.clone(),
            disposition: AdmissionDisposition::AcceptExisting,
            rationale: "Exact filesystem read existed before the new effect prohibition.".into(),
            grant_ref: Some("external-review:fixture".into()),
        }],
        expires_at: expiry,
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R26-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R26
#[test]
fn new_policy_admits_only_preexisting_newly_governed_sites() {
    let (fixture, policy) = fixture();
    let evaluator = CanonicalMigrationEvaluator;
    let before = evaluator.observe(&fixture.root).unwrap();
    let result = preview_repository_admission(&fixture.root, vec![policy.clone()], &[]).unwrap();
    let workspace = fortress_core::candidate::CandidateWorkspace::open_cold(&fixture.root).unwrap();
    let request = fortress_core::candidate::CandidateRequest {
        schema_version: 1,
        base_source_ref: workspace.base_source_ref().into(),
        context_ref: workspace.context_ref().into(),
        operations: vec![policy.clone()],
        comparison_context: fortress_core::state_governance::ComparisonContext::default(),
    };
    assert_eq!(
        workspace
            .preview_governance_admission(request.clone(), &AtomicBool::new(true))
            .err()
            .unwrap()
            .code,
        "CANCELLED"
    );
    assert_eq!(
        workspace
            .preview_governance_admission(request, &AtomicBool::new(false))
            .unwrap()
            .assessment(),
        result.assessment()
    );
    let review = accepted(result.assessment(), None);
    let finding = result
        .assessment()
        .findings
        .iter()
        .find(|finding| finding.finding_id == review.decisions[0].finding_id)
        .unwrap();
    assert!(!finding.evidence_refs.is_empty());
    assert!(
        !finding.defeater_refs.is_empty(),
        "known positive proof must retain unresolved observations"
    );
    let draft = result.review(&review, None).unwrap();
    assert!(draft.proposed_governance().baseline().is_none());
    assert_eq!(draft.proposed_governance().admissions().len(), 1);
    let serialized = draft.proposed_governance().to_canonical_json().unwrap();
    assert_eq!(
        &fortress_core::finding_governance::FindingGovernanceDocument::from_json_str(&serialized)
            .unwrap(),
        draft.proposed_governance(),
    );
    assert_eq!(before, evaluator.observe(&fixture.root).unwrap());
    let bytes = lifecycle_bytes(result.assessment()).unwrap();
    assert_eq!(
        AdmissionAssessment::from_json_str(std::str::from_utf8(&bytes).unwrap())
            .unwrap()
            .digest()
            .unwrap(),
        review.assessment_ref
    );
    assert_eq!(
        bytes,
        lifecycle_bytes(
            preview_repository_admission(&fixture.root, vec![policy], &[])
                .unwrap()
                .assessment()
        )
        .unwrap()
    );
    let mut modified = serde_json::to_value(result.assessment()).unwrap();
    modified["findings"][0]["reason"] = serde_json::json!("Different reviewed evidence.");
    assert!(AdmissionAssessment::from_json_str(&modified.to_string()).is_err());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R26-006`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R26
#[test]
fn disable_reenable_does_not_reset_history() {
    let (fixture, change) = fixture();
    let former = preview_repository_admission(&fixture.root, vec![change.clone()], &[]).unwrap();
    let previous = former.pre_admission_state().clone();
    let restored = preview_repository_admission(&fixture.root, vec![change], &[previous]).unwrap();
    assert!(
        restored
            .assessment()
            .findings
            .iter()
            .any(|row| row.classification == Origin::PreviouslyGoverned)
    );
    assert!(
        restored
            .assessment()
            .findings
            .iter()
            .all(|row| row.classification != Origin::NewlyGoverned)
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R26-007`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R26
#[test]
fn old_violation_cannot_be_absorbed() {
    let fixture = Fixture::with_violation();
    let report = preview_repository_admission(&fixture.root, vec![], &[]).unwrap();
    assert!(
        report
            .assessment()
            .findings
            .iter()
            .any(|row| row.rule_id == "ARCH-SEMANTIC-001"
                && row.classification == Origin::ExistingViolation)
    );
    assert!(
        report
            .assessment()
            .findings
            .iter()
            .all(|row| row.classification != Origin::NewlyGoverned)
    );
    fs::write(fixture.root.join("src/lib.rs"), b"pub fn value() {}\n").unwrap();
    let regression = preview_repository_admission(
        &fixture.root,
        vec![fixture.replace(
            "src/lib.rs",
            b"pub fn value() { let _ = std::fs::read(\"input\"); }\n",
        )],
        &[],
    )
    .unwrap();
    assert!(
        regression
            .assessment()
            .findings
            .iter()
            .any(|row| row.rule_id == "ARCH-SEMANTIC-001"
                && row.classification == Origin::ImplementationRegression),
        "{:#?}",
        regression.assessment().findings
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R26-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R26
#[test]
fn profile_scope_changes_preserve_already_governed_findings() {
    let fixture = Fixture::with_violation();
    let path = "__fortress/.fsconfig";
    let mut configuration: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.root.join(path)).unwrap()).unwrap();
    let catalog: serde_json::Value =
        serde_json::from_str(fortress_core::profile::installed_profiles_source()).unwrap();
    let profile = catalog["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "ASSURE-SEMANTIC-EVALUABILITY")
        .unwrap();
    configuration["assurance_profiles"] = serde_json::json!([{
        "id": profile["id"], "version": profile["version"], "digest": profile["digest"]
    }]);
    let active = serde_json::to_vec(&configuration).unwrap();
    let operation = fixture.replace(path, &active);
    let activation =
        preview_repository_admission(&fixture.root, vec![operation.clone()], &[]).unwrap();
    assert!(
        activation
            .assessment()
            .findings
            .iter()
            .any(|f| f.rule_id == "ARCH-SEMANTIC-001"
                && f.classification == Origin::ExistingViolation)
    );
    assert!(
        activation
            .assessment()
            .findings
            .iter()
            .all(|f| f.classification != Origin::NewlyGoverned)
    );
    fs::write(fixture.root.join(path), active).unwrap();
    configuration["assurance_profiles"] = serde_json::json!([]);
    let deactivation = preview_repository_admission(
        &fixture.root,
        vec![fixture.replace(path, &serde_json::to_vec(&configuration).unwrap())],
        &[],
    )
    .unwrap();
    assert!(
        deactivation
            .assessment()
            .findings
            .iter()
            .all(|f| f.classification != Origin::NewlyGoverned)
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R26-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R26
#[test]
fn mixed_source_patch_is_not_auto_admitted() {
    let (fixture, policy) = fixture();
    let mixed = vec![
        policy,
        fixture.replace(
            "src/lib.rs",
            b"pub fn value() { let _ = std::fs::read(\"another\"); }\n",
        ),
    ];
    let assessment = preview_repository_admission(&fixture.root, mixed, &[]).unwrap();
    assert!(
        assessment
            .assessment()
            .findings
            .iter()
            .any(|f| f.classification == Origin::MixedChange)
    );
    assert!(
        assessment
            .assessment()
            .findings
            .iter()
            .all(|f| f.classification != Origin::NewlyGoverned)
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R26-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R26
#[test]
fn history_loss_and_review_disagreement_do_not_grant_treatment() {
    let (fixture, policy) = fixture();
    let unavailable = fortress_core::state_governance::ComparisonState::unavailable(None);
    let unknown =
        preview_repository_admission(&fixture.root, vec![policy.clone()], &[unavailable]).unwrap();
    assert!(
        unknown
            .assessment()
            .findings
            .iter()
            .any(|row| row.classification == Origin::OriginalHistoryUnavailable)
    );
    let evaluation = preview_repository_admission(&fixture.root, vec![policy], &[]).unwrap();
    let mut review = accepted(evaluation.assessment(), Some(10));
    assert!(evaluation.review(&review, None).is_err());
    assert!(evaluation.review(&review, Some(10)).is_err());
    assert!(evaluation.review(&review, Some(9)).is_ok());
    let accepted_item = review.decisions[0].clone();
    review.decisions[0].disposition = AdmissionDisposition::Defer;
    assert!(
        review
            .records(evaluation.assessment(), Some(9))
            .unwrap()
            .is_empty()
    );
    review.decisions[0].disposition = AdmissionDisposition::Reject;
    assert!(
        review
            .records(evaluation.assessment(), Some(9))
            .unwrap()
            .is_empty()
    );
    review.decisions.push(accepted_item);
    assert!(review.records(evaluation.assessment(), Some(9)).is_err());
}

fn trusted_policy(
    evaluated: &fortress_core::migration_governance::MigrationEvaluation,
) -> TrustedBasePolicy {
    let scopes = evaluated
        .protected_inputs
        .iter()
        .map(|p| p.scope.clone())
        .chain(std::iter::once("project".into()))
        .collect::<BTreeSet<_>>();
    let rules = scopes
        .into_iter()
        .enumerate()
        .map(|(index, scope)| AuthorizationRule {
            id: format!("fixture-rule-{index}"),
            classes: ProtectedClass::all().into_iter().collect(),
            actions: BTreeSet::from([Action::Create, Action::Replace]),
            scope,
            issuer_policy_ref: format!("sha256:{}", "6".repeat(64)),
        })
        .collect();
    TrustedBasePolicy::from_host(
        evaluated.state.digest().unwrap(),
        evaluated.state.governing_identity().unwrap().unwrap(),
        format!("sha256:{}", "7".repeat(64)),
        false,
        rules,
    )
    .unwrap()
}

struct FixtureGrant;
impl GrantValidator for FixtureGrant {
    fn validate(&self, request: &GrantRequest) -> GrantValidation {
        GrantValidation::Authenticated(Box::new(HostAssertion::for_request(
            request,
            "independent-test-only-owner",
            format!("sha256:{}", "8".repeat(64)),
            Some(50),
            None,
        )))
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R26-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R26
#[test]
fn reviewed_list_cannot_expand_during_apply() {
    let (fixture, operation) = fixture();
    let evaluator = CanonicalMigrationEvaluator;
    let before = evaluator.observe(&fixture.root).unwrap();
    let canonical = evaluator.evaluate(&before).unwrap();
    let proposal = preview_repository_admission(&fixture.root, vec![operation], &[]).unwrap();
    let review = accepted(proposal.assessment(), Some(40));
    let selected = review.decisions[0].finding_id.clone();
    let reviewed = proposal.review(&review, Some(3)).unwrap();
    let policy = trusted_policy(&canonical);
    let history =
        TrustedAdmissionHistory::from_host(canonical.state.digest().unwrap(), BTreeSet::new())
            .unwrap();
    let missing = CanonicalAdmissionMigrationAuthority {
        authority: CanonicalMigrationAuthority {
            policy: Some(&policy),
            host: &UnmediatedHost,
            validator: &NoGrantValidator,
            evaluation_time: Some(3),
            reviewed_initial_intent_ref: None,
            finding_proposal: None,
            identity_plan: None,
        },
        reviewed: &reviewed,
        history: Some(&history),
    };
    let preview = reviewed.preview(&evaluator, &missing).unwrap();
    assert_tampered_review_is_rejected(&before, &preview.plan, &missing, &selected);
    assert!(
        reviewed
            .authorize_preview(&preview, &missing, Some(3))
            .is_err()
    );
    assert_eq!(before, evaluator.observe(&fixture.root).unwrap());
    let authority = CanonicalAdmissionMigrationAuthority {
        authority: CanonicalMigrationAuthority {
            policy: Some(&policy),
            host: &UnmediatedHost,
            validator: &FixtureGrant,
            evaluation_time: Some(3),
            reviewed_initial_intent_ref: None,
            finding_proposal: None,
            identity_plan: None,
        },
        reviewed: &reviewed,
        history: Some(&history),
    };
    let permit = reviewed
        .authorize_preview(&preview, &authority, Some(3))
        .unwrap();
    let storage = MigrationStorage::new(
        fixture.storage.clone(),
        StoragePolicy {
            reserve_bytes: 0,
            ..StoragePolicy::default()
        },
    )
    .unwrap();
    let actual = apply_migration(
        &fixture.root,
        &preview.plan,
        &MigrationServices {
            evaluator: &evaluator,
            authority: &authority,
            resources: &storage,
            observer: &NoMutationFaults,
        },
    )
    .unwrap();
    assert_eq!(
        actual.receipt.actual_state_ref,
        permit.record().candidate_state_ref
    );
    assert_authorized_projection(&fixture, &reviewed, &permit, &selected);
    future_reintroduced_site_blocks(
        &fixture,
        proposal.pre_admission_state(),
        &selected,
        &storage,
    );
}

fn assert_authorized_projection(
    fixture: &Fixture,
    reviewed: &fortress_core::migration_governance::ReviewedAdmission,
    permit: &fortress_core::development_governance::ApplicationAuthorization,
    selected: &str,
) {
    let ordinary = fortress_core::audit::audit_repository(&fixture.root).unwrap();
    let blocked = ordinary
        .finding_governance()
        .findings()
        .iter()
        .find(|row| row.finding_id() == selected)
        .unwrap();
    assert_eq!(blocked.enforcement(), FindingEnforcement::Blocking);
    let assessment =
        evaluate_authorized_admission(&fixture.root, reviewed, permit, Some(3)).unwrap();
    let treated = assessment
        .findings()
        .iter()
        .find(|row| row.finding_id() == selected)
        .unwrap();
    assert_eq!(treated.disposition(), FindingDisposition::Admitted);
    assert_eq!(treated.enforcement(), FindingEnforcement::NonBlocking);
    assert_eq!(
        serde_json::to_value(treated).unwrap()["raw_conformance"],
        "FAIL"
    );
    assert!(evaluate_authorized_admission(&fixture.root, reviewed, permit, Some(40)).is_err());
    fs::write(
        fixture.root.join("src/lib.rs"),
        b"pub fn value() { let _ = std::fs::read(\"new\"); }\n",
    )
    .unwrap();
    assert!(evaluate_authorized_admission(&fixture.root, reviewed, permit, Some(3)).is_err());
}

fn assert_tampered_review_is_rejected(
    before: &fortress_core::observation::SourceView,
    plan: &fortress_core::migration_governance::MigrationPlan,
    authority: &impl fortress_core::migration_governance::MigrationAuthority,
    finding: &str,
) {
    let governance = fortress_core::finding_governance::FINDING_GOVERNANCE_PATH;
    let mut operations = plan.operations().to_vec();
    let postimage = operations
        .iter_mut()
        .find_map(|operation| match operation {
            MigrationOperation::CreateFile { path, postimage }
            | MigrationOperation::ReplaceFile {
                path, postimage, ..
            } if path == governance => Some(postimage),
            _ => None,
        })
        .unwrap();
    let mut doc: serde_json::Value = serde_json::from_slice(postimage).unwrap();
    let record = &mut doc["admissions"][finding];
    record["grant_ref"] = serde_json::json!("forged/replacement/approval");
    record["record_ref"] = serde_json::json!("");
    record["record_ref"] =
        serde_json::json!(fortress_core::finding_governance::lifecycle_digest(record).unwrap());
    *postimage = serde_json::to_vec(&doc).unwrap();
    let refusal = preview_migration(
        &CanonicalMigrationEvaluator,
        authority,
        before,
        operations,
        MigrationOptions::default(),
    )
    .err()
    .unwrap();
    assert_eq!(refusal.code, "STALE_ADMISSION_REVIEW");
}

fn future_reintroduced_site_blocks(
    fixture: &Fixture,
    original: &fortress_core::state_governance::ComparisonState,
    selected: &str,
    storage: &MigrationStorage,
) {
    let evaluator = CanonicalMigrationEvaluator;
    let path = fortress_core::finding_governance::FINDING_GOVERNANCE_PATH;
    let violation_bytes = b"pub fn value() { let _ = std::fs::read(\"input\"); }\n";
    fs::write(fixture.root.join("src/lib.rs"), b"pub fn value() {}\n").unwrap();
    let fixed = evaluator.observe(&fixture.root).unwrap();
    let evaluated = evaluator.evaluate(&fixed).unwrap();
    let existing = fortress_core::lifecycle_load::load_finding_authority(&fixture.root).unwrap();
    let retirement = fortress_core::lifecycle_load::propose_prune(
        &existing,
        original,
        &evaluated.state,
        &BTreeSet::from([selected.into()]),
    )
    .unwrap();
    let governed = retirement.proposed_governance();
    assert_eq!(governed.admissions(), existing.admissions());
    assert!(governed.admission_retirements().contains_key(selected));
    let operation = fixture.replace(path, governed.to_canonical_json().unwrap().as_bytes());
    let policy = trusted_policy(&evaluated);
    let authority = CanonicalMigrationAuthority {
        policy: Some(&policy),
        host: &UnmediatedHost,
        validator: &FixtureGrant,
        evaluation_time: Some(3),
        reviewed_initial_intent_ref: None,
        finding_proposal: Some(&retirement),
        identity_plan: None,
    };
    let plan = preview_migration(
        &evaluator,
        &authority,
        &fixed,
        vec![operation],
        MigrationOptions::default(),
    )
    .unwrap()
    .plan;
    apply_migration(
        &fixture.root,
        &plan,
        &MigrationServices {
            evaluator: &evaluator,
            authority: &authority,
            resources: storage,
            observer: &NoMutationFaults,
        },
    )
    .unwrap();
    fs::write(fixture.root.join("src/lib.rs"), violation_bytes).unwrap();
    let audit = fortress_core::audit::audit_repository(&fixture.root).unwrap();
    let finding = audit
        .finding_governance()
        .findings()
        .iter()
        .find(|row| row.finding_id() == selected)
        .unwrap();
    assert_eq!(finding.lifecycle(), FindingLifecycle::Reintroduced);
    assert_eq!(finding.enforcement(), FindingEnforcement::Blocking);
}
