//! Exact proposal and external authorization boundary regression controls.
use fortress_core::development_governance::*;
use fortress_core::observation::{CandidateChangeSet, ChangeOperation, SourceView};
use fortress_core::state_governance::*;
use std::collections::{BTreeMap, BTreeSet};

fn d(n: u8) -> String {
    format!("sha256:{n:064x}")
}
fn state(n: u8) -> ComparisonState {
    ComparisonState {
        schema: "urn:fortress:derived:v1:comparison-state".into(),
        schema_version: 1,
        source_ref: Some(d(n)),
        view: None,
        retained_application: None,
        origin_ref: None,
        limitations: vec![],
        assets: Some(StateAssets {
            subject_ref: d(n),
            complete_axes: BTreeSet::from([
                Axis::Subject,
                Axis::Intent,
                Axis::Authority,
                Axis::Governance,
            ]),
            inputs: vec![AxisInput {
                id: "code".into(),
                path: "src/lib.rs".into(),
                content_ref: d(n),
                scope_refs: BTreeSet::new(),
                roles: BTreeMap::from([(Axis::Subject, d(n))]),
            }],
            entities: vec![],
            policies: vec![],
            standard_ref: Some(d(4)),
            profile_refs: BTreeSet::new(),
            evaluator_ref: Some(d(6)),
            exclusions_ref: None,
            exclusions: None,
            reference_facts: None,
        }),
    }
}
fn proposal(class: Option<ProtectedClass>) -> PreparedChange {
    proposal_classes(class.into_iter().collect())
}
fn proposal_classes(classes: Vec<ProtectedClass>) -> PreparedChange {
    let base = SourceView::from_bytes([("src/lib.rs", b"old".to_vec())]).unwrap();
    let mut before = state(1);
    let mut after = state(2);
    let candidate = SourceView::from_bytes([("src/lib.rs", b"new".to_vec())]).unwrap();
    before.source_ref = Some(fortress_core::certification::certification_source_digest(
        base.files(),
    ));
    before.assets.as_mut().unwrap().subject_ref = before.source_ref.clone().unwrap();
    after.source_ref = Some(fortress_core::certification::certification_source_digest(
        candidate.files(),
    ));
    after.assets.as_mut().unwrap().subject_ref = after.source_ref.clone().unwrap();
    let context = ComparisonContext::default();
    let comparison = compare_states(&before, &after, &context).unwrap();
    let changes = CandidateChangeSet::new(
        &base,
        comparison.comparison_context,
        after.governing_identity().unwrap().unwrap(),
        [ChangeOperation::Replace {
            path: "src/lib.rs".into(),
            base_bytes: b"old".to_vec(),
            candidate_bytes: b"new".to_vec(),
        }],
    )
    .unwrap();
    let roles = classes
        .into_iter()
        .map(|class| ProtectedInput {
            path: "src/lib.rs".into(),
            class,
            scope: "module:app".into(),
        })
        .collect();
    PreparedChange::new(
        &before,
        &after,
        &context,
        &base,
        &changes,
        (roles, vec![]),
        true,
    )
    .unwrap()
}
fn policy(p: &PreparedChange, required: bool) -> TrustedBasePolicy {
    TrustedBasePolicy::from_host(
        p.base_state_ref(),
        p.base_authority_ref().unwrap(),
        d(8),
        required,
        vec![AuthorizationRule {
            id: "owner".into(),
            classes: ProtectedClass::all().into_iter().collect(),
            actions: BTreeSet::from([
                Action::Create,
                Action::Replace,
                Action::Delete,
                Action::Move,
            ]),
            scope: "module:app".into(),
            issuer_policy_ref: d(7),
        }],
    )
    .unwrap()
}
struct Host {
    assertion: Option<HostAssertion>,
}
impl GrantValidator for Host {
    fn validate(&self, _request: &GrantRequest) -> GrantValidation {
        self.assertion
            .clone()
            .map_or(GrantValidation::Missing, |a| {
                GrantValidation::Authenticated(Box::new(a))
            })
    }
}
fn inspect(p: &PreparedChange, required: bool) -> ChangeDecision {
    evaluate_change(
        p,
        &policy(p, required),
        &UnmediatedHost,
        &NoGrantValidator,
        None,
    )
    .unwrap()
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-001`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn candidate_cannot_allow_its_own_forbidden_change() {
    let p = proposal(Some(ProtectedClass::ModuleIntent));
    let result = inspect(&p, false);
    assert_eq!(result.disposition, Disposition::RequireAuthorization);
    assert!(!result.enforced);
    assert_eq!(result.semantic_enforcement.state, "UNEVALUATED");
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-002`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn renamed_or_new_governance_is_protected() {
    for class in ProtectedClass::all() {
        let p = proposal(Some(class));
        assert_eq!(inspect(&p, false).requirements.len(), 1);
    }
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-003`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn reference_string_is_not_a_grant() {
    let mut p = proposal(Some(ProtectedClass::FindingGovernance));
    p.authorization_references
        .push("https://example.test/approved:true".into());
    assert_eq!(inspect(&p, false).authorization[0].state, "MISSING");
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-004`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn unknown_and_required_assurance_have_different_reasons() {
    let p = proposal(None);
    let a = inspect(&p, false);
    let b = inspect(&p, true);
    assert_eq!(a.disposition, Disposition::Unevaluated);
    assert_eq!(b.disposition, Disposition::HoldRequiredAssurance);
    assert_ne!(a.semantic_enforcement.state, b.assurance_requirements.state);
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-005`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn unmediated_host_is_reported() {
    assert_eq!(
        inspect(&proposal(None), false).host_coverage.state,
        "UNMEDIATED"
    );
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-006`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn grant_is_exact_base_candidate_and_scope_bound() {
    let p = proposal(Some(ProtectedClass::ModuleIntent));
    let pol = policy(&p, false);
    let requirement = inspect(&p, false).requirements[0].clone();
    let assertion = HostAssertion::for_request(
        &GrantRequest::new(&p, &pol, &requirement, None),
        "external-owner",
        d(11),
        None,
        None,
    );
    let good = Host {
        assertion: Some(assertion.clone()),
    };
    let r = evaluate_change(&p, &pol, &UnmediatedHost, &good, None).unwrap();
    assert_eq!(r.authorization[0].state, "VERIFIED");
    for field in [
        "proposal_ref",
        "candidate_state_ref",
        "base_state_ref",
        "issuer_policy_ref",
        "scope",
        "action",
        "class",
    ] {
        let mut value = serde_json::to_value(&assertion).unwrap();
        value[field] = serde_json::json!(if field == "action" {
            "DELETE"
        } else if field == "class" {
            "STANDARD"
        } else {
            "wrong"
        });
        let forged = serde_json::from_value(value).unwrap();
        let r = evaluate_change(
            &p,
            &pol,
            &UnmediatedHost,
            &Host {
                assertion: Some(forged),
            },
            None,
        )
        .unwrap();
        assert_eq!(r.authorization[0].state, "INVALID", "{field}");
    }
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-007`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn assessor_change_requires_trusted_qualification() {
    let p = proposal(Some(ProtectedClass::AssessorTrust));
    let pol = policy(&p, false);
    let req = inspect(&p, false).requirements[0].clone();
    let assertion = HostAssertion::for_request(
        &GrantRequest::new(&p, &pol, &req, None),
        "external-owner",
        d(11),
        None,
        None,
    );
    let r = evaluate_change(
        &p,
        &pol,
        &UnmediatedHost,
        &Host {
            assertion: Some(assertion),
        },
        None,
    )
    .unwrap();
    assert_eq!(r.authorization[0].state, "QUALIFICATION_REQUIRED");
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-008`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn policy_is_pinned_and_conflicts_are_not_resolved_favorably() {
    let p = proposal(None);
    let wrong = TrustedBasePolicy::from_host(d(99), d(4), d(8), false, vec![]).unwrap();
    assert!(evaluate_change(&p, &wrong, &UnmediatedHost, &NoGrantValidator, None).is_err());
    let mut rules = policy(&p, false).rules().to_vec();
    rules.push(rules[0].clone());
    assert!(
        TrustedBasePolicy::from_host(
            p.base_state_ref(),
            p.base_authority_ref().unwrap(),
            d(8),
            false,
            rules
        )
        .is_err()
    );
    let mut rules = policy(&p, false).rules().to_vec();
    let mut conflict = rules[0].clone();
    conflict.id = "different-rule-same-scope".into();
    rules.push(conflict);
    assert!(
        TrustedBasePolicy::from_host(
            p.base_state_ref(),
            p.base_authority_ref().unwrap(),
            d(8),
            false,
            rules
        )
        .is_err()
    );
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-009`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn decision_is_deterministic_and_receipt_is_not_a_grant() {
    let p = proposal(Some(ProtectedClass::ProviderTrust));
    let a = inspect(&p, false);
    assert_eq!(
        a.to_canonical_bytes().unwrap(),
        inspect(&p, false).to_canonical_bytes().unwrap()
    );
    let bytes = a.to_canonical_bytes().unwrap();
    let read = ChangeDecision::from_json_str(std::str::from_utf8(&bytes).unwrap()).unwrap();
    assert_eq!(a.digest().unwrap(), read.digest().unwrap());
    assert!(ChangeDecision::from_json_str("{\"schema_version\":1,\"schema_version\":1}").is_err());
}

/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-010`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn time_limits_require_explicit_clock_and_do_not_admit_expired_grants() {
    let p = proposal(Some(ProtectedClass::ModuleIntent));
    let pol = policy(&p, false);
    let r = inspect(&p, false).requirements[0].clone();
    let a = HostAssertion::for_request(
        &GrantRequest::new(&p, &pol, &r, None),
        "owner",
        d(11),
        Some(20),
        None,
    );
    for (now, expected) in [
        (None, "INVALID"),
        (Some(19), "VERIFIED"),
        (Some(20), "INVALID"),
        (Some(21), "INVALID"),
    ] {
        let result = evaluate_change(
            &p,
            &pol,
            &UnmediatedHost,
            &Host {
                assertion: Some(a.clone()),
            },
            now,
        )
        .unwrap();
        assert_eq!(result.authorization[0].state, expected);
    }
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-011`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn changed_base_rules_cannot_replay_old_grants() {
    let p = proposal(Some(ProtectedClass::ProviderTrust));
    let old = policy(&p, false);
    let r = inspect(&p, false).requirements[0].clone();
    let a = HostAssertion::for_request(
        &GrantRequest::new(&p, &old, &r, None),
        "owner",
        d(11),
        None,
        None,
    );
    let new = TrustedBasePolicy::from_host(
        p.base_state_ref(),
        p.base_authority_ref().unwrap(),
        d(8),
        true,
        old.rules().to_vec(),
    )
    .unwrap();
    let result = evaluate_change(
        &p,
        &new,
        &UnmediatedHost,
        &Host { assertion: Some(a) },
        None,
    )
    .unwrap();
    assert_eq!(result.authorization[0].state, "INVALID");
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-012`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn schema_and_control_roles_survive_new_paths_and_include_selection_publication() {
    use fortress_core::authority_roles::protected_input_roles;
    use fortress_core::control_layout::{ControlLayout, ControlRole};
    let layout = ControlLayout::standard();
    for path in ["new/name.json", "renamed/arbitrary"] {
        assert!(
            protected_input_roles(
                &layout,
                path,
                Some("urn:fortress:schema:v2:module-contract")
            )
            .contains(&ProtectedClass::ModuleIntent)
        );
    }
    for (role, class) in [
        (
            ControlRole::ProjectConfiguration,
            ProtectedClass::ProtectedConfiguration,
        ),
        (
            ControlRole::AssessmentSelectionIndex,
            ProtectedClass::EvidenceSelection,
        ),
    ] {
        assert!(
            protected_input_roles(&layout, layout.role_path(role).unwrap(), None).contains(&class)
        );
    }
    let path = layout.generation_path(&d(1), None).unwrap();
    assert!(
        protected_input_roles(&layout, &path, None).contains(&ProtectedClass::EvidencePublication)
    );
    assert!(protected_input_roles(&layout, "src/ordinary.rs", None).is_empty());
    assert!(
        protected_input_roles(&layout, "__fortress/new/unknown", None)
            .contains(&ProtectedClass::UnknownControl)
    );
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-013`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn authorization_statuses_preserve_frozen_meaning_without_favorable_outage() {
    struct Outcome(&'static str);
    impl GrantValidator for Outcome {
        fn validate(&self, _: &GrantRequest) -> GrantValidation {
            match self.0 {
                "MISSING" => GrantValidation::Missing,
                "INVALID" => GrantValidation::Invalid,
                "UNSUPPORTED" => GrantValidation::Unsupported,
                "CONFLICTING" => GrantValidation::Conflicting,
                "UNAVAILABLE" => GrantValidation::Unavailable,
                _ => unreachable!(),
            }
        }
    }
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("../_data/authority_cases_v1.json")).unwrap();
    let p = proposal(Some(ProtectedClass::ModuleIntent));
    let pol = policy(&p, false);
    for case in cases["cases"].as_array().unwrap() {
        let expected = case["state"].as_str().unwrap();
        let fixed = match expected {
            "MISSING" => "MISSING",
            "INVALID" => "INVALID",
            "UNSUPPORTED" => "UNSUPPORTED",
            "CONFLICTING" => "CONFLICTING",
            "UNAVAILABLE" => "UNAVAILABLE",
            _ => unreachable!(),
        };
        let result = evaluate_change(&p, &pol, &UnmediatedHost, &Outcome(fixed), None).unwrap();
        assert_eq!(result.authorization[0].state, expected);
        assert_eq!(
            serde_json::to_value(result.disposition).unwrap(),
            case["disposition"]
        );
    }
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-014`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn complete_paged_rpc_explanations_match_native_records_and_cancel_without_analysis() {
    use fortress_core::query::{QueryInput, QueryRequest, QueryService};
    use std::sync::atomic::AtomicBool;
    let p = proposal_classes(ProtectedClass::all());
    let decision = inspect(&p, false);
    let id = decision.digest().unwrap();
    let service = QueryService::new(QueryInput::empty(d(1)))
        .unwrap()
        .with_change_decisions(vec![decision.clone()])
        .unwrap();
    let mut cursor = None;
    let mut count = 0;
    loop {
        let request = QueryRequest {
            protocol_version: 2,
            request_id: "explain".into(),
            method: "explain".into(),
            state_ref: None,
            context_ref: None,
            parameters: serde_json::json!({"selector":id,"page":{"limit":2,"cursor":cursor}}),
        };
        let response =
            serde_json::to_value(service.execute(&request, &AtomicBool::new(false))).unwrap();
        assert!(response["error"].is_null(), "{response}");
        let evidence = &response["result"]["data"]["evidence"];
        count += evidence["records"].as_array().unwrap().len();
        cursor = evidence["next_cursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(count, decision.requirements.len() + 1);
    let request = QueryRequest {
        protocol_version: 2,
        request_id: "cancel".into(),
        method: "explain".into(),
        state_ref: None,
        context_ref: None,
        parameters: serde_json::json!({"selector":id}),
    };
    assert_eq!(
        service
            .execute(&request, &AtomicBool::new(true))
            .error
            .unwrap()
            .code,
        "CANCELLED"
    );
    for requirement in &decision.requirements {
        assert!(decision.to_human().contains(&requirement.path));
    }
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-015`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn missing_scope_rule_never_uses_another_scopes_permission() {
    let p = proposal(Some(ProtectedClass::ModuleIntent));
    let pol = TrustedBasePolicy::from_host(
        p.base_state_ref(),
        p.base_authority_ref().unwrap(),
        d(8),
        false,
        vec![],
    )
    .unwrap();
    let result = evaluate_change(&p, &pol, &UnmediatedHost, &NoGrantValidator, None).unwrap();
    assert_eq!(result.authorization[0].state, "UNSUPPORTED");
    assert_eq!(result.disposition, Disposition::RequireAuthorization);
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-016`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn altered_requirement_and_unsupported_version_are_rejected() {
    let p = proposal(Some(ProtectedClass::ModuleIntent));
    let decision = inspect(&p, false);
    let mut v = serde_json::to_value(&decision).unwrap();
    v["requirements"][0]["scope"] = serde_json::json!("other");
    assert!(ChangeDecision::from_json_str(&v.to_string()).is_err());
    v = serde_json::to_value(decision).unwrap();
    v["schema_version"] = serde_json::json!(99);
    assert!(ChangeDecision::from_json_str(&v.to_string()).is_err());
}

fn snapshot(files: BTreeMap<String, Vec<u8>>) -> fortress_core::authority_load::AuthoritySnapshot {
    use sha2::{Digest, Sha256};
    let mut s = state(1);
    let layout = fortress_core::control_layout::ControlLayout::standard();
    let source = files
        .iter()
        .filter(|(p, _)| {
            layout.resolve(p).is_none_or(|e| {
                e.role() == fortress_core::control_layout::ControlRole::Unrecognized
                    || e.source_binding()
                        != fortress_core::control_layout::ControlSourceBinding::Nonrecursive
            })
        })
        .map(|(p, b)| (p.clone(), b.clone()))
        .collect();
    s.source_ref = Some(fortress_core::certification::certification_source_digest(
        &source,
    ));
    let assets = s.assets.as_mut().unwrap();
    assets.subject_ref = s.source_ref.clone().unwrap();
    assets.inputs = source
        .iter()
        .map(|(p, b)| AxisInput {
            id: p.clone(),
            path: p.clone(),
            content_ref: format!("sha256:{:x}", Sha256::digest(b)),
            scope_refs: BTreeSet::new(),
            roles: BTreeMap::from([(Axis::Subject, format!("sha256:{:x}", Sha256::digest(b)))]),
        })
        .collect();
    fortress_core::authority_load::AuthoritySnapshot {
        schema: "urn:fortress:derived:v1:authority-snapshot".into(),
        schema_version: 1,
        state: s,
        files,
    }
}
fn snapshot_decision(
    before: &fortress_core::authority_load::AuthoritySnapshot,
    after: &fortress_core::authority_load::AuthoritySnapshot,
) -> ChangeDecision {
    let p = fortress_core::authority_load::prepare_authority_change(
        before,
        after,
        &ComparisonContext::default(),
    )
    .unwrap();
    let pol = TrustedBasePolicy::from_host(
        p.base_state_ref(),
        p.base_authority_ref().unwrap(),
        d(8),
        false,
        vec![AuthorizationRule {
            id: "project-owner".into(),
            classes: ProtectedClass::all().into_iter().collect(),
            actions: BTreeSet::from([
                Action::Create,
                Action::Replace,
                Action::Delete,
                Action::Move,
            ]),
            scope: "project".into(),
            issuer_policy_ref: d(7),
        }],
    )
    .unwrap();
    fortress_core::authority_load::preview_authority_change(&p, &pol).unwrap()
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-017`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn simultaneous_implementation_and_renamed_governance_use_both_role_inventories() {
    let declaration =
        br#"{"$schema":"urn:fortress:schema:v2:module-contract","id":"app","deny":true}"#.to_vec();
    let before = snapshot(BTreeMap::from([
        ("src/app.rs".into(), b"old".to_vec()),
        ("old/intent".into(), declaration.clone()),
    ]));
    let after = snapshot(BTreeMap::from([
        ("src/app.rs".into(), b"new".to_vec()),
        ("new/renamed".into(), declaration),
    ]));
    let original = before.to_canonical_bytes().unwrap();
    let result = snapshot_decision(&before, &after);
    assert!(
        result
            .requirements
            .iter()
            .any(|r| r.path == "old/intent" && r.action == Action::Delete)
    );
    assert!(
        result
            .requirements
            .iter()
            .any(|r| r.path == "new/renamed" && r.action == Action::Create)
    );
    assert_eq!(result.disposition, Disposition::RequireAuthorization);
    assert_eq!(before.to_canonical_bytes().unwrap(), original);
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-018`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn unprotected_development_and_readonly_history_do_not_require_authorization() {
    let before = snapshot(BTreeMap::from([("src/app.rs".into(), b"old".to_vec())]));
    let after = snapshot(BTreeMap::from([("src/app.rs".into(), b"new".to_vec())]));
    let result = snapshot_decision(&before, &after);
    assert!(result.requirements.is_empty());
    assert_eq!(result.disposition, Disposition::Unevaluated);
    let same = snapshot_decision(&before, &before);
    assert!(same.requirements.is_empty());
    assert!(
        same.transition
            .input_deltas
            .iter()
            .all(|a| a.change == Change::Unchanged)
    );
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-019`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn evidence_selection_and_history_tamper_are_authorization_not_semantic_violations() {
    use fortress_core::control_layout::{ControlLayout, ControlRole};
    let layout = ControlLayout::standard();
    for path in [
        layout
            .role_path(ControlRole::AssessmentSelectionIndex)
            .unwrap()
            .to_owned(),
        layout.generation_path(&d(1), None).unwrap(),
    ] {
        let before = snapshot(BTreeMap::from([
            ("src/app.rs".into(), b"same".to_vec()),
            (path.clone(), b"old".to_vec()),
        ]));
        let mut after = before.clone();
        after.files.insert(path, b"tampered".to_vec());
        let result = snapshot_decision(&before, &after);
        assert!(!result.requirements.is_empty());
        assert_eq!(result.semantic_enforcement.state, "UNEVALUATED");
        assert_eq!(before.state.source_ref, after.state.source_ref);
        assert_ne!(result.disposition, Disposition::DenySupportedViolation);
    }
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-020`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn malformed_snapshots_unsafe_paths_and_missing_history_never_become_permission() {
    use fortress_core::authority_load::{AuthoritySnapshot, prepare_authority_change};
    let original = snapshot(BTreeMap::from([("src/app.rs".into(), b"old".to_vec())]));
    let mut changed = original.clone();
    changed
        .files
        .insert("src/app.rs".into(), b"tampered".to_vec());
    assert!(changed.to_canonical_bytes().is_err());
    changed = original.clone();
    changed.files.insert("../outside".into(), vec![]);
    assert!(changed.to_canonical_bytes().is_err());
    changed = original.clone();
    changed.state = ComparisonState::unavailable(None);
    assert!(prepare_authority_change(&original, &changed, &ComparisonContext::default()).is_err());
    assert!(
        AuthoritySnapshot::from_json_str("{\"schema_version\":1,\"schema_version\":1}").is_err()
    );
    let mut ambiguous = original.clone();
    let mut input = ambiguous.state.assets.as_ref().unwrap().inputs[0].clone();
    input.id = "conflicting-identity".into();
    ambiguous.state.assets.as_mut().unwrap().inputs.push(input);
    assert_eq!(
        prepare_authority_change(&original, &ambiguous, &ComparisonContext::default())
            .unwrap_err()
            .code,
        "AMBIGUOUS_AUTHORITY"
    );
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-021`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn public_schema_and_canonical_digest_are_independently_reproducible() {
    use sha2::{Digest, Sha256};
    let value = inspect(&proposal(Some(ProtectedClass::ModuleIntent)), false);
    let bytes = value.to_canonical_bytes().unwrap();
    let canonical =
        fortress_core::wire::canonicalize_public_json(&serde_json::to_string(&value).unwrap())
            .unwrap();
    assert_eq!(bytes, canonical);
    assert_eq!(
        value.digest().unwrap(),
        format!("sha256:{:x}", Sha256::digest(canonical))
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("engine/standard_registry/_data/schema_manifest.json")).unwrap(),
    )
    .unwrap();
    let resources = manifest["schemas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| {
            let schema: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join(path.as_str().unwrap())).unwrap())
                    .unwrap();
            (
                schema["$id"].as_str().unwrap().to_owned(),
                jsonschema::Resource::from_contents(schema).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../_data/change_decision_schema_v1.json")).unwrap();
    let validator = jsonschema::options()
        .with_resources(resources.into_iter())
        .build(&schema)
        .unwrap();
    validator
        .validate(&serde_json::to_value(value).unwrap())
        .unwrap();
}

fn attach_assessment(
    s: &mut fortress_core::authority_load::AuthoritySnapshot,
    truth: fortress_core::declaration::DeclarationTruth,
    blocking: bool,
) {
    use fortress_core::application::{ApplicationAssessment, ApplicationRuleOutcome};
    use fortress_core::assessment::{
        EvidenceAcceptancePolicy, ExpectedProfileAssessment, ProfileAssessment,
    };
    use fortress_core::declaration::{
        ConformanceDeclaration, DeclarationBinding, DeclarationClaim, DeclarationClaimKind,
        DeclarationResidue, DeclarationTruth, DimensionManifest, RequiredDimension,
        RuleClaimDetail,
    };
    let binding = DeclarationBinding {
        subject_ref: s.state.source_ref.clone().unwrap(),
        context_ref: d(7),
        authority_ref: d(4),
    };
    let manifest = DimensionManifest {
        profiles: vec![],
        dimensions: vec![RequiredDimension {
            id: "RULES".into(),
            claim_refs: vec!["rule:STD-ID-001".into()],
        }],
    };
    let declaration = ConformanceDeclaration::compose(
        binding.clone(),
        manifest.clone(),
        vec![DeclarationClaim {
            kind: DeclarationClaimKind::RuleCheck,
            id: "rule:STD-ID-001".into(),
            scope_ref: "rule:STD-ID-001".into(),
            truth,
            proof_refs: vec![],
            findings: if truth == DeclarationTruth::SupportedViolation {
                vec!["finding".into()]
            } else {
                vec![]
            },
            defeater_refs: vec![],
            reason_codes: vec![],
            assumptions: vec![],
            semantic_claim: None,
            rule_result: Some(RuleClaimDetail {
                outcome: match truth {
                    DeclarationTruth::SupportedViolation => ApplicationRuleOutcome::Failed,
                    DeclarationTruth::NotEvaluable => ApplicationRuleOutcome::Unsupported,
                    _ => ApplicationRuleOutcome::Passed,
                },
                applicable: true,
                applicability_reason: None,
                detail: "Prepared upstream result; not authorization evidence.".into(),
            }),
        }],
        vec![],
        DeclarationResidue {
            blocking_findings: if blocking {
                vec!["finding".into()]
            } else {
                vec![]
            },
            ..Default::default()
        },
    )
    .unwrap();
    let expected = ExpectedProfileAssessment {
        artifacts: vec![],
        binding: binding.clone(),
        dimensions: manifest,
        profile_digest: d(5),
        obligations: vec![],
    };
    let assessment = ProfileAssessment::evaluate(
        &declaration,
        &expected,
        &[],
        &EvidenceAcceptancePolicy::default(),
    )
    .unwrap();
    let app = ApplicationAssessment {
        portable_replay: None,
        project: "fixture".into(),
        declaration,
        assessment,
        evidence: vec![],
        obligations: vec![],
        evidence_inputs: Some(
            fortress_core::provider_inputs::EvidenceInputSet::compose(binding, vec![]).unwrap(),
        ),
        provider_requirements: vec![],
    };
    s.state.view = Some(fortress_core::state_view::StateView {
        portable_evidence_graph: None,
        schema: "urn:fortress:derived:v2:state-view".into(),
        schema_version: 2,
        source_ref: s.state.source_ref.clone().unwrap(),
        status: fortress_core::state_view::StateViewStatus::Complete,
        detail: None,
        application: Some(app),
    });
    s.state.validate().unwrap();
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-022`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn raw_progressive_and_authorization_outcomes_remain_independent() {
    use fortress_core::declaration::DeclarationTruth;
    for (truth, blocking, expected) in [
        (
            DeclarationTruth::SupportedViolation,
            true,
            Disposition::DenySupportedViolation,
        ),
        (
            DeclarationTruth::SupportedViolation,
            false,
            Disposition::Permit,
        ),
        (
            DeclarationTruth::NoSupportedViolation,
            false,
            Disposition::Permit,
        ),
        (
            DeclarationTruth::NotEvaluable,
            false,
            Disposition::Unevaluated,
        ),
    ] {
        let mut before = snapshot(BTreeMap::from([("src/app.rs".into(), b"old".to_vec())]));
        let mut after = snapshot(BTreeMap::from([("src/app.rs".into(), b"new".to_vec())]));
        attach_assessment(&mut before, DeclarationTruth::NoSupportedViolation, false);
        attach_assessment(&mut after, truth, blocking);
        let old = before.to_canonical_bytes().unwrap();
        let result = snapshot_decision(&before, &after);
        assert_eq!(result.disposition, expected, "{truth:?}");
        assert_eq!(before.to_canonical_bytes().unwrap(), old);
        assert_eq!(
            after
                .state
                .view
                .as_ref()
                .unwrap()
                .application
                .as_ref()
                .unwrap()
                .declaration
                .claims[0]
                .truth,
            truth
        );
    }
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-023`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn candidate_authority_cannot_substitute_favorable_target_assessment() {
    use fortress_core::declaration::DeclarationTruth;
    let mut before = snapshot(BTreeMap::from([("src/app.rs".into(), b"old".to_vec())]));
    let mut after = snapshot(BTreeMap::from([("src/app.rs".into(), b"new".to_vec())]));
    attach_assessment(&mut before, DeclarationTruth::NoSupportedViolation, false);
    attach_assessment(&mut after, DeclarationTruth::NoSupportedViolation, false);
    after.state.assets.as_mut().unwrap().standard_ref = Some(d(99));
    let result = snapshot_decision(&before, &after);
    assert_eq!(result.semantic_enforcement.state, "UNEVALUATED");
    assert_eq!(result.disposition, Disposition::RequireAuthorization);
    assert!(
        result
            .requirements
            .iter()
            .any(|r| r.path == "@authority/standard")
    );
}

/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-024`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn externally_authorized_weakening_still_retains_original_transition_meaning() {
    struct Approver;
    impl GrantValidator for Approver {
        fn validate(&self, r: &GrantRequest) -> GrantValidation {
            GrantValidation::Authenticated(Box::new(HostAssertion::for_request(
                r,
                "external-fixture-owner",
                d(11),
                None,
                None,
            )))
        }
    }
    let declaration =
        br#"{"$schema":"urn:fortress:schema:v2:module-contract","deny":true}"#.to_vec();
    let mut before = snapshot(BTreeMap::from([("contract.json".into(), declaration)]));
    let mut after = before.clone();
    after.files.insert(
        "contract.json".into(),
        br#"{"$schema":"urn:fortress:schema:v2:module-contract","deny":false}"#.to_vec(),
    );
    after = snapshot(after.files);
    for (s, deny) in [(&mut before, true), (&mut after, false)] {
        let assets = s.state.assets.as_mut().unwrap();
        let origin = assets.inputs[0].content_ref.clone();
        assets.inputs[0].roles.insert(Axis::Intent, origin.clone());
        assets.policies.push(FinitePolicy {
            id: "promise".into(),
            origin_ref: origin,
            origin_kind: "AUTHORED".into(),
            vocabulary_ref: d(10),
            scope: "all".into(),
            quantifier: "ALL".into(),
            context_ref: d(7),
            complete: true,
            universe: BTreeSet::from(["fs.write".into()]),
            denied: if deny {
                BTreeSet::from(["fs.write".into()])
            } else {
                BTreeSet::new()
            },
            allowed: if deny {
                BTreeSet::new()
            } else {
                BTreeSet::from(["fs.write".into()])
            },
        });
    }
    let p = fortress_core::authority_load::prepare_authority_change(
        &before,
        &after,
        &ComparisonContext::default(),
    )
    .unwrap();
    let pol = TrustedBasePolicy::from_host(
        p.base_state_ref(),
        p.base_authority_ref().unwrap(),
        d(8),
        false,
        vec![AuthorizationRule {
            id: "owner".into(),
            classes: ProtectedClass::all().into_iter().collect(),
            actions: BTreeSet::from([
                Action::Create,
                Action::Replace,
                Action::Delete,
                Action::Move,
            ]),
            scope: "project".into(),
            issuer_policy_ref: d(7),
        }],
    )
    .unwrap();
    let result = evaluate_change(&p, &pol, &UnmediatedHost, &Approver, None).unwrap();
    assert!(!result.transition.weakenings.is_empty());
    assert!(result.authorization.iter().all(|a| a.state == "VERIFIED"));
    assert_eq!(result.semantic_enforcement.state, "UNEVALUATED");
    assert_eq!(result.disposition, Disposition::Unevaluated);
    assert!(result.to_human().contains("Authored weakening retained"));
}
/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-025`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn result_digest_resource_limits_and_duplicate_rule_sets_are_strict() {
    let result = inspect(&proposal(Some(ProtectedClass::ModuleIntent)), false);
    let text = String::from_utf8(result.to_canonical_bytes().unwrap()).unwrap();
    assert!(ChangeDecision::from_json_str_bound(&text, &result.digest().unwrap()).is_ok());
    assert!(ChangeDecision::from_json_str_bound(&text, &d(99)).is_err());
    assert_eq!(
        ChangeDecision::from_json_str(&" ".repeat(MAX_TRANSITION_BYTES + 1))
            .unwrap_err()
            .code,
        "RESOURCE_LIMIT"
    );
    let rule = serde_json::json!({"id":"owner","classes":["STANDARD","STANDARD"],"actions":["REPLACE"],"scope":"project","issuer_policy_ref":d(7)});
    assert!(serde_json::from_value::<AuthorizationRule>(rule).is_err());
}

/// `T-AF-DEVELOPMENT-GOVERNANCE-0001-R01-026`
/// Fortress requirement: AF-DEVELOPMENT-GOVERNANCE-0001-R01
#[test]
fn external_assessor_qualification_is_exact_and_local_booleans_are_not_evidence() {
    let p = proposal(Some(ProtectedClass::AssessorTrust));
    let pol = policy(&p, false);
    let requirement = inspect(&p, false).requirements[0].clone();
    let request = GrantRequest::new(&p, &pol, &requirement, None);
    let qualified = QualificationAssertion {
        candidate_state_ref: request.candidate_state_ref.clone(),
        base_evaluator_ref: request.base_evaluator_ref.clone().unwrap(),
        policy_ref: request.qualification_policy_ref.clone(),
        evidence_ref: d(12),
    };
    let assertion = HostAssertion::for_request(
        &request,
        "trusted-fixture-issuer",
        d(11),
        None,
        Some(qualified.clone()),
    );
    let result = evaluate_change_with_grants(
        &p,
        &pol,
        &UnmediatedHost,
        &Host {
            assertion: Some(assertion.clone()),
        },
        None,
    )
    .unwrap();
    assert_eq!(result.decision().authorization[0].state, "VERIFIED");
    assert_eq!(result.grants().len(), 1);
    assert_eq!(
        result.grants()[0].assertion().proposal_ref,
        request.proposal_ref
    );
    for key in [
        "candidate_state_ref",
        "base_evaluator_ref",
        "policy_ref",
        "evidence_ref",
    ] {
        let mut value = serde_json::to_value(&assertion).unwrap();
        value["qualification"][key] = serde_json::json!(if key == "evidence_ref" {
            "self-certified"
        } else {
            "sha256:0000000000000000000000000000000000000000000000000000000000000063"
        });
        let forged = serde_json::from_value(value).unwrap();
        let result = evaluate_change(
            &p,
            &pol,
            &UnmediatedHost,
            &Host {
                assertion: Some(forged),
            },
            None,
        )
        .unwrap();
        assert_eq!(result.authorization[0].state, "INVALID");
    }
    let mut local = serde_json::to_value(assertion).unwrap();
    local["assessor_qualified"] = serde_json::json!(true);
    assert!(serde_json::from_value::<HostAssertion>(local).is_err());
    let unknown = snapshot(BTreeMap::from([(
        "__fortress/unregistered/code.rs".into(),
        b"source".to_vec(),
    )]));
    assert!(unknown.to_canonical_bytes().is_ok());
}
