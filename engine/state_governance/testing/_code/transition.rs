//! Frozen finite temporal classifications and adversarial immutable comparison controls.
use fortress_core::assessment::*;
use fortress_core::declaration::*;
use fortress_core::state_governance::*;
use fortress_core::state_view::{StateView, StateViewStatus};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
fn d(n: u8) -> String {
    format!("sha256:{n:064x}")
}

fn value_ref(value: &impl serde::Serialize) -> String {
    let bytes =
        fortress_core::wire::canonicalize_public_json(&serde_json::to_string(value).unwrap())
            .unwrap();
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn state() -> ComparisonState {
    ComparisonState {
        schema: "urn:fortress:derived:v1:comparison-state".into(),
        schema_version: 1,
        source_ref: Some(d(1)),
        view: Some(StateView {
            schema: "urn:fortress:derived:v2:state-view".into(),
            schema_version: 2,
            source_ref: d(1),
            status: StateViewStatus::Ungoverned,
            detail: None,
            application: None,
        }),
        retained_application: None,
        assets: Some(StateAssets {
            subject_ref: d(1),
            complete_axes: BTreeSet::from([
                Axis::Subject,
                Axis::Intent,
                Axis::Authority,
                Axis::Governance,
            ]),
            inputs: vec![
                AxisInput {
                    id: "code".into(),
                    path: "src/lib.rs".into(),
                    content_ref: d(2),
                    scope_refs: BTreeSet::from(["module-policy".into()]),
                    roles: BTreeMap::from([(Axis::Subject, d(2))]),
                },
                AxisInput {
                    id: "policy".into(),
                    path: "contract.json".into(),
                    content_ref: d(3),
                    scope_refs: BTreeSet::new(),
                    roles: BTreeMap::from([(Axis::Intent, d(3))]),
                },
            ],
            entities: vec![],
            policies: vec![],
            standard_ref: Some(d(4)),
            profile_refs: BTreeSet::from([d(5)]),
            evaluator_ref: Some(d(6)),
            exclusions_ref: Some(value_ref(&BTreeSet::<String>::new())),
            exclusions: Some(BTreeSet::new()),
            reference_facts: Some(BTreeSet::new()),
        }),
        origin_ref: None,
        limitations: vec![],
    }
}
fn policy() -> FinitePolicy {
    FinitePolicy {
        id: "module-policy".into(),
        origin_ref: d(3),
        origin_kind: "AUTHORED".into(),
        vocabulary_ref: d(8),
        scope: "all-owned".into(),
        quantifier: "ALL".into(),
        context_ref: d(9),
        complete: true,
        universe: BTreeSet::from(["fs.read".into(), "fs.write".into()]),
        denied: BTreeSet::new(),
        allowed: BTreeSet::new(),
    }
}
fn install_policy(state: &mut ComparisonState, mut policy: FinitePolicy) {
    let bytes = serde_json::to_vec(&json!([policy.denied, policy.allowed])).unwrap();
    let identity = format!("sha256:{:x}", Sha256::digest(bytes));
    policy.origin_ref.clone_from(&identity);
    let assets = state.assets.as_mut().unwrap();
    assets.inputs[1].content_ref.clone_from(&identity);
    assets.inputs[1].roles.insert(Axis::Intent, identity);
    assets.policies.push(policy);
}
fn compare(before: &ComparisonState, after: &ComparisonState) -> TransitionAnalysis {
    compare_states(before, after, &ComparisonContext::default()).unwrap()
}
fn axis(t: &TransitionAnalysis, axis: Axis) -> Change {
    t.input_deltas
        .iter()
        .find(|prior| prior.axis == axis)
        .unwrap()
        .change
}
fn set(values: &Value) -> BTreeSet<String> {
    values
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().into())
        .collect()
}
fn app_state(truth: DeclarationTruth, context: u8, authority: u8) -> ComparisonState {
    use fortress_core::application::{ApplicationAssessment, ApplicationRuleOutcome};
    let binding = DeclarationBinding {
        subject_ref: d(1),
        context_ref: d(context),
        authority_ref: d(authority),
    };
    let rule = match truth {
        DeclarationTruth::SupportedViolation => ApplicationRuleOutcome::Failed,
        DeclarationTruth::NotEvaluable => ApplicationRuleOutcome::Unsupported,
        DeclarationTruth::NotApplicable => ApplicationRuleOutcome::NotApplicable,
        _ => ApplicationRuleOutcome::Passed,
    };
    let claim = DeclarationClaim {
        kind: DeclarationClaimKind::RuleCheck,
        id: "rule:STD-ID-001".into(),
        scope_ref: "rule:STD-ID-001".into(),
        truth,
        proof_refs: vec![],
        findings: if truth == DeclarationTruth::SupportedViolation {
            vec!["finding-one".into()]
        } else {
            vec![]
        },
        defeater_refs: vec![],
        reason_codes: vec![],
        assumptions: vec![],
        semantic_claim: None,
        rule_result: Some(RuleClaimDetail {
            outcome: rule,
            applicable: truth != DeclarationTruth::NotApplicable,
            applicability_reason: None,
            detail: "Frozen upstream result, not transition adjudication.".into(),
        }),
    };
    let manifest = DimensionManifest {
        profiles: vec![],
        dimensions: vec![RequiredDimension {
            id: "RULES".into(),
            claim_refs: vec![claim.id.clone()],
        }],
    };
    let declaration = ConformanceDeclaration::compose(
        binding.clone(),
        manifest.clone(),
        vec![claim],
        vec![],
        DeclarationResidue::default(),
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
    let inputs =
        fortress_core::provider_inputs::EvidenceInputSet::compose(binding, vec![]).unwrap();
    let app = ApplicationAssessment {
        project: "fixture".into(),
        declaration,
        assessment,
        evidence: vec![],
        obligations: vec![],
        evidence_inputs: Some(inputs),
        provider_requirements: vec![],
    };
    let mut s = state();
    s.assets.as_mut().unwrap().standard_ref = Some(d(authority));
    s.view.as_mut().unwrap().application = Some(app);
    s.view.as_mut().unwrap().status = StateViewStatus::Complete;
    s.validate().unwrap();
    s
}
fn refresh(s: &mut ComparisonState) {
    let app = s.view.as_mut().unwrap().application.as_mut().unwrap();
    let expected = ExpectedProfileAssessment {
        artifacts: vec![],
        binding: app.declaration.binding.clone(),
        dimensions: app.declaration.required_dimension_manifest.clone(),
        profile_digest: d(5),
        obligations: app.obligations.clone(),
    };
    app.assessment = ProfileAssessment::evaluate(
        &app.declaration,
        &expected,
        &app.evidence,
        &EvidenceAcceptancePolicy::default(),
    )
    .unwrap();
    app.evidence_inputs = Some(
        fortress_core::provider_inputs::EvidenceInputSet::compose(
            app.declaration.binding.clone(),
            vec![],
        )
        .unwrap(),
    );
    s.view.as_mut().unwrap().status = match s
        .view
        .as_ref()
        .unwrap()
        .application
        .as_ref()
        .unwrap()
        .assessment
        .decision
    {
        AssessmentDecision::Satisfied => StateViewStatus::Complete,
        AssessmentDecision::NotSatisfied => StateViewStatus::Negative,
        AssessmentDecision::NotEvaluable => StateViewStatus::Partial,
        AssessmentDecision::Invalid => StateViewStatus::Invalid,
    };
    s.validate().unwrap();
}
/// `T-AF-STATE-GOVERNANCE-0001-R01-001`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R01
#[test]
fn four_axes_unchanged_single_and_simultaneous_are_independent() {
    let before = state();
    let same = compare(&before, &before);
    assert!(
        same.input_deltas
            .iter()
            .all(|prior| prior.change == Change::Unchanged)
    );
    for target in [
        Axis::Subject,
        Axis::Intent,
        Axis::Authority,
        Axis::Governance,
    ] {
        let mut after = before.clone();
        after.assets.as_mut().unwrap().inputs.push(AxisInput {
            id: "changed".into(),
            path: "changed.json".into(),
            content_ref: d(20),
            scope_refs: BTreeSet::new(),
            roles: BTreeMap::from([(target, d(21))]),
        });
        let t = compare(&before, &after);
        for prior in &t.input_deltas {
            assert_eq!(
                prior.change,
                if prior.axis == target {
                    Change::Changed
                } else {
                    Change::Unchanged
                }
            );
        }
    }
    let mut after = before.clone();
    after.assets.as_mut().unwrap().inputs.push(AxisInput {
        id: "overlapping".into(),
        path: "__fortress/.fsconfig".into(),
        content_ref: d(20),
        scope_refs: BTreeSet::new(),
        roles: [
            Axis::Subject,
            Axis::Intent,
            Axis::Authority,
            Axis::Governance,
        ]
        .into_iter()
        .map(|prior| (prior, d(21)))
        .collect(),
    });
    assert!(
        compare(&before, &after)
            .input_deltas
            .iter()
            .all(|d| d.change == Change::Changed)
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R02-001`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R02
#[test]
fn policy_relaxation_is_not_code_fix() {
    let cases: Value =
        serde_json::from_str(include_str!("../_data/temporal_cases_v1.json")).unwrap();
    let protocol: Value =
        serde_json::from_str(include_str!("../_data/temporal_protocol_v1.json")).unwrap();
    assert_eq!(
        format!(
            "sha256:{:x}",
            Sha256::digest(include_bytes!("../_data/temporal_cases_v1.json"))
        ),
        protocol["cases_digest"]
    );
    for case in cases["cases"].as_array().unwrap() {
        let mut before = state();
        let mut after = state();
        let mut bp = policy();
        let mut ap = policy();
        bp.denied = set(&case["before_denied"]);
        bp.allowed = set(&case["before_allowed"]);
        ap.denied = set(&case["after_denied"]);
        ap.allowed = set(&case["after_allowed"]);
        install_policy(&mut before, bp);
        install_policy(&mut after, ap);
        let t = compare(&before, &after);
        let row = t
            .semantic_deltas
            .iter()
            .find(|prior| prior.category == "policy")
            .unwrap();
        assert_eq!(json!(row.change), case["expected"], "{}", case["id"]);
        assert_eq!(axis(&t, Axis::Subject), Change::Unchanged);
    }
}
/// `T-AF-STATE-GOVERNANCE-0001-R02-002`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R02
#[test]
fn finite_policy_order_matches_independent_exhaustive_assignment_oracle() {
    // An independent test-owned product order over each target: DENY > UNDECLARED > ALLOW.
    // Compare every two-target assignment; expected answers never consume Fortress output.
    for before in 0..9 {
        for after in 0..9 {
            let assignments = |n: usize| [n % 3, n / 3];
            let prior = assignments(before);
            let next = assignments(after);
            let mut before = state();
            let mut after = state();
            let mut bp = policy();
            let mut ap = policy();
            for (index, name) in ["fs.read", "fs.write"].into_iter().enumerate() {
                for (v, p) in [(prior[index], &mut bp), (next[index], &mut ap)] {
                    if v == 0 {
                        p.allowed.insert(name.into());
                    } else if v == 2 {
                        p.denied.insert(name.into());
                    }
                }
            }
            install_policy(&mut before, bp);
            install_policy(&mut after, ap);
            let expected = if prior == next {
                Change::Unchanged
            } else if (0..2).all(|i| next[i] >= prior[i]) {
                Change::Strengthened
            } else if (0..2).all(|i| next[i] <= prior[i]) {
                Change::Weakened
            } else {
                Change::Mixed
            };
            assert_eq!(
                compare(&before, &after)
                    .semantic_deltas
                    .iter()
                    .find(|d| d.category == "policy")
                    .unwrap()
                    .change,
                expected
            );
        }
    }
}
/// `T-AF-STATE-GOVERNANCE-0001-R01-002`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R01
#[test]
fn analyzer_change_without_verdict_change_is_visible() {
    let before = app_state(DeclarationTruth::NoSupportedViolation, 9, 4);
    let mut after = before.clone();
    after.assets.as_mut().unwrap().evaluator_ref = Some(d(30));
    let t = compare(&before, &after);
    assert_eq!(axis(&t, Axis::Authority), Change::Changed);
    assert!(
        t.semantic_deltas
            .iter()
            .any(|d| d.category == "semantic" && d.change == Change::NotComparable)
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R02-003`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R02
#[test]
fn code_and_permission_comovement_requires_authority() {
    let mut before = state();
    let mut p = policy();
    p.denied.insert("fs.write".into());
    install_policy(&mut before, p);
    let mut after = before.clone();
    let assets = after.assets.as_mut().unwrap();
    assets.inputs[0].roles.insert(Axis::Subject, d(31));
    assets.inputs[1].roles.insert(Axis::Intent, d(32));
    assets.policies[0].denied.clear();
    assets.policies[0].allowed.insert("fs.write".into());
    assets.policies[0].origin_ref = d(32);
    assets.inputs[1].content_ref = d(32);
    let t = compare(&before, &after);
    assert!(
        t.semantic_deltas
            .iter()
            .any(|d| d.change == Change::CoMovingAuthorization)
    );
    assert!(
        t.required_authorizations
            .iter()
            .all(|right_index| right_index.validation == "NOT_VALIDATED")
    );
    assert_eq!(t.required_authorizations.len(), 1);
}
/// `T-AF-STATE-GOVERNANCE-0001-R03-001`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R03
#[test]
fn excluded_scope_is_not_resolved_finding() {
    let before = app_state(DeclarationTruth::SupportedViolation, 9, 4);
    let mut after = app_state(DeclarationTruth::NotEvaluable, 9, 4);
    let exclusions = BTreeSet::from(["src/excluded".to_owned()]);
    after.assets.as_mut().unwrap().exclusions_ref = Some(value_ref(&exclusions));
    after.assets.as_mut().unwrap().exclusions = Some(exclusions);
    let t = compare(&before, &after);
    assert_eq!(
        t.finding_deltas
            .iter()
            .find(|prior| prior.id == "finding-one")
            .unwrap()
            .change,
        Change::NotObserved
    );
    assert!(
        t.semantic_deltas
            .iter()
            .any(|prior| prior.change == Change::NotComparable)
    );
    assert!(
        t.coverage_deltas
            .iter()
            .any(|d| d.change == Change::ScopeExcluded)
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R03-002`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R03
#[test]
fn noncomparable_context_stays_noncomparable() {
    let before = app_state(DeclarationTruth::SupportedViolation, 9, 4);
    let after = app_state(DeclarationTruth::NoSupportedViolation, 10, 4);
    let t = compare(&before, &after);
    assert_eq!(axis(&t, Axis::Authority), Change::Changed);
    assert!(
        t.semantic_deltas
            .iter()
            .any(|prior| prior.category == "semantic" && prior.change == Change::NotComparable)
    );
    assert!(!t.incomparabilities.is_empty());
}
/// `T-AF-STATE-GOVERNANCE-0001-R03-003`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R03
#[test]
fn evaluability_gain_loss_and_nonapplicability_preserve_original_truth() {
    let unknown = app_state(DeclarationTruth::NotEvaluable, 9, 4);
    let known = app_state(DeclarationTruth::SupportedViolation, 9, 4);
    assert!(
        compare(&unknown, &known)
            .coverage_deltas
            .iter()
            .any(|d| d.change == Change::NewlyEvaluable)
    );
    assert!(
        compare(&known, &unknown)
            .coverage_deltas
            .iter()
            .any(|d| d.change == Change::EvaluabilityLost)
    );
    let na = app_state(DeclarationTruth::NotApplicable, 9, 4);
    assert!(
        compare(&na, &na)
            .coverage_deltas
            .iter()
            .any(|d| d.change == Change::NotApplicable)
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R04-001`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R04
#[test]
fn identity_preserving_relocation_has_placement_delta_only() {
    let mut before = state();
    before.assets.as_mut().unwrap().entities.push(Entity {
        id: "AF-STABLE-0001".into(),
        kind: "module".into(),
        semantic_ref: d(40),
        path: Some("old/contract.json".into()),
        promise: None,
    });
    let mut after = before.clone();
    after.assets.as_mut().unwrap().entities[0].path = Some("new/contract.json".into());
    let t = compare(&before, &after);
    assert_eq!(
        t.semantic_deltas
            .iter()
            .find(|d| d.category == "entity")
            .unwrap()
            .change,
        Change::PlacementOnly
    );
    assert!(t.input_deltas.iter().all(|d| d.change == Change::Unchanged));
    let mut duplicate = after.assets.as_ref().unwrap().entities[0].clone();
    duplicate.path = Some("another/contract.json".into());
    after.assets.as_mut().unwrap().entities.push(duplicate);
    assert!(
        compare(&before, &after)
            .semantic_deltas
            .iter()
            .any(|d| d.change == Change::IdentityAmbiguous)
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R04-002`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R04
#[test]
fn only_unchanged_authored_conjuncts_support_guarantee_implication() {
    let mut before = state();
    before.assets.as_mut().unwrap().entities.push(Entity {
        id: "GUA-FINITE-PROMISE".into(),
        kind: "guarantee".into(),
        semantic_ref: d(40),
        path: Some("contract.json".into()),
        promise: Some(Promise {
            subject: "module:A".into(),
            quantifier: "ALL".into(),
            clauses: BTreeMap::from([("R01".into(), d(41))]),
        }),
    });
    let mut after = before.clone();
    let e = &mut after.assets.as_mut().unwrap().entities[0];
    e.semantic_ref = d(42);
    e.promise
        .as_mut()
        .unwrap()
        .clauses
        .insert("R02".into(), d(43));
    assert_eq!(
        compare(&before, &after).strengthenings,
        vec!["entity:guarantee:GUA-FINITE-PROMISE"]
    );
    assert_eq!(
        compare(&after, &before).weakenings,
        vec!["entity:guarantee:GUA-FINITE-PROMISE"]
    );
    after.assets.as_mut().unwrap().entities[0]
        .promise
        .as_mut()
        .unwrap()
        .clauses
        .insert("R01".into(), d(44));
    assert!(
        compare(&before, &after)
            .semantic_deltas
            .iter()
            .any(|d| d.change == Change::NotComparable)
    );
    after.assets.as_mut().unwrap().entities.clear();
    let t = compare(&before, &after);
    assert!(
        t.semantic_deltas
            .iter()
            .any(|d| d.change == Change::Removed)
    );
    assert!(t.weakenings.is_empty());
}
/// `T-AF-STATE-GOVERNANCE-0001-R05-001`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R05
#[test]
fn merge_parents_are_labelled_separately() {
    let before = state();
    let mut parent = before.clone();
    parent.assets.as_mut().unwrap().inputs[0]
        .roles
        .insert(Axis::Subject, d(45));
    let result = compare_merge(
        &before,
        &[
            ("parent-z".into(), parent.clone()),
            ("parent-a".into(), before.clone()),
        ],
        &parent,
        &ComparisonContext::default(),
    )
    .unwrap();
    assert_eq!(
        result
            .iter()
            .map(|right_index| right_index.label.as_str())
            .collect::<Vec<_>>(),
        vec!["base", "parent-a", "parent-z"]
    );
    assert_eq!(axis(&result[0].transition, Axis::Subject), Change::Changed);
    assert_eq!(
        axis(&result[2].transition, Axis::Subject),
        Change::Unchanged
    );
    assert!(
        compare_merge(
            &before,
            &[("base".into(), parent)],
            &before,
            &ComparisonContext::default()
        )
        .is_err()
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R05-002`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R05
#[test]
fn explicit_common_authority_cells_are_bound_and_incomplete_cells_stay_unknown() {
    let before = app_state(DeclarationTruth::NoSupportedViolation, 9, 4);
    let after = app_state(DeclarationTruth::NotEvaluable, 9, 10);
    let cell = Counterfactual {
        subject_ref: before.subject_identity().unwrap().unwrap(),
        authority_ref: before.governing_identity().unwrap().unwrap(),
        view: before.view.clone().unwrap(),
        assets: before.assets.clone(),
    };
    let context = ComparisonContext {
        counterfactuals: vec![cell.clone()],
        ..Default::default()
    };
    assert!(
        compare_states(&before, &after, &context)
            .unwrap()
            .semantic_deltas
            .iter()
            .any(|d| d.category == "common_authority" && d.change == Change::NotComparable)
    );
    let mut wrong = cell.clone();
    wrong.subject_ref = d(99);
    assert!(
        compare_states(
            &before,
            &after,
            &ComparisonContext {
                counterfactuals: vec![wrong],
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        compare_states(
            &before,
            &after,
            &ComparisonContext {
                counterfactuals: vec![cell.clone(), cell],
                ..Default::default()
            }
        )
        .is_err()
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R06-001`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R06
#[test]
fn canonical_replay_is_order_independent_bound_and_cancellable() {
    let before = state();
    let mut after = before.clone();
    after.assets.as_mut().unwrap().inputs.reverse();
    assert_eq!(after.digest().unwrap(), before.digest().unwrap());
    let mut ambiguous = before.clone();
    let mut duplicate = ambiguous.assets.as_ref().unwrap().inputs[0].clone();
    duplicate.path = "another.rs".into();
    ambiguous.assets.as_mut().unwrap().inputs.push(duplicate);
    let ordered = compare(&before, &ambiguous).to_canonical_bytes().unwrap();
    ambiguous.assets.as_mut().unwrap().inputs.reverse();
    assert_eq!(
        ordered,
        compare(&before, &ambiguous).to_canonical_bytes().unwrap()
    );
    let t = compare(&before, &after);
    let bytes = t.to_canonical_bytes().unwrap();
    let digest = t.digest().unwrap();
    assert!(
        TransitionAnalysis::from_json_str(std::str::from_utf8(&bytes).unwrap(), &digest).is_ok()
    );
    assert!(
        TransitionAnalysis::from_json_str(std::str::from_utf8(&bytes).unwrap(), &d(99)).is_err()
    );
    assert_eq!(
        compare_states_cancellable(
            &before,
            &after,
            &ComparisonContext::default(),
            &std::sync::atomic::AtomicBool::new(true)
        )
        .unwrap_err()
        .code,
        "CANCELLED"
    );
    assert!(ComparisonState::from_json_str("{\"schema_version\":1,\"schema_version\":1}").is_err());
    after.schema_version = 2;
    assert_eq!(after.validate().unwrap_err().code, "UNSUPPORTED_VERSION");
}
/// `T-AF-STATE-GOVERNANCE-0001-R06-002`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R06
#[test]
fn missing_history_unsupported_vocabulary_and_malformed_paths_are_honest() {
    let before = state();
    let missing = ComparisonState::unavailable(Some(d(90)));
    let t = compare(&before, &missing);
    assert!(t.input_deltas.iter().all(|d| d.change == Change::Unknown));
    assert!(!t.incomparabilities.is_empty());
    let mut duplicate_set = serde_json::to_value(&before).unwrap();
    duplicate_set["assets"]["complete_axes"]
        .as_array_mut()
        .unwrap()
        .push(json!("SUBJECT"));
    assert!(ComparisonState::from_json_str(&duplicate_set.to_string()).is_err());
    let mut after = before.clone();
    after.assets.as_mut().unwrap().inputs[0].path = "../escape".into();
    assert!(after.validate().is_err());
    let mut after = before.clone();
    after.assets.as_mut().unwrap().policies.push(policy());
    let mut c = after.clone();
    c.assets.as_mut().unwrap().policies[0].quantifier = "EXISTS".into();
    assert!(
        compare(&after, &c)
            .semantic_deltas
            .iter()
            .any(|d| d.change == Change::Unsupported)
    );
    c.assets.as_mut().unwrap().policies[0].quantifier = "ALL".into();
    c.assets.as_mut().unwrap().policies[0].vocabulary_ref = d(91);
    assert!(
        compare(&after, &c)
            .semantic_deltas
            .iter()
            .any(|d| d.change == Change::NotComparable)
    );
    let mut oversized = before.clone();
    oversized.limitations = vec!["x".repeat(MAX_TRANSITION_BYTES + 1)];
    assert!(oversized.validate().is_err());
}
/// `T-AF-STATE-GOVERNANCE-0001-R01-003`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R01
#[test]
fn governance_only_changes_preserve_raw_truth_and_history() {
    let before = app_state(DeclarationTruth::SupportedViolation, 9, 4);
    let original = before.to_canonical_bytes().unwrap();
    let mut after = before.clone();
    let app = after.view.as_mut().unwrap().application.as_mut().unwrap();
    app.declaration.residue_summary.accepted_baseline = vec!["finding-one".into()];
    refresh(&mut after);
    after.assets.as_mut().unwrap().inputs.push(AxisInput {
        id: "baseline".into(),
        path: "__fortress/governance/finding_governance.json".into(),
        content_ref: d(92),
        scope_refs: BTreeSet::new(),
        roles: BTreeMap::from([(Axis::Governance, d(92))]),
    });
    let t = compare(&before, &after);
    assert_eq!(axis(&t, Axis::Governance), Change::Changed);
    assert_eq!(axis(&t, Axis::Subject), Change::Unchanged);
    assert_eq!(before.to_canonical_bytes().unwrap(), original);
    assert!(
        t.finding_deltas
            .iter()
            .any(|d| d.id == "finding-one" && d.change == Change::Changed)
    );
}

fn change_subject(s: &mut ComparisonState, value: u8) {
    let id = d(value);
    s.assets.as_mut().unwrap().inputs[0]
        .roles
        .insert(Axis::Subject, id.clone());
    s.assets.as_mut().unwrap().inputs[0]
        .content_ref
        .clone_from(&id);
    s.source_ref = Some(id.clone());
    s.assets.as_mut().unwrap().subject_ref.clone_from(&id);
    s.view.as_mut().unwrap().source_ref.clone_from(&id);
    s.view
        .as_mut()
        .unwrap()
        .application
        .as_mut()
        .unwrap()
        .declaration
        .binding
        .subject_ref = id;
    refresh(s);
}
/// `T-AF-STATE-GOVERNANCE-0001-R05-003`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R05
#[test]
fn four_cell_contrasts_are_complete_order_independent_and_never_choose_a_cause() {
    let before = app_state(DeclarationTruth::SupportedViolation, 9, 4);
    let mut after = app_state(DeclarationTruth::NoSupportedViolation, 9, 10);
    change_subject(&mut after, 11);
    let mut other = app_state(DeclarationTruth::NotEvaluable, 9, 4);
    change_subject(&mut other, 11);
    let fourth = app_state(DeclarationTruth::NoSupportedViolation, 9, 10);
    let cells = [before.clone(), after.clone(), other, fourth]
        .into_iter()
        .map(|s| {
            let subject = s.subject_identity().unwrap().unwrap();
            let governing = s.governing_identity().unwrap().unwrap();
            let assets = s.assets.clone();
            let view = s.view.unwrap();
            let _authority = view
                .application
                .as_ref()
                .unwrap()
                .declaration
                .binding
                .authority_ref
                .clone();
            Counterfactual {
                subject_ref: subject,
                authority_ref: governing,
                view,
                assets,
            }
        })
        .collect();
    let context = ComparisonContext {
        counterfactuals: cells,
        ..Default::default()
    };
    let result = compare_states(&before, &after, &context).unwrap();
    let mut reversed = context.clone();
    reversed.counterfactuals.reverse();
    assert_eq!(
        result.to_canonical_bytes().unwrap(),
        compare_states(&before, &after, &reversed)
            .unwrap()
            .to_canonical_bytes()
            .unwrap()
    );
    assert_eq!(
        result
            .semantic_deltas
            .iter()
            .filter(|d| d.category == "common_authority" && d.change == Change::Changed)
            .count(),
        2
    );
    assert!(
        result
            .limitations
            .iter()
            .any(|s| s.contains("neither regression"))
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R03-004`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R03
#[test]
fn missing_obligations_are_not_retired_and_original_retained_results_are_unchanged() {
    let before = app_state(DeclarationTruth::SupportedViolation, 9, 4);
    let original = before.to_canonical_bytes().unwrap();
    let mut retained = before.clone();
    let mut app = retained.view.take().unwrap().application.unwrap();
    app.evidence_inputs = None;
    retained.retained_application = Some(app);
    retained.assets = None;
    let result = compare(&before, &retained);
    assert!(
        result
            .evidence_deltas
            .iter()
            .any(|d| d.id == "retained-metadata" && d.change == Change::NotComparable)
    );
    assert!(
        !result
            .evidence_deltas
            .iter()
            .any(|d| d.change == Change::Removed)
    );
    assert_eq!(original, before.to_canonical_bytes().unwrap());
    let absent = app_state(DeclarationTruth::NotEvaluable, 9, 4);
    let retirement = compare(&before, &absent).retirement_evidence;
    assert_eq!(retirement.len(), 1);
    assert_eq!(
        retirement[0].reason,
        fortress_core::finding_governance::RetirementReason::NotObserved
    );
    assert!(retirement[0].support_refs.is_empty());
}
/// `T-AF-STATE-GOVERNANCE-0001-R03-005`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R03
#[test]
fn introduced_retired_obligations_and_incompatible_profiles_remain_distinct() {
    let mut declared = state();
    install_policy(&mut declared, policy());
    assert!(
        compare(&declared, &state())
            .semantic_deltas
            .iter()
            .any(|d| d.category == "policy" && d.change == Change::PolicyRetired)
    );
    assert!(
        compare(&state(), &declared)
            .semantic_deltas
            .iter()
            .any(|d| d.category == "policy" && d.change == Change::Added)
    );
    let before = app_state(DeclarationTruth::NoSupportedViolation, 9, 4);
    let mut after = before.clone();
    after
        .view
        .as_mut()
        .unwrap()
        .application
        .as_mut()
        .unwrap()
        .obligations
        .push(ProfileObligation {
            id: "verification:new".into(),
            scope_ref: "requirement:new".into(),
            predicate: ObligationPredicate::SuccessfulExecution,
            evidence_class: fortress_core::certification::EvidenceClass::ExecutedTest,
            authenticated_producer_required: true,
            proof: None,
        });
    refresh(&mut after);
    assert!(
        compare(&before, &after)
            .evidence_deltas
            .iter()
            .any(|d| d.category == "obligation" && d.change == Change::Added)
    );
    assert!(
        compare(&after, &before)
            .evidence_deltas
            .iter()
            .any(|d| d.category == "obligation" && d.change == Change::Removed)
    );
    assert!(compare(&before, &after).strengthenings.is_empty());
    let mut incompatible_standard = before.clone();
    incompatible_standard.assets.as_mut().unwrap().standard_ref = Some(d(101));
    assert!(
        compare(&before, &incompatible_standard)
            .semantic_deltas
            .iter()
            .any(|d| d.category == "semantic" && d.change == Change::NotComparable)
    );
    after.assets.as_mut().unwrap().profile_refs.insert(d(100));
    let result = compare(&before, &after);
    assert_eq!(axis(&result, Axis::Authority), Change::Changed);
    assert!(
        result
            .evidence_deltas
            .iter()
            .any(|d| d.category == "assurance" && d.change == Change::NotComparable)
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R04-003`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R04
#[test]
fn formatting_storage_and_ambiguous_input_identity_do_not_fake_semantic_changes() {
    let before = state();
    let mut after = before.clone();
    after.assets.as_mut().unwrap().inputs[1].content_ref = d(50);
    let result = compare(&before, &after);
    assert!(
        result
            .input_deltas
            .iter()
            .all(|d| d.change == Change::Unchanged)
    );
    assert!(
        result
            .evidence_deltas
            .iter()
            .any(|d| d.change == Change::StorageOnly)
    );
    let mut duplicate = after.assets.as_ref().unwrap().inputs[0].clone();
    duplicate.path = "other.rs".into();
    after.assets.as_mut().unwrap().inputs.push(duplicate);
    let result = compare(&before, &after);
    assert!(
        result
            .semantic_deltas
            .iter()
            .any(|d| d.change == Change::IdentityAmbiguous)
    );
    assert!(
        !result
            .input_deltas
            .iter()
            .find(|d| d.axis == Axis::Subject)
            .unwrap()
            .complete
    );
    let mut after = before.clone();
    let mut observation = Entity {
        id: "observed".into(),
        kind: "observation".into(),
        semantic_ref: d(51),
        path: None,
        promise: None,
    };
    observation.promise = Some(Promise {
        subject: "x".into(),
        quantifier: "ALL".into(),
        clauses: BTreeMap::new(),
    });
    after.assets.as_mut().unwrap().entities.push(observation);
    assert!(after.validate().is_err());
}
/// `T-AF-STATE-GOVERNANCE-0001-R06-003`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R06
#[test]
fn protocol_two_pages_complete_results_and_preserves_version_one() {
    use fortress_core::query::*;
    use std::sync::atomic::AtomicBool;
    let mut before = state();
    for i in 0..501 {
        before.assets.as_mut().unwrap().entities.push(Entity {
            id: format!("observation-{i:04}"),
            kind: "observation".into(),
            semantic_ref: d(20),
            path: None,
            promise: None,
        });
    }
    let after = before.clone();
    let reference = before.digest().unwrap();
    let service = QueryService::new(QueryInput::empty(d(1)))
        .unwrap()
        .with_comparison_states(vec![before, after])
        .unwrap();
    let mut cursor = Value::Null;
    let mut seen = BTreeSet::new();
    let mut result_ref = None;
    let total = loop {
        let request = QueryRequest {
            protocol_version: 2,
            request_id: "compare".into(),
            method: "transition".into(),
            state_ref: None,
            context_ref: None,
            parameters: json!({"from_state_ref":reference,"to_state_ref":reference,"page":{"limit":17,"cursor":cursor}}),
        };
        let response = service.execute(&request, &AtomicBool::new(false));
        assert!(response.error.is_none(), "{:?}", response.error);
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["protocol_version"], 2);
        let body = &value["result"]["data"];
        if let Some(id) = &result_ref {
            assert_eq!(&body["analysis_ref"], id);
        } else {
            result_ref = Some(body["analysis_ref"].clone());
        }
        for row in body["deltas"]["records"].as_array().unwrap() {
            assert!(seen.insert(row["id"].as_str().unwrap().to_owned()));
            assert!(response.to_human().contains(row["id"].as_str().unwrap()));
        }
        cursor = body["deltas"]["next_cursor"].clone();
        if cursor.is_null() {
            break body["deltas"]["total"].as_u64().unwrap();
        }
    };
    assert_eq!(seen.len() as u64, total);
    assert!(seen.iter().any(|s| s.contains("observation-0500")));
    let mut request = QueryRequest {
        protocol_version: 1,
        request_id: "old".into(),
        method: "transition".into(),
        state_ref: None,
        context_ref: None,
        parameters: json!({"from_state_ref":reference,"to_state_ref":reference}),
    };
    assert_eq!(
        service
            .execute(&request, &AtomicBool::new(false))
            .error
            .unwrap()
            .code,
        "UNKNOWN_METHOD"
    );
    request.method = "protocol".into();
    request.parameters = json!({});
    let inventory =
        serde_json::to_value(service.execute(&request, &AtomicBool::new(false))).unwrap();
    assert!(
        !inventory["result"]["data"]["methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "transition")
    );
    assert_eq!(
        service
            .execute(&request, &AtomicBool::new(false))
            .protocol_version,
        1
    );
    request.protocol_version = 99;
    assert_eq!(
        service
            .execute(&request, &AtomicBool::new(false))
            .error
            .unwrap()
            .code,
        "UNSUPPORTED_VERSION"
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R06-004`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R06
#[test]
fn public_input_result_and_response_schemas_match_emitted_meaning() {
    use fortress_core::query::{QueryInput, QueryRequest, QueryService};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(root.join("engine/standard_registry/_data/schema_manifest.json")).unwrap(),
    )
    .unwrap();
    let mut schemas = BTreeMap::new();
    for file in manifest["schemas"].as_array().unwrap() {
        let v: Value =
            serde_json::from_slice(&std::fs::read(root.join(file.as_str().unwrap())).unwrap())
                .unwrap();
        schemas.insert(v["$id"].as_str().unwrap().to_owned(), v);
    }
    let endpoint = state();
    let reference = endpoint.digest().unwrap();
    let service = QueryService::new(QueryInput::empty(d(1)))
        .unwrap()
        .with_comparison_states(vec![endpoint])
        .unwrap();
    let response = service.execute(
        &QueryRequest {
            protocol_version: 2,
            request_id: "schema".into(),
            state_ref: None,
            context_ref: None,
            method: "transition".into(),
            parameters: json!({"from_state_ref":reference,"to_state_ref":reference}),
        },
        &std::sync::atomic::AtomicBool::new(false),
    );
    assert!(response.error.is_none());
    for value in [
        serde_json::to_value(state()).unwrap(),
        serde_json::to_value(compare(&state(), &state())).unwrap(),
        serde_json::to_value(response).unwrap(),
    ] {
        let id = value["$schema"].as_str().unwrap();
        let resources = schemas
            .iter()
            .map(|(id, v)| {
                (
                    id.clone(),
                    jsonschema::Resource::from_contents(v.clone()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let validator = jsonschema::options()
            .with_resources(resources.into_iter())
            .build(&schemas[id])
            .unwrap();
        assert!(
            validator.is_valid(&value),
            "{:?}",
            validator.iter_errors(&value).collect::<Vec<_>>()
        );
    }
}

/// `T-AF-STATE-GOVERNANCE-0001-R02-004`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R02
#[test]
fn unrelated_or_unsupported_permission_changes_never_become_coauthorization() {
    let mut before = state();
    let mut restriction = policy();
    restriction.denied.insert("fs.write".into());
    install_policy(&mut before, restriction);
    let mut after = before.clone();
    after.assets.as_mut().unwrap().inputs[0]
        .roles
        .insert(Axis::Subject, d(31));
    after.assets.as_mut().unwrap().inputs[0].scope_refs = BTreeSet::from(["other-module".into()]);
    let mut permission = policy();
    permission.allowed.insert("fs.write".into());
    after.assets.as_mut().unwrap().policies.clear();
    install_policy(&mut after, permission);
    let result = compare(&before, &after);
    assert!(
        !result
            .semantic_deltas
            .iter()
            .any(|d| d.change == Change::CoMovingAuthorization)
    );
    assert!(
        result
            .semantic_deltas
            .iter()
            .any(|d| d.id == "source-permission-comovement" && d.change == Change::Unknown)
    );
    after.assets.as_mut().unwrap().policies[0].complete = false;
    let result = compare(&before, &after);
    assert!(
        result
            .semantic_deltas
            .iter()
            .any(|d| d.change == Change::Unsupported)
    );
    assert!(result.weakenings.is_empty());
}
/// `T-AF-STATE-GOVERNANCE-0001-R03-006`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R03
#[test]
fn reported_evaluability_gain_across_authority_drift_does_not_hide_incomparability() {
    let before = app_state(DeclarationTruth::NotEvaluable, 9, 4);
    let mut after = app_state(DeclarationTruth::SupportedViolation, 9, 4);
    after.assets.as_mut().unwrap().evaluator_ref = Some(d(120));
    let result = compare(&before, &after);
    assert_eq!(axis(&result, Axis::Authority), Change::Changed);
    assert_eq!(axis(&result, Axis::Subject), Change::Unchanged);
    assert!(
        result
            .coverage_deltas
            .iter()
            .any(|d| d.change == Change::NewlyEvaluable)
    );
    assert!(
        result
            .semantic_deltas
            .iter()
            .any(|d| d.category == "semantic" && d.change == Change::NotComparable)
    );
    assert!(result.strengthenings.is_empty());
}
/// `T-AF-STATE-GOVERNANCE-0001-R01-004`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R01
#[test]
fn frozen_temporal_axis_matrix_and_every_axis_combination_match_independent_expectations() {
    let frozen: Value =
        serde_json::from_str(include_str!("../_data/temporal_cases_v1.json")).unwrap();
    let mut patterns = (0u8..16)
        .map(|mask| {
            [
                Axis::Subject,
                Axis::Intent,
                Axis::Authority,
                Axis::Governance,
            ]
            .into_iter()
            .enumerate()
            .filter(|(n, _)| mask & (1 << n) != 0)
            .map(|(_, axis)| axis)
            .collect::<BTreeSet<_>>()
        })
        .collect::<Vec<_>>();
    for case in frozen["temporal_cases"].as_array().unwrap() {
        patterns.push(serde_json::from_value(case["changes"].clone()).unwrap());
    }
    for changes in patterns {
        let before = state();
        let mut after = before.clone();
        if !changes.is_empty() {
            after.assets.as_mut().unwrap().inputs.push(AxisInput {
                id: "frozen-change".into(),
                path: "configured.json".into(),
                scope_refs: BTreeSet::new(),
                content_ref: d(123),
                roles: changes.iter().map(|axis| (*axis, d(124))).collect(),
            });
        }
        let result = compare(&before, &after);
        for delta in &result.input_deltas {
            assert_eq!(
                delta.change,
                if changes.contains(&delta.axis) {
                    Change::Changed
                } else {
                    Change::Unchanged
                }
            );
        }
    }
    assert_eq!(frozen["temporal_cases"].as_array().unwrap().len(), 20);
}
/// `T-AF-STATE-GOVERNANCE-0001-R04-004`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R04
#[test]
fn incomplete_inventory_never_retires_properties_and_observation_moves_are_not_equivalence() {
    let mut before = state();
    before.assets.as_mut().unwrap().entities.push(Entity {
        id: "opaque-derived-symbol".into(),
        kind: "observation".into(),
        semantic_ref: d(70),
        path: Some("old.rs".into()),
        promise: None,
    });
    let mut after = before.clone();
    after.assets.as_mut().unwrap().entities[0].path = Some("new.rs".into());
    assert!(
        compare(&before, &after)
            .semantic_deltas
            .iter()
            .any(|d| d.change == Change::NotComparable)
    );
    after.assets.as_mut().unwrap().entities.clear();
    after.assets.as_mut().unwrap().complete_axes.clear();
    let result = compare(&before, &after);
    assert!(
        result
            .semantic_deltas
            .iter()
            .any(|d| d.category == "entity" && d.change == Change::Unknown)
    );
    assert!(
        !result
            .semantic_deltas
            .iter()
            .any(|d| d.change == Change::Removed)
    );
}

struct HistoryFixture(std::path::PathBuf);
impl HistoryFixture {
    fn new() -> Self {
        for n in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fortress-transition-history-{}-{n}",
                std::process::id()
            ));
            if std::fs::create_dir(&path).is_ok() {
                return Self(path);
            }
        }
        panic!("bounded fixture claim exhausted");
    }
}
impl Drop for HistoryFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
/// `T-AF-STATE-GOVERNANCE-0001-R06-005`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R06
#[test]
fn registered_history_missing_artifacts_and_tampering_are_read_only_and_explicit() {
    use fortress_core::control_layout::ControlLayout;
    use fortress_core::transition_load::load_comparison_state;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let layout = ControlLayout::standard();
    let index: Value = serde_json::from_slice(
        &std::fs::read(
            root.join(
                layout
                    .role_path(fortress_core::control_layout::ControlRole::AssessmentSelectionIndex)
                    .unwrap(),
            ),
        )
        .unwrap(),
    )
    .unwrap();
    let generation = index["selections"][0]["generation_digest"]
        .as_str()
        .unwrap();
    let loaded = load_comparison_state(&root, &format!("generation:{generation}")).unwrap();
    assert!(loaded.view.is_none());
    assert!(loaded.assets.is_none());
    assert!(loaded.retained_application.is_some());
    let fixture = HistoryFixture::new();
    assert!(
        load_comparison_state(&fixture.0, &format!("generation:{generation}"))
            .unwrap()
            .source_ref
            .is_none()
    );
    let member = layout.generation_path(generation, None).unwrap();
    let manifest = std::fs::read(root.join(&member)).unwrap();
    let value: Value = serde_json::from_slice(&manifest).unwrap();
    let dest = fixture.0.join(&member);
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::write(&dest, &manifest).unwrap();
    for artifact in value["artifacts"].as_array().unwrap() {
        if artifact["storage"]["kind"] == "INCLUDED" {
            let path = layout
                .generation_path(generation, Some(artifact["id"].as_str().unwrap()))
                .unwrap();
            std::fs::write(
                fixture.0.join(&path),
                std::fs::read(root.join(&path)).unwrap(),
            )
            .unwrap();
        }
    }
    let evidence = layout
        .generation_path(generation, Some("evidence-graph"))
        .unwrap();
    std::fs::remove_file(fixture.0.join(&evidence)).unwrap();
    let partial = load_comparison_state(&fixture.0, &format!("generation:{generation}")).unwrap();
    assert!(partial.retained_application.is_some());
    assert!(
        partial
            .limitations
            .iter()
            .any(|s| s.contains("Missing historical artifact"))
    );
    let declaration = layout
        .generation_path(generation, Some("conformance-declaration"))
        .unwrap();
    std::fs::write(fixture.0.join(&declaration), b"tampered").unwrap();
    assert_eq!(
        load_comparison_state(&fixture.0, &format!("generation:{generation}"))
            .unwrap_err()
            .code,
        "INTEGRITY_ERROR"
    );
    assert!(load_comparison_state(&fixture.0, "generation:sha256:../escape").is_err());
    assert_eq!(std::fs::read(root.join(member)).unwrap(), manifest);
}
/// `T-AF-STATE-GOVERNANCE-0001-R01-005`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R01
#[test]
fn real_governance_capture_keeps_software_and_standard_authority_independent() {
    use fortress_core::bootstrap::{
        BootstrapDiscoveryOptions, apply_repository_bootstrap, discover_repository_bootstrap,
    };
    use fortress_core::transition_load::load_comparison_state;
    let fixture = HistoryFixture::new();
    std::fs::create_dir(fixture.0.join("src")).unwrap();
    std::fs::write(
        fixture.0.join("Cargo.toml"),
        b"[package]\nname=\"temporal-fixture\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    std::fs::write(fixture.0.join("src/lib.rs"), b"pub fn value()->u32 {7}\n").unwrap();
    let proposal = discover_repository_bootstrap(
        &fixture.0,
        &BootstrapDiscoveryOptions::new(
            Some("PF-TEMPORAL-FIXTURE".into()),
            Some("Temporal Fixture".into()),
        ),
    )
    .unwrap();
    apply_repository_bootstrap(&fixture.0, &proposal, false).unwrap();
    let before = load_comparison_state(&fixture.0, "current").unwrap();
    assert!(
        before.view.as_ref().unwrap().application.is_some(),
        "{:?}",
        before.view
    );
    let layout = fortress_core::control_layout::ControlLayout::standard();
    let gov = fixture.0.join(
        layout
            .role_path(fortress_core::control_layout::ControlRole::FindingGovernance)
            .unwrap(),
    );
    std::fs::remove_file(gov).unwrap();
    let after = load_comparison_state(&fixture.0, "current").unwrap();
    let result = compare(&before, &after);
    assert_ne!(before.source_ref, after.source_ref);
    assert_eq!(
        before.subject_identity().unwrap(),
        after.subject_identity().unwrap()
    );
    assert_ne!(
        before.governing_identity().unwrap(),
        after.governing_identity().unwrap()
    );
    assert_eq!(axis(&result, Axis::Subject), Change::Unchanged);
    assert_eq!(axis(&result, Axis::Intent), Change::Unchanged);
    assert_eq!(axis(&result, Axis::Authority), Change::Unchanged);
    assert_eq!(axis(&result, Axis::Governance), Change::Changed);
}

/// `T-AF-STATE-GOVERNANCE-0001-R01-006`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R01
#[test]
fn incomplete_authority_is_unknown_without_hiding_known_differences() {
    let mut missing_standard = app_state(DeclarationTruth::NoSupportedViolation, 9, 4);
    missing_standard.assets.as_mut().unwrap().standard_ref = None;
    let mut changed_source = missing_standard.clone();
    change_subject(&mut changed_source, 122);
    let cells = [&missing_standard, &changed_source]
        .into_iter()
        .map(|state| Counterfactual {
            subject_ref: state.subject_identity().unwrap().unwrap(),
            authority_ref: state
                .view
                .as_ref()
                .unwrap()
                .application
                .as_ref()
                .unwrap()
                .declaration
                .binding
                .authority_ref
                .clone(),
            view: state.view.clone().unwrap(),
            assets: state.assets.clone(),
        })
        .collect();
    let contrast = compare_states(
        &missing_standard,
        &changed_source,
        &ComparisonContext {
            counterfactuals: cells,
            ..ComparisonContext::default()
        },
    )
    .unwrap();
    assert!(
        contrast
            .semantic_deltas
            .iter()
            .any(|d| d.category == "common_authority" && d.change == Change::NotComparable)
    );
    let before = app_state(DeclarationTruth::NoSupportedViolation, 9, 4);
    let mut partial = before.clone();
    let assets = partial.assets.as_mut().unwrap();
    assets.complete_axes.remove(&Axis::Authority);
    assets.complete_axes.remove(&Axis::Intent);
    assets.standard_ref = None;
    assets.evaluator_ref = None;
    assets.profile_refs.clear();
    assets.exclusions_ref = None;
    assets.exclusions = None;
    let result = compare(&before, &partial);
    assert_eq!(axis(&result, Axis::Subject), Change::Unchanged);
    assert_eq!(axis(&result, Axis::Authority), Change::Unknown);
    assert_eq!(axis(&result, Axis::Intent), Change::Unknown);
    assert!(
        result
            .semantic_deltas
            .iter()
            .any(|d| d.category == "semantic" && d.change == Change::NotComparable)
    );
    partial.assets.as_mut().unwrap().standard_ref = Some(d(121));
    assert_eq!(
        axis(&compare(&before, &partial), Axis::Authority),
        Change::Changed
    );
    let mut declared = state();
    let mut restricted = policy();
    restricted.denied.insert("fs.write".into());
    install_policy(&mut declared, restricted);
    let mut relaxed = declared.clone();
    let mut permitted = policy();
    permitted.allowed.insert("fs.write".into());
    relaxed.assets.as_mut().unwrap().policies.clear();
    install_policy(&mut relaxed, permitted);
    relaxed
        .assets
        .as_mut()
        .unwrap()
        .complete_axes
        .remove(&Axis::Authority);
    let result = compare(&declared, &relaxed);
    assert!(result.weakenings.is_empty());
    assert!(
        result
            .semantic_deltas
            .iter()
            .any(|d| d.category == "policy" && d.change == Change::NotComparable)
    );
}
