//! Evidence-governed retirement acceptance controls over existing owner results.
use super::*;
use fortress_core::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingLocation, FindingOccurrence,
    RuleFindingDefinition,
};
use fortress_core::finding_governance::{FindingGovernanceDocument, RetirementOutcome};
use fortress_core::standard::FindingCategory;

fn raw() -> CanonicalFinding {
    presentation("src/lib.rs", "Original violation")
}
fn presentation(path: &str, message: &str) -> CanonicalFinding {
    occurrence(path, message, "EXACT_TARGET")
}
fn occurrence(path: &str, message: &str, discriminator: &str) -> CanonicalFinding {
    CanonicalFinding::failure(
        RuleFindingDefinition::new(
            "STD-ID-001",
            1,
            FindingCategory::Architecture,
            "Restore the obligation.",
        )
        .unwrap(),
        FindingOccurrence::new(
            vec!["AF-RETIRE-0001".into()],
            FindingLocation::at_path(path).unwrap(),
            message,
        )
        .unwrap()
        .with_discriminator(discriminator)
        .unwrap(),
        EvaluatorProvenance::new("fixture", "1").unwrap(),
        "1.0.0-draft.1",
    )
    .unwrap()
}
fn endpoint(truth: DeclarationTruth) -> ComparisonState {
    let mut s = app_state(truth, 9, 4);
    let app = s.view.as_mut().unwrap().application.as_mut().unwrap();
    let claim = &mut app.declaration.claims[0];
    claim.findings = if truth == DeclarationTruth::SupportedViolation {
        vec![raw().finding_id().into()]
    } else {
        vec![]
    };
    claim.proof_refs = vec!["rule-result:STD-ID-001".into()];
    let claim_digest = value_ref(claim);
    let payload = value_ref(&(
        "static-claim-premise-v1",
        &app.declaration.binding,
        &claim_digest,
        &claim.proof_refs[0],
    ));
    let id = format!(
        "assessment-leaf:{}",
        value_ref(&(&claim.scope_ref, &claim.proof_refs[0]))
    );
    app.evidence = vec![AssessmentEvidence {
        id: id.clone(),
        source_ref: claim.proof_refs[0].clone(),
        binding: app.declaration.binding.clone(),
        scope_ref: claim.scope_ref.clone(),
        evidence_class: fortress_core::certification::EvidenceClass::StaticProof,
        proposition: if truth == DeclarationTruth::NoSupportedViolation {
            EvidenceProposition::NoSupportedViolation
        } else {
            EvidenceProposition::SupportedViolation
        },
        payload_digest: payload,
        assumptions: vec![],
        valid_until: None,
    }];
    app.obligations = vec![ProfileObligation {
        id: claim.id.clone(),
        scope_ref: claim.scope_ref.clone(),
        predicate: ObligationPredicate::RuleCheck,
        evidence_class: fortress_core::certification::EvidenceClass::StaticProof,
        authenticated_producer_required: false,
        proof: Some(fortress_core::proof::ProofGraph::new(
            "root",
            vec![fortress_core::proof::ProofExpression {
                node_id: "root".into(),
                operator: fortress_core::proof::ProofOperator::Leaf,
                required_refs: vec![fortress_core::proof::EvidenceReference::new(id).unwrap()],
                children: vec![],
            }],
        )),
    }];
    if matches!(
        truth,
        DeclarationTruth::NoSupportedViolation | DeclarationTruth::NotApplicable
    ) {
        set_subject(&mut s, 11);
    }
    refresh(&mut s);
    s
}
fn set_subject(s: &mut ComparisonState, n: u8) {
    let subject = d(n);
    s.source_ref = Some(subject.clone());
    let a = s.assets.as_mut().unwrap();
    a.subject_ref.clone_from(&subject);
    a.inputs[0].content_ref = d(n + 1);
    a.inputs[0].roles.insert(Axis::Subject, d(n + 1));
    let view = s.view.as_mut().unwrap();
    view.source_ref = subject.clone();
    let app = view.application.as_mut().unwrap();
    app.declaration.binding.subject_ref = subject;
    for leaf in &mut app.evidence {
        leaf.binding = app.declaration.binding.clone();
        let c = app
            .declaration
            .claims
            .iter()
            .find(|c| c.scope_ref == leaf.scope_ref)
            .unwrap();
        leaf.payload_digest = value_ref(&(
            "static-claim-premise-v1",
            &leaf.binding,
            value_ref(c),
            &leaf.source_ref,
        ));
    }
}
fn governed(s: &ComparisonState) -> FindingGovernanceDocument {
    let mut doc = FindingGovernanceDocument::empty();
    let anchors = finding_anchors(s, &[raw()]).unwrap();
    doc.create_anchored_baseline(
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
        &[raw()],
        anchors,
    )
    .unwrap();
    doc
}
fn retirement(
    a: &ComparisonState,
    b: &ComparisonState,
    doc: &FindingGovernanceDocument,
) -> Vec<fortress_core::finding_governance::RetirementEvidenceV2> {
    assess_retirements(a, b, doc, &ComparisonContext::default()).unwrap()
}

/// `T-AF-STATE-GOVERNANCE-0001-R07-013`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
fn aggregate_retirement_output_is_admitted_before_retention() {
    let mut before = endpoint(DeclarationTruth::SupportedViolation);
    let after = endpoint(DeclarationTruth::NoSupportedViolation);
    let findings = (0..7000)
        .map(|n| occurrence("src/lib.rs", "Same aggregate rule", &format!("TARGET_{n}")))
        .collect::<Vec<_>>();
    let mut ids = findings
        .iter()
        .map(|f| f.finding_id().to_owned())
        .collect::<Vec<_>>();
    ids.sort();
    before
        .view
        .as_mut()
        .unwrap()
        .application
        .as_mut()
        .unwrap()
        .declaration
        .residue_summary
        .blocking_findings = ids.clone();
    before
        .view
        .as_mut()
        .unwrap()
        .application
        .as_mut()
        .unwrap()
        .declaration
        .claims[0]
        .findings = ids;
    refresh(&mut before);
    let anchors = finding_anchors(&before, &findings).unwrap();
    let mut doc = FindingGovernanceDocument::empty_current();
    doc.create_anchored_baseline(
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
        &findings,
        anchors,
    )
    .unwrap();
    let original = doc.authority_digest().unwrap();
    let error =
        assess_retirements(&before, &after, &doc, &ComparisonContext::default()).unwrap_err();
    assert_eq!(error.code, "RESOURCE_LIMIT");
    assert_eq!(doc.authority_digest().unwrap(), original);
}
/// `T-AF-STATE-GOVERNANCE-0001-R07-001`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
fn coverage_loss_retains_baseline_entry() {
    let a = endpoint(DeclarationTruth::SupportedViolation);
    let b = endpoint(DeclarationTruth::NotEvaluable);
    let mut doc = governed(&a);
    let e = retirement(&a, &b, &doc);
    assert_eq!(e[0].outcome, RetirementOutcome::NotObserved);
    assert!(doc.prune_with_evidence(&e).is_err());
    assert_eq!(doc.baseline().unwrap().active_entries().len(), 1);
}
/// `T-AF-STATE-GOVERNANCE-0001-R07-002`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
fn disabled_rule_is_policy_retirement_not_fix() {
    let a = endpoint(DeclarationTruth::SupportedViolation);
    let mut b = endpoint(DeclarationTruth::NotApplicable);
    let app = b.view.as_mut().unwrap().application.as_mut().unwrap();
    let mut manifest = app.declaration.required_dimension_manifest.clone();
    manifest.dimensions[0].claim_refs.clear();
    app.declaration = ConformanceDeclaration::compose(
        app.declaration.binding.clone(),
        manifest,
        vec![],
        vec![],
        DeclarationResidue::default(),
    )
    .unwrap();
    app.evidence.clear();
    app.obligations.clear();
    b.assets.as_mut().unwrap().profile_refs.insert(d(17));
    refresh(&mut b);
    let doc = governed(&a);
    assert_eq!(
        retirement(&a, &b, &doc)[0].outcome,
        RetirementOutcome::PolicyRetired
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R07-003`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
fn actual_fix_under_comparable_scope_prunes() {
    let a = endpoint(DeclarationTruth::SupportedViolation);
    let b = endpoint(DeclarationTruth::NoSupportedViolation);
    let mut doc = governed(&a);
    let e = retirement(&a, &b, &doc);
    assert_eq!(e[0].outcome, RetirementOutcome::Resolved);
    assert_eq!(doc.prune_with_evidence(&e).unwrap().removed, 1);
    assert!(doc.baseline().unwrap().active_entries().is_empty());
    assert_eq!(doc.baseline().unwrap().retired_entries().len(), 1);
}
/// `T-AF-STATE-GOVERNANCE-0001-R07-004`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
fn removed_subject_records_why_it_retired() {
    let mut a = endpoint(DeclarationTruth::SupportedViolation);
    a.assets.as_mut().unwrap().entities.push(Entity {
        id: "AF-RETIRE-0001".into(),
        kind: "module".into(),
        semantic_ref: d(21),
        path: Some("src/lib.rs".into()),
        promise: None,
    });
    a.assets.as_mut().unwrap().inputs[0].scope_refs = BTreeSet::from(["AF-RETIRE-0001".into()]);
    let mut b = endpoint(DeclarationTruth::NotApplicable);
    b.assets.as_mut().unwrap().inputs.retain(|i| i.id != "code");
    let mut doc = governed(&a);
    let e = retirement(&a, &b, &doc);
    assert_eq!(e[0].outcome, RetirementOutcome::SubjectRemoved);
    assert!(!e[0].reasons.is_empty());
    assert_eq!(doc.prune_with_evidence(&e).unwrap().removed, 1);
    assert_eq!(
        doc.lifecycle()
            .unwrap()
            .retirements
            .values()
            .next()
            .unwrap()
            .evidence
            .outcome,
        RetirementOutcome::SubjectRemoved
    );
}
/// `T-AF-STATE-GOVERNANCE-0001-R07-005`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
fn legacy_entry_without_anchor_is_not_invented() {
    let a = endpoint(DeclarationTruth::SupportedViolation);
    let b = endpoint(DeclarationTruth::NoSupportedViolation);
    let mut doc = FindingGovernanceDocument::empty();
    doc.create_baseline("STD-FORTRESS-ENGINEERING", "1.0.0-draft.1", &[raw()])
        .unwrap();
    let e = retirement(&a, &b, &doc);
    assert_eq!(e[0].outcome, RetirementOutcome::NotObserved);
    assert!(doc.prune_with_evidence(&e).is_err());
}
/// `T-AF-STATE-GOVERNANCE-0001-R07-006`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
fn exception_expiry_uses_explicit_time() {
    use fortress_core::finding_governance::ExceptionReviewPolicy;
    let p = ExceptionReviewPolicy {
        review_at: Some(10),
        expires_at: Some(20),
    };
    assert_eq!(p.state_at(None), "TIME_REQUIRED");
    assert_eq!(p.state_at(Some(9)), "CURRENT");
    assert_eq!(p.state_at(Some(10)), "REVIEW_REQUIRED");
    assert_eq!(p.state_at(Some(20)), "EXPIRED");
}
/// `T-AF-STATE-GOVERNANCE-0001-R07-007`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
fn reintroduced_violation_blocks_without_new_exception() {
    let a = endpoint(DeclarationTruth::SupportedViolation);
    let b = endpoint(DeclarationTruth::NoSupportedViolation);
    let mut doc = governed(&a);
    doc.prune_with_evidence(&retirement(&a, &b, &doc)).unwrap();
    let g = fortress_core::finding_governance::evaluate_finding_governance(
        &[raw()],
        Some(&doc),
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
    )
    .unwrap();
    assert!(!g.is_success());
    assert_eq!(g.summary().reintroduced_blocking, 1);
}

/// `T-AF-STATE-GOVERNANCE-0001-R07-011`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
fn incidental_presentation_cannot_resolve_or_replace_a_governed_violation() {
    use fortress_core::finding_governance::evaluate_finding_governance_in_context;
    let before = endpoint(DeclarationTruth::SupportedViolation);
    let doc = governed(&before);
    let mut ambiguous = before.clone();
    original_subject(&mut ambiguous);
    let mut duplicate = ambiguous.assets.as_ref().unwrap().entities[0].clone();
    duplicate.path = Some("other/lib.rs".into());
    ambiguous.assets.as_mut().unwrap().entities.push(duplicate);
    assert!(finding_anchors(&ambiguous, &[raw()]).is_err());
    assert!(current_governance_anchors(&ambiguous, &doc).is_err());
    let mut after = before.clone();
    set_subject(&mut after, 11);
    after
        .assets
        .as_mut()
        .unwrap()
        .entities
        .iter_mut()
        .for_each(|e| e.path = Some("moved/lib.rs".into()));
    refresh(&mut after);
    let moved = presentation(
        "moved/lib.rs",
        "Different diagnostic wording\nwith another line",
    );
    assert_eq!(moved.finding_id(), raw().finding_id());
    assert_eq!(
        retirement(&before, &after, &doc)[0].outcome,
        RetirementOutcome::Present
    );
    let context = fortress_core::lifecycle_load::current_context(&after, &doc, None).unwrap();
    let current = evaluate_finding_governance_in_context(
        &[moved],
        Some(&doc),
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
        &context,
    )
    .unwrap();
    assert_eq!(current.summary().baselined_non_blocking, 1);
    after.assets.as_mut().unwrap().standard_ref = Some(d(88));
    let context = fortress_core::lifecycle_load::current_context(&after, &doc, None).unwrap();
    let changed = evaluate_finding_governance_in_context(
        &[raw()],
        Some(&doc),
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
        &context,
    )
    .unwrap();
    assert!(!changed.is_success());
    assert_eq!(changed.summary().baselined_non_blocking, 0);
}

fn original_subject(s: &mut ComparisonState) {
    if !s
        .assets
        .as_ref()
        .unwrap()
        .entities
        .iter()
        .any(|e| e.id == "AF-RETIRE-0001")
    {
        s.assets.as_mut().unwrap().entities.push(Entity {
            id: "AF-RETIRE-0001".into(),
            kind: "module".into(),
            semantic_ref: d(21),
            path: Some("src/lib.rs".into()),
            promise: None,
        });
    }
    s.assets.as_mut().unwrap().inputs[0].scope_refs = BTreeSet::from(["AF-RETIRE-0001".into()]);
}
fn remove_claim(s: &mut ComparisonState) {
    let app = s.view.as_mut().unwrap().application.as_mut().unwrap();
    let mut manifest = app.declaration.required_dimension_manifest.clone();
    manifest.dimensions[0].claim_refs.clear();
    app.declaration = ConformanceDeclaration::compose(
        app.declaration.binding.clone(),
        manifest,
        vec![],
        vec![],
        DeclarationResidue::default(),
    )
    .unwrap();
    app.obligations.clear();
    app.evidence.clear();
    refresh(s);
}
/// `T-AF-STATE-GOVERNANCE-0001-R07-008`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "One frozen acceptance matrix retains each adversarial premise alongside its outcome"
)]
fn frozen_retirement_outcomes_and_adversarial_missing_premises_are_honest() {
    let fixtures: Value =
        serde_json::from_str(include_str!("../_data/retirement_cases_v1.json")).unwrap();
    assert_eq!(fixtures["cases"].as_array().unwrap().len(), 8);
    for row in fixtures["cases"].as_array().unwrap() {
        let mut before = endpoint(DeclarationTruth::SupportedViolation);
        original_subject(&mut before);
        let mut after = endpoint(DeclarationTruth::NoSupportedViolation);
        let doc = governed(&before);
        match row["id"].as_str().unwrap() {
            "unchanged_violation" => after = before.clone(),
            "supported_fix" => {}
            "complete_subject_removal" => {
                after = endpoint(DeclarationTruth::NotApplicable);
                after
                    .assets
                    .as_mut()
                    .unwrap()
                    .inputs
                    .retain(|i| i.id != "code");
            }
            "coverage_loss" => after = endpoint(DeclarationTruth::NotEvaluable),
            "disabled_rule" => {
                remove_claim(&mut after);
                after.assets.as_mut().unwrap().profile_refs.insert(d(17));
            }
            "excluded_source" => {
                let excluded = BTreeSet::from(["src".to_owned()]);
                after.assets.as_mut().unwrap().exclusions_ref = Some(value_ref(&excluded));
                after.assets.as_mut().unwrap().exclusions = Some(excluded);
            }
            "analyzer_change" => after.assets.as_mut().unwrap().evaluator_ref = Some(d(72)),
            "ambiguous_subject" => {
                original_subject(&mut after);
                let mut duplicate = after.assets.as_ref().unwrap().entities[0].clone();
                duplicate.path = Some("other/source.rs".into());
                after.assets.as_mut().unwrap().entities.push(duplicate);
            }
            _ => panic!("unassigned frozen scenario"),
        }
        if !matches!(
            row["id"].as_str().unwrap(),
            "complete_subject_removal" | "ambiguous_subject"
        ) {
            original_subject(&mut after);
        }
        let evidence = retirement(&before, &after, &doc);
        assert_eq!(
            serde_json::to_value(evidence[0].outcome).unwrap(),
            row["expected"],
            "{}",
            row["id"]
        );
        if !matches!(
            evidence[0].outcome,
            RetirementOutcome::Resolved | RetirementOutcome::SubjectRemoved
        ) {
            let mut untouched = doc.clone();
            assert!(untouched.prune_with_evidence(&evidence).is_err());
            assert_eq!(untouched, doc);
        }
    }
    let before = endpoint(DeclarationTruth::SupportedViolation);
    let doc = governed(&before);
    let mut unchanged = endpoint(DeclarationTruth::NoSupportedViolation);
    set_subject(&mut unchanged, 1);
    refresh(&mut unchanged);
    assert_eq!(
        retirement(&before, &unchanged, &doc)[0].outcome,
        RetirementOutcome::NotObserved
    );
    for attack in [
        "proof_absent",
        "tampered_payload",
        "defeater",
        "incomplete_inventory",
        "incompatible_profile",
        "incompatible_standard",
        "wrong_history",
        "governing_scope_changed",
        "authored_contract_removed_with_source_change",
    ] {
        let mut after = endpoint(DeclarationTruth::NoSupportedViolation);
        let mut original = before.clone();
        match attack {
            "proof_absent" => {
                after
                    .view
                    .as_mut()
                    .unwrap()
                    .application
                    .as_mut()
                    .unwrap()
                    .evidence
                    .clear();
                after
                    .view
                    .as_mut()
                    .unwrap()
                    .application
                    .as_mut()
                    .unwrap()
                    .obligations
                    .clear();
                refresh(&mut after);
            }
            "tampered_payload" => {
                after
                    .view
                    .as_mut()
                    .unwrap()
                    .application
                    .as_mut()
                    .unwrap()
                    .evidence[0]
                    .payload_digest = d(33);
                refresh(&mut after);
            }
            "defeater" => {
                after
                    .view
                    .as_mut()
                    .unwrap()
                    .application
                    .as_mut()
                    .unwrap()
                    .declaration
                    .claims[0]
                    .defeater_refs
                    .push("unknown:external-call".into());
                refresh(&mut after);
            }
            "incomplete_inventory" => {
                after
                    .assets
                    .as_mut()
                    .unwrap()
                    .complete_axes
                    .remove(&Axis::Subject);
            }
            "incompatible_profile" => {
                after.assets.as_mut().unwrap().profile_refs.insert(d(35));
            }
            "incompatible_standard" => after.assets.as_mut().unwrap().standard_ref = Some(d(36)),
            "wrong_history" => {
                original.origin_ref = Some(d(37));
            }
            "governing_scope_changed" => {
                original_subject(&mut after);
                after.assets.as_mut().unwrap().entities[0].semantic_ref = d(93);
            }
            "authored_contract_removed_with_source_change" => {
                after.assets.as_mut().unwrap().inputs[1]
                    .roles
                    .insert(Axis::Intent, d(94));
                after.assets.as_mut().unwrap().inputs[1].content_ref = d(94);
            }
            _ => unreachable!(),
        }
        assert!(
            !matches!(
                retirement(&original, &after, &doc)[0].outcome,
                RetirementOutcome::Resolved | RetirementOutcome::SubjectRemoved
            ),
            "{attack}"
        );
    }
}

/// `T-AF-STATE-GOVERNANCE-0001-R07-012`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "Keeps atomic mutation and complete historical preservation assertions together"
)]
fn neutral_lifecycle_records_reject_tamper_and_preserve_original_history() {
    use fortress_core::finding_governance::*;
    let before = endpoint(DeclarationTruth::SupportedViolation);
    let after = endpoint(DeclarationTruth::NoSupportedViolation);
    let mut invalid = serde_json::to_value(FindingGovernanceDocument::empty_current()).unwrap();
    invalid["schema_version"] = json!(99);
    let invalid: FindingGovernanceDocument = serde_json::from_value(invalid).unwrap();
    assert!(assess_retirements(&before, &after, &invalid, &ComparisonContext::default()).is_err());
    assert!(current_governance_anchors(&before, &invalid).is_err());
    let mut doc = governed(&before);
    let original = doc.clone();
    let evidence = retirement(&before, &after, &doc);
    assert!(
        doc.create_baseline("STD-FORTRESS-ENGINEERING", "1.0.0-draft.1", &[])
            .is_err()
    );
    assert_eq!(doc, original);
    for field in ["finding_id", "original_authority_ref", "from_subject"] {
        let mut record = serde_json::to_value(&evidence[0]).unwrap();
        record[field] = json!(d(99));
        let parsed = RetirementEvidenceV2::from_json_str(&record.to_string()).unwrap();
        assert!(doc.prune_with_evidence(&[parsed]).is_err());
        assert_eq!(doc, original);
    }
    for field in ["from_state", "governance_ref", "anchor_ref"] {
        let mut record = evidence[0].clone();
        let mut basis = serde_json::to_value(&record.comparison_basis).unwrap();
        basis[field] = json!(d(99));
        record.comparison_basis = serde_json::from_value(basis).unwrap();
        assert!(doc.prune_with_evidence(&[record]).is_err());
        assert_eq!(doc, original);
    }
    let mut missing = evidence[0].clone();
    missing.proof_refs.clear();
    assert!(missing.validate().is_err());
    let mut unsupported = evidence[0].clone();
    unsupported.schema_version = 99;
    assert!(unsupported.validate().is_err());
    let wire = serde_json::to_string(&evidence[0]).unwrap();
    let duplicate = wire.replacen('{', "{\"schema_version\":2,", 1);
    assert!(RetirementEvidenceV2::from_json_str(&duplicate).is_err());
    doc.prune_with_evidence(&evidence).unwrap();
    let retired = doc
        .lifecycle()
        .unwrap()
        .retirements
        .values()
        .next()
        .unwrap();
    assert_eq!(
        &retired.anchor,
        &original.lifecycle().unwrap().anchors[raw().finding_id()]
    );
    assert_eq!(retired.evidence, evidence[0]);
    assert_eq!(
        FindingGovernanceDocument::from_json_str(&doc.to_canonical_json().unwrap()).unwrap(),
        doc
    );
    let bytes = doc.to_canonical_json().unwrap();
    assert!(doc.prune_with_evidence(&evidence).is_err());
    assert_eq!(doc.to_canonical_json().unwrap(), bytes);
    let mut exceptions = FindingGovernanceDocument::empty_current();
    let anchor = finding_anchors(&before, &[raw()])
        .unwrap()
        .remove(raw().finding_id())
        .unwrap();
    exceptions
        .create_reviewed_exception(
            "EX-RETIRE-0001",
            raw().finding_id(),
            "https://example.invalid/approved:true",
            "Finding-specific reviewed proposal",
            &[raw()],
            anchor.clone(),
            ExceptionReviewPolicy {
                review_at: Some(10),
                expires_at: Some(20),
            },
        )
        .unwrap();
    for time in [None, Some(9), Some(10), Some(20)] {
        let context =
            fortress_core::lifecycle_load::current_context(&before, &exceptions, time).unwrap();
        let review = exceptions.review_exceptions(&context).unwrap();
        assert!(!review[0].applicable);
        assert_eq!(review[0].authorization_state, "UNVERIFIED_REFERENCE");
        let evaluated = evaluate_finding_governance_in_context(
            &[raw()],
            Some(&exceptions),
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            &context,
        )
        .unwrap();
        assert!(!evaluated.is_success());
        assert_eq!(
            serde_json::to_value(&evaluated).unwrap()["findings"][0]["raw_conformance"],
            "FAIL"
        );
    }
    exceptions
        .create_anchored_baseline(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            &[raw()],
            finding_anchors(&before, &[raw()]).unwrap(),
        )
        .unwrap();
    assert_eq!(exceptions.lifecycle().unwrap().exception_reviews.len(), 1);
    exceptions
        .retire_reviewed_exception(
            "EX-RETIRE-0001",
            "Explicit authority withdrawal, not semantic resolution",
        )
        .unwrap();
    assert_eq!(
        exceptions.lifecycle().unwrap().exception_reviews["EX-RETIRE-0001"]
            .anchor
            .as_ref(),
        Some(&anchor)
    );
    assert!(
        exceptions
            .retire_reviewed_exception("EX-RETIRE-0001", "again")
            .is_err()
    );
    let mut legacy = FindingGovernanceDocument::empty();
    legacy
        .create_exception(
            "EX-LEGACY-0001",
            raw().finding_id(),
            "old-owner",
            "Original rationale",
            &[raw()],
        )
        .unwrap();
    legacy
        .retire_reviewed_exception(
            "EX-LEGACY-0001",
            "Retire without inventing original anchors",
        )
        .unwrap();
    assert!(
        legacy.lifecycle().unwrap().exception_reviews["EX-LEGACY-0001"]
            .anchor
            .is_none()
    );
}

fn snapshot_with_governance(
    mut state: ComparisonState,
    authority: &FindingGovernanceDocument,
) -> fortress_core::authority_load::AuthoritySnapshot {
    use fortress_core::authority_load::AuthoritySnapshot;
    let files = BTreeMap::from([
        (
            "src/lib.rs".into(),
            b"pub fn original_subject() {}".to_vec(),
        ),
        ("contract.json".into(), b"{}".to_vec()),
        (
            "__fortress/governance/finding_governance.json".into(),
            authority.to_canonical_json().unwrap().into_bytes(),
        ),
    ]);
    let subject = fortress_core::certification::certification_source_digest(&files);
    state.source_ref = Some(subject.clone());
    state
        .assets
        .as_mut()
        .unwrap()
        .subject_ref
        .clone_from(&subject);
    let assets = state.assets.as_mut().unwrap();
    assets.inputs.clear();
    for (path, bytes) in &files {
        let r = format!("sha256:{:x}", Sha256::digest(bytes));
        let axis = if path == "src/lib.rs" {
            Axis::Subject
        } else if path == "contract.json" {
            Axis::Intent
        } else {
            Axis::Governance
        };
        assets.inputs.push(AxisInput {
            id: path.clone(),
            path: path.clone(),
            content_ref: r.clone(),
            scope_refs: BTreeSet::new(),
            roles: BTreeMap::from([(axis, r)]),
        });
    }
    let view = state.view.as_mut().unwrap();
    view.source_ref = subject.clone();
    let app = view.application.as_mut().unwrap();
    app.declaration.binding.subject_ref = subject;
    app.declaration.binding.authority_ref =
        value_ref(&("fixture-authority", authority.authority_digest().unwrap()));
    app.declaration.residue_summary.accepted_baseline =
        authority.baseline().map_or_else(Vec::new, |b| {
            b.active_entries()
                .iter()
                .map(|e| e.finding_id().to_owned())
                .collect()
        });
    for leaf in &mut app.evidence {
        leaf.binding = app.declaration.binding.clone();
        let claim = app
            .declaration
            .claims
            .iter()
            .find(|c| c.scope_ref == leaf.scope_ref)
            .unwrap();
        leaf.payload_digest = value_ref(&(
            "static-claim-premise-v1",
            &leaf.binding,
            value_ref(claim),
            &leaf.source_ref,
        ));
    }
    refresh(&mut state);
    let result = AuthoritySnapshot {
        schema: "urn:fortress:derived:v1:authority-snapshot".into(),
        schema_version: 1,
        state,
        files,
    };
    result.to_canonical_bytes().unwrap();
    result
}
/// `T-AF-STATE-GOVERNANCE-0001-R07-009`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "End-to-end grant fixtures retain exact requests, candidates and independent raw results"
)]
fn protected_exception_uses_exact_opaque_grants_and_keeps_raw_failure() {
    use fortress_core::development_governance::*;
    use fortress_core::finding_governance::*;
    use fortress_core::lifecycle_load::*;
    struct FixtureExternalPort {
        wrong_scope: bool,
    }
    impl GrantValidator for FixtureExternalPort {
        fn validate(&self, r: &GrantRequest) -> GrantValidation {
            let mut a =
                HostAssertion::for_request(r, "fixture-independent-owner", d(89), None, None);
            if self.wrong_scope {
                a.scope = "another-project".into();
            }
            GrantValidation::Authenticated(Box::new(a))
        }
    }
    let original = snapshot_with_governance(
        endpoint(DeclarationTruth::SupportedViolation),
        &FindingGovernanceDocument::empty(),
    );
    let mut authority = FindingGovernanceDocument::empty();
    authority
        .create_anchored_baseline(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            &[raw()],
            finding_anchors(&original.state, &[raw()]).unwrap(),
        )
        .unwrap();
    let base = snapshot_with_governance(endpoint(DeclarationTruth::SupportedViolation), &authority);
    let proposal = propose_exception(
        &authority,
        &base.state,
        &[raw()],
        "EX-OPAQUE-0001",
        raw().finding_id(),
        "owner:exact-scoped-reference",
        "Fixture scoped exception, not a raw PASS",
        ExceptionReviewPolicy {
            review_at: Some(10),
            expires_at: Some(20),
        },
    )
    .unwrap();
    let candidate = snapshot_with_governance(
        endpoint(DeclarationTruth::SupportedViolation),
        proposal.proposed_governance(),
    );
    let context = ComparisonContext {
        authorization_refs: BTreeSet::new(),
        counterfactuals: vec![Counterfactual {
            subject_ref: base.state.subject_identity().unwrap().unwrap(),
            authority_ref: base.state.governing_identity().unwrap().unwrap(),
            view: base.state.view.clone().unwrap(),
            assets: base.state.assets.clone(),
        }],
    };
    let prepared =
        fortress_core::authority_load::prepare_authority_change(&base, &candidate, &context)
            .unwrap();
    let policy = TrustedBasePolicy::from_host(
        prepared.base_state_ref(),
        prepared.base_authority_ref().unwrap(),
        d(87),
        false,
        vec![AuthorizationRule {
            id: "fixture-owner-governance".into(),
            classes: BTreeSet::from([ProtectedClass::FindingGovernance]),
            actions: BTreeSet::from([Action::Create, Action::Replace, Action::Delete]),
            scope: "project".into(),
            issuer_policy_ref: d(88),
        }],
    )
    .unwrap();
    let missing = evaluate_change_with_grants(
        &prepared,
        &policy,
        &UnmediatedHost,
        &NoGrantValidator,
        Some(9),
    )
    .unwrap();
    assert_eq!(
        missing.decision().disposition,
        Disposition::RequireAuthorization
    );
    assert!(authorize_governance_update(&proposal, &base, &candidate, &context, &missing).is_err());
    for time in [9, 20] {
        let evaluation = evaluate_change_with_grants(
            &prepared,
            &policy,
            &UnmediatedHost,
            &FixtureExternalPort { wrong_scope: false },
            Some(time),
        )
        .unwrap();
        assert_eq!(evaluation.decision().disposition, Disposition::Permit);
        assert!(!evaluation.decision().enforced);
        let admitted =
            authorize_governance_update(&proposal, &base, &candidate, &context, &evaluation)
                .unwrap();
        assert_eq!(
            admitted.bytes(),
            candidate.files["__fortress/governance/finding_governance.json"]
        );
        let current =
            authorized_exception_context(&proposal, &base, &candidate, &context, &evaluation)
                .unwrap();
        let report = evaluate_finding_governance_in_context(
            &[raw()],
            Some(proposal.proposed_governance()),
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            &current,
        )
        .unwrap();
        let review = &report.exception_reviews()[0];
        assert_eq!(review.authorization_state, "VERIFIED_EXTERNAL");
        assert!(review.authorization_evidence_ref.is_some());
        assert_eq!(review.applicable, time == 9);
        assert_eq!(
            report.summary().excepted_non_blocking,
            usize::from(time == 9)
        );
        assert_eq!(
            serde_json::to_value(&report).unwrap()["findings"][0]["raw_conformance"],
            "FAIL"
        );
        assert_ne!(
            candidate
                .state
                .view
                .as_ref()
                .unwrap()
                .application
                .as_ref()
                .unwrap()
                .assessment
                .decision,
            AssessmentDecision::Satisfied
        );
    }
    let invalid = evaluate_change_with_grants(
        &prepared,
        &policy,
        &UnmediatedHost,
        &FixtureExternalPort { wrong_scope: true },
        Some(9),
    )
    .unwrap();
    assert!(authorize_governance_update(&proposal, &base, &candidate, &context, &invalid).is_err());
    let evaluation = evaluate_change_with_grants(
        &prepared,
        &policy,
        &UnmediatedHost,
        &FixtureExternalPort { wrong_scope: false },
        Some(9),
    )
    .unwrap();
    assert!(
        authorize_governance_update(
            &proposal,
            &base,
            &candidate,
            &ComparisonContext::default(),
            &evaluation
        )
        .is_err()
    );
    let different = propose_exception(
        &authority,
        &base.state,
        &[raw()],
        "EX-OPAQUE-0002",
        raw().finding_id(),
        "owner:other",
        "Different postimage",
        ExceptionReviewPolicy {
            review_at: None,
            expires_at: None,
        },
    )
    .unwrap();
    assert!(
        authorize_governance_update(&different, &base, &candidate, &context, &evaluation).is_err()
    );
}

/// `T-AF-STATE-GOVERNANCE-0001-R07-010`
/// Fortress requirement: AF-STATE-GOVERNANCE-0001-R07
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "Public schemas, serialized records and every page are checked in one acceptance scenario"
)]
fn lifecycle_public_schemas_and_warm_paging_preserve_the_same_records() {
    use fortress_core::finding_governance::*;
    use fortress_core::query::{QueryInput, QueryRequest, QueryService};
    let before = endpoint(DeclarationTruth::SupportedViolation);
    let after = endpoint(DeclarationTruth::NoSupportedViolation);
    let doc = governed(&before);
    let record = retirement(&before, &after, &doc).remove(0);
    let reference = record.digest().unwrap();
    let mut exception = FindingGovernanceDocument::empty_current();
    exception
        .create_reviewed_exception(
            "EX-SCHEMA-0001",
            raw().finding_id(),
            "owner:unverified",
            "Scoped Unicode λ rationale",
            &[raw()],
            finding_anchors(&before, &[raw()])
                .unwrap()
                .remove(raw().finding_id())
                .unwrap(),
            ExceptionReviewPolicy {
                review_at: Some(10),
                expires_at: Some(20),
            },
        )
        .unwrap();
    let context =
        fortress_core::lifecycle_load::current_context(&before, &exception, Some(9)).unwrap();
    let review = exception.review_exceptions(&context).unwrap().remove(0);
    let proposal = fortress_core::lifecycle_load::propose_baseline(
        &FindingGovernanceDocument::empty_current(),
        &before,
        &[raw()],
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
    )
    .unwrap();
    // Migration consumes the original pre-maintenance proof, avoiding a digest self-reference.
    let prune =
        fortress_core::lifecycle_load::propose_prune(&doc, &before, &after, &BTreeSet::new())
            .unwrap();
    let governance_path = "__fortress/governance/finding_governance.json";
    let source = fortress_core::observation::SourceView::from_bytes([(
        governance_path,
        doc.to_canonical_json().unwrap().into_bytes(),
    )])
    .unwrap();
    let target = fortress_core::observation::SourceView::from_bytes([(
        governance_path,
        prune
            .proposed_governance()
            .to_canonical_json()
            .unwrap()
            .into_bytes(),
    )])
    .unwrap();
    let admitted = fortress_core::lifecycle_load::migration_proposal_evidence(
        &prune, &after, &source, &target,
    )
    .unwrap();
    assert!(admitted.contains(&reference));
    assert!(
        fortress_core::lifecycle_load::migration_proposal_evidence(
            &prune, &before, &source, &target
        )
        .is_err()
    );
    let report = fortress_core::lifecycle_load::assess_finding_lifecycle(
        &doc,
        &before,
        &after,
        &[],
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
        Some(9),
    )
    .unwrap();
    assert!(
        fortress_core::lifecycle_load::assess_finding_lifecycle(
            &doc,
            &before,
            &after,
            &[raw()],
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            Some(9)
        )
        .is_err()
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(root.join("engine/standard_registry/_data/schema_manifest.json")).unwrap(),
    )
    .unwrap();
    let mut schemas = BTreeMap::new();
    for path in manifest["schemas"].as_array().unwrap() {
        let s: Value =
            serde_json::from_slice(&std::fs::read(root.join(path.as_str().unwrap())).unwrap())
                .unwrap();
        schemas.insert(s["$id"].as_str().unwrap().to_owned(), s);
    }
    for (id, value) in [
        (
            "urn:fortress:schema:v2:finding-governance",
            serde_json::to_value(&doc).unwrap(),
        ),
        (
            "urn:fortress:schema:v2:finding-governance",
            serde_json::to_value(&exception).unwrap(),
        ),
        (
            "urn:fortress:derived:v2:retirement-evidence",
            serde_json::to_value(&record).unwrap(),
        ),
        (
            "urn:fortress:derived:v1:exception-review",
            serde_json::to_value(&review).unwrap(),
        ),
        (
            "urn:fortress:derived:v1:governance-proposal",
            serde_json::to_value(&proposal).unwrap(),
        ),
        (
            "urn:fortress:derived:v1:finding-lifecycle",
            serde_json::to_value(&report).unwrap(),
        ),
    ] {
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
            "{id}: {:?}",
            validator.iter_errors(&value).collect::<Vec<_>>()
        );
    }
    assert_eq!(
        lifecycle_bytes(&record).unwrap(),
        fortress_core::wire::canonicalize_public_json(&serde_json::to_string(&record).unwrap())
            .unwrap()
    );
    let service = QueryService::new(QueryInput::empty(d(1)))
        .unwrap()
        .with_finding_authority(&doc)
        .unwrap()
        .with_retirement_evidence(vec![record.clone()])
        .unwrap();
    let original_before = before.digest().unwrap();
    let original_after = after.digest().unwrap();
    let mut cursor = None;
    let mut ids = BTreeSet::new();
    let mut pages = 0;
    loop {
        let response = service.execute(
            &QueryRequest {
                protocol_version: 1,
                request_id: "lifecycle-page".into(),
                state_ref: None,
                context_ref: None,
                method: "explain".into(),
                parameters: json!({"selector":reference,"page":{"limit":1,"cursor":cursor}}),
            },
            &std::sync::atomic::AtomicBool::new(false),
        );
        assert!(response.error.is_none(), "{:?}", response.error);
        let payload = serde_json::to_value(response.result.unwrap()).unwrap();
        assert_eq!(payload["kind"], "EXPLANATION");
        let result = &payload["data"];
        assert_eq!(
            result["description"]["recorded_result"]["record"]["outcome"],
            "RESOLVED"
        );
        for r in result["evidence"]["records"].as_array().unwrap() {
            assert!(ids.insert(r["id"].as_str().unwrap().to_owned()));
        }
        pages += 1;
        cursor = result["evidence"]["next_cursor"]
            .as_str()
            .map(str::to_owned);
        if cursor.is_none() {
            break;
        }
        assert!(pages < 8);
    }
    assert_eq!(pages, 2);
    assert_eq!(ids.len(), 2);
    assert_eq!(before.digest().unwrap(), original_before);
    assert_eq!(after.digest().unwrap(), original_after);
    let request = QueryRequest {
        protocol_version: 2,
        request_id: "lifecycle-cancel".into(),
        state_ref: None,
        context_ref: None,
        method: "explain".into(),
        parameters: json!({"selector":reference}),
    };
    assert_eq!(
        service
            .execute(&request, &std::sync::atomic::AtomicBool::new(true))
            .error
            .unwrap()
            .code,
        "CANCELLED"
    );
    let mut unsupported = request.clone();
    unsupported.protocol_version = 99;
    assert_eq!(
        service
            .execute(&unsupported, &std::sync::atomic::AtomicBool::new(false))
            .error
            .unwrap()
            .code,
        "UNSUPPORTED_VERSION"
    );
    let other = retirement(&before, &endpoint(DeclarationTruth::NotEvaluable), &doc).remove(0);
    let ambiguous = QueryService::new(QueryInput::empty(d(1)))
        .unwrap()
        .with_retirement_evidence(vec![record.clone(), other.clone()])
        .unwrap();
    let mut request = request;
    request.parameters = json!({"selector":raw().finding_id()});
    assert_eq!(
        ambiguous
            .execute(&request, &std::sync::atomic::AtomicBool::new(false))
            .error
            .unwrap()
            .code,
        "AMBIGUOUS_SELECTOR"
    );
    assert!(
        QueryService::new(QueryInput::empty(d(1)))
            .unwrap()
            .with_retirement_evidence(vec![record.clone(), record])
            .is_err()
    );
    let mut malformed = serde_json::to_value(&other).unwrap();
    malformed["approved"] = json!(true);
    assert!(RetirementEvidenceV2::from_json_str(&malformed.to_string()).is_err());
    assert!(RetirementEvidenceV2::from_json_str(&" ".repeat(MAX_GOVERNANCE_BYTES + 1)).is_err());
}
