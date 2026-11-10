//! Neutral lifecycle controls; synthetic records do not claim semantic proof or authorization.
use fortress_core::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingLocation, FindingOccurrence,
    RuleFindingDefinition,
};
use fortress_core::finding_governance::{
    ExceptionReviewPolicy, FindingAnchor, FindingGovernanceDocument, LifecycleContext,
    RetirementComparisonBasis, RetirementEvidenceV2, RetirementOutcome,
    evaluate_finding_governance_in_context, finding_semantic_ref, lifecycle_digest,
};
use fortress_core::standard::FindingCategory;
use std::collections::BTreeMap;
fn d(n: u8) -> String {
    format!("sha256:{n:064x}")
}
fn raw() -> CanonicalFinding {
    CanonicalFinding::failure(
        RuleFindingDefinition::new(
            "STD-ID-001",
            1,
            FindingCategory::Architecture,
            "Restore obligation.",
        )
        .unwrap(),
        FindingOccurrence::new(
            vec!["AF-FIXTURE-0001".into()],
            FindingLocation::none(),
            "Violation",
        )
        .unwrap()
        .with_discriminator("EXACT_TARGET")
        .unwrap(),
        EvaluatorProvenance::new("neutral-fixture", "1").unwrap(),
        "fixture",
    )
    .unwrap()
}
fn anchor(f: &CanonicalFinding) -> FindingAnchor {
    FindingAnchor {
        finding_id: f.finding_id().into(),
        rule_id: f.rule_id().into(),
        from_state: d(1),
        subject_ref: d(2),
        original_authority_ref: d(3),
        meaning_ref: d(4),
        claim_scope_ref: "rule:STD-ID-001".into(),
        identity_ref: finding_semantic_ref(f).unwrap(),
        subject_refs: f.entities().to_vec(),
    }
}
fn record(doc: &FindingGovernanceDocument, a: &FindingAnchor) -> RetirementEvidenceV2 {
    RetirementEvidenceV2 { schema:"urn:fortress:derived:v2:retirement-evidence".into(),schema_version:2,finding_id:a.finding_id.clone(),original_authority_ref:Some(a.original_authority_ref.clone()),from_subject:Some(a.subject_ref.clone()),to_subject:Some(d(5)),claim_scope_ref:Some(a.claim_scope_ref.clone()),comparison_basis:RetirementComparisonBasis{from_state:a.from_state.clone(),to_state:d(6),transition_ref:d(7),governance_ref:doc.authority_digest().unwrap(),anchor_ref:Some(lifecycle_digest(a).unwrap())},outcome:RetirementOutcome::Resolved,proof_refs:vec![d(8)],reasons:vec!["Synthetic owner-supplied neutral record; no semantic evaluation performed.".into()],limitations:vec!["A caller must rederive proof from authoritative states and independently authorize application.".into()] }
}
/// `T-AF-FINDING-MODEL-0001-R02-001`
/// Fortress requirement: AF-FINDING-MODEL-0001-R02
#[test]
fn neutral_lifecycle_is_monotonic_bound_and_preserves_unverified_exception_history() {
    let f = raw();
    let a = anchor(&f);
    let anchors = BTreeMap::from([(f.finding_id().into(), a.clone())]);
    let mut doc = FindingGovernanceDocument::empty_current();
    doc.create_anchored_baseline(
        "STD-FORTRESS-ENGINEERING",
        "fixture",
        std::slice::from_ref(&f),
        anchors.clone(),
    )
    .unwrap();
    let original = doc.clone();
    assert!(
        doc.create_anchored_baseline("STD-FORTRESS-ENGINEERING", "fixture", &[], BTreeMap::new())
            .is_err()
    );
    assert_eq!(doc, original);
    let evidence = record(&doc, &a);
    for attack in ["missing_proof", "wrong_version", "wrong_anchor"] {
        let mut invalid = evidence.clone();
        match attack {
            "missing_proof" => invalid.proof_refs.clear(),
            "wrong_version" => invalid.schema_version = 99,
            "wrong_anchor" => invalid.comparison_basis.anchor_ref = Some(d(99)),
            _ => unreachable!(),
        }
        assert!(doc.prune_with_evidence(&[invalid]).is_err());
        assert_eq!(doc, original);
    }
    let mut invalid = evidence.clone();
    invalid.comparison_basis.governance_ref = d(99);
    assert!(doc.prune_with_evidence(&[invalid]).is_err());
    doc.prune_with_evidence(std::slice::from_ref(&evidence))
        .unwrap();
    assert!(doc.baseline().unwrap().active_entries().is_empty());
    let history = &doc.lifecycle().unwrap().retirements[f.finding_id()];
    assert_eq!(history.anchor, a);
    assert_eq!(history.evidence, evidence);
    assert_eq!(
        &history.original_entry,
        &original.baseline().unwrap().active_entries()[0]
    );
    let reintroduced = evaluate_finding_governance_in_context(
        std::slice::from_ref(&f),
        Some(&doc),
        "STD-FORTRESS-ENGINEERING",
        "fixture",
        &LifecycleContext::observed(doc.authority_digest().unwrap(), anchors.clone(), Some(9))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reintroduced.summary().reintroduced_blocking, 1);
    review_exception_history(&f, &a, &anchors);
}
fn review_exception_history(
    f: &CanonicalFinding,
    a: &FindingAnchor,
    anchors: &BTreeMap<String, FindingAnchor>,
) {
    let mut exception = FindingGovernanceDocument::empty_current();
    let mut wrong = a.clone();
    wrong.subject_refs = vec!["AF-OTHER-0001".into()];
    assert!(
        exception
            .create_reviewed_exception(
                "EX-FORGED-0001",
                f.finding_id(),
                "owner:reference",
                "Wrong target",
                std::slice::from_ref(f),
                wrong,
                ExceptionReviewPolicy {
                    review_at: None,
                    expires_at: None
                }
            )
            .is_err()
    );
    exception
        .create_reviewed_exception(
            "EX-FIXTURE-0001",
            f.finding_id(),
            "https://example.invalid/unverified",
            "Scoped proposal",
            std::slice::from_ref(f),
            a.clone(),
            ExceptionReviewPolicy {
                review_at: Some(10),
                expires_at: Some(20),
            },
        )
        .unwrap();
    for (time, state) in [
        (None, "TIME_REQUIRED"),
        (Some(9), "CURRENT"),
        (Some(10), "REVIEW_REQUIRED"),
        (Some(20), "EXPIRED"),
    ] {
        let context = LifecycleContext::observed(
            exception.authority_digest().unwrap(),
            anchors.clone(),
            time,
        )
        .unwrap();
        let result = evaluate_finding_governance_in_context(
            std::slice::from_ref(f),
            Some(&exception),
            "STD-FORTRESS-ENGINEERING",
            "fixture",
            &context,
        )
        .unwrap();
        assert!(!result.is_success());
        assert_eq!(result.exception_reviews()[0].review_state, state);
        assert_eq!(
            result.exception_reviews()[0].authorization_state,
            "UNVERIFIED_REFERENCE"
        );
        assert!(!result.exception_reviews()[0].applicable);
    }
    exception
        .retire_reviewed_exception("EX-FIXTURE-0001", "Explicit review ended the exception")
        .unwrap();
    assert_eq!(
        exception.lifecycle().unwrap().exception_reviews["EX-FIXTURE-0001"].anchor,
        Some(a.clone())
    );
    let canonical = exception.to_canonical_json().unwrap();
    assert_eq!(
        FindingGovernanceDocument::from_json_str(&canonical).unwrap(),
        exception
    );
    assert!(
        FindingGovernanceDocument::from_json_str(&canonical.replacen(
            '{',
            "{\"schema_version\":2,",
            1
        ))
        .is_err()
    );
}
