//! Finding identity, baseline ratchet, and explicit exception conformance.

use fortress_core::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingIdentityEligibility, FindingLocation,
    FindingOccurrence, RuleFindingDefinition, SourceSpan,
};
use fortress_core::finding_governance::{
    ExceptionState, FindingDisposition, FindingEnforcement, FindingGovernanceDocument,
    FindingLifecycle, evaluate_finding_governance,
};
use fortress_core::standard::FindingCategory;

fn finding(
    rule: &str,
    subject: &str,
    path: &str,
    discriminator: &str,
    message: &str,
    line: u32,
) -> CanonicalFinding {
    CanonicalFinding::failure(
        RuleFindingDefinition::new(
            rule,
            1,
            FindingCategory::Architecture,
            "Repair the violation.",
        )
        .unwrap(),
        FindingOccurrence::new(
            vec![subject.into()],
            FindingLocation::at_path(path)
                .unwrap()
                .with_span(SourceSpan::new(line, 1, line, 2).unwrap()),
            message,
        )
        .unwrap()
        .with_discriminator(discriminator)
        .unwrap(),
        EvaluatorProvenance::new("test-evaluator", "1").unwrap(),
        "1.0.0-draft.1",
    )
    .unwrap()
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R15-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R15
#[test]
fn stable_finding_identity_excludes_presentation_and_position() {
    let first = finding(
        "ARCH-DEPENDENCY-001",
        "AF-CORE-0001",
        "mods/a/code/a.rs",
        "UNDECLARED:CAP-X",
        "old wording",
        2,
    );
    let drifted = finding(
        "ARCH-DEPENDENCY-001",
        "AF-CORE-0001",
        "mods/a/code/a.rs",
        "UNDECLARED:CAP-X",
        "new wording",
        200,
    );
    assert_eq!(first.finding_id(), drifted.finding_id());

    let relocated = finding(
        "ARCH-DEPENDENCY-001",
        "AF-CORE-0001",
        "mods/moved/code/a.rs",
        "UNDECLARED:CAP-X",
        "new wording",
        1,
    );
    assert_eq!(first.finding_id(), relocated.finding_id());
    assert_ne!(
        first.finding_id(),
        finding(
            "ARCH-DEPENDENCY-001",
            "AF-OTHER-0001",
            "mods/a/code/a.rs",
            "UNDECLARED:CAP-X",
            "old wording",
            2
        )
        .finding_id()
    );
    assert_ne!(
        first.finding_id(),
        finding(
            "ARCH-REALIZATION-001",
            "AF-CORE-0001",
            "mods/a/code/a.rs",
            "UNDECLARED:CAP-X",
            "old wording",
            2
        )
        .finding_id()
    );
    assert_ne!(
        first.finding_id(),
        finding(
            "ARCH-DEPENDENCY-001",
            "AF-CORE-0001",
            "mods/a/code/a.rs",
            "UNDECLARED:CAP-Y",
            "old wording",
            2
        )
        .finding_id()
    );

    let ineligible = CanonicalFinding::failure(
        RuleFindingDefinition::new(
            "ARCH-DEPENDENCY-001",
            1,
            FindingCategory::Architecture,
            "Repair.",
        )
        .unwrap(),
        FindingOccurrence::new(Vec::new(), FindingLocation::none(), "No stable subject.").unwrap(),
        EvaluatorProvenance::new("test", "1").unwrap(),
        "1.0.0-draft.1",
    )
    .unwrap();
    assert_eq!(
        ineligible.identity_eligibility(),
        FindingIdentityEligibility::BaselineIneligible
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R15-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R15
#[test]
fn baseline_is_explicit_monotonic_and_detects_reintroduction() {
    let legacy = finding(
        "ARCH-DEPENDENCY-001",
        "AF-CORE-0001",
        "mods/a/code/a.rs",
        "LEGACY",
        "legacy",
        1,
    );
    let new = finding(
        "ARCH-REALIZATION-001",
        "AF-OTHER-0001",
        "mods/b/code/b.rs",
        "NEW",
        "new",
        1,
    );
    let mut authority = FindingGovernanceDocument::empty();
    let created = authority
        .create_baseline(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            std::slice::from_ref(&legacy),
        )
        .unwrap();
    assert_eq!(created.active, 1);
    assert!(
        authority
            .create_baseline("STD-FORTRESS-ENGINEERING", "1.0.0-draft.1", &[])
            .is_err()
    );

    let current = evaluate_finding_governance(
        &[legacy.clone(), new.clone()],
        Some(&authority),
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
    )
    .unwrap();
    assert_eq!(current.summary().baselined_non_blocking, 1);
    assert_eq!(current.summary().new_blocking, 1);
    assert!(!current.is_success());

    let pruned = authority
        .prune_baseline(std::slice::from_ref(&new))
        .unwrap();
    assert_eq!(pruned.removed, 1);
    assert!(authority.baseline().unwrap().active_entries().is_empty());
    let reintroduced = evaluate_finding_governance(
        std::slice::from_ref(&legacy),
        Some(&authority),
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
    )
    .unwrap();
    assert_eq!(
        reintroduced.findings()[0].lifecycle(),
        FindingLifecycle::Reintroduced
    );
    assert_eq!(
        reintroduced.findings()[0].enforcement(),
        FindingEnforcement::Blocking
    );
    assert_eq!(
        authority.to_canonical_json().unwrap(),
        authority.to_canonical_json().unwrap()
    );
    assert!(
        FindingGovernanceDocument::from_json_str(
            r#"{"$schema":"wrong","schema_version":1,"baseline":null,"exceptions":[]}"#
        )
        .is_err()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R15-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R15
#[test]
fn exception_changes_enforcement_not_raw_violation() {
    let violation = finding(
        "ARCH-DEPENDENCY-001",
        "AF-CORE-0001",
        "mods/a/code/a.rs",
        "EXCEPT",
        "violation",
        1,
    );
    let mut authority = FindingGovernanceDocument::empty();
    assert!(
        authority
            .create_exception(
                "EX-FINDING-0001",
                violation.finding_id(),
                "",
                "reason",
                std::slice::from_ref(&violation)
            )
            .is_err()
    );
    assert!(
        authority
            .create_exception(
                "EX-FINDING-0001",
                violation.finding_id(),
                "owner:decision",
                "",
                std::slice::from_ref(&violation)
            )
            .is_err()
    );
    authority
        .create_exception(
            "EX-FINDING-0001",
            violation.finding_id(),
            "owner:decision",
            "Temporary reviewed tolerance.",
            std::slice::from_ref(&violation),
        )
        .unwrap();
    let excepted = evaluate_finding_governance(
        std::slice::from_ref(&violation),
        Some(&authority),
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
    )
    .unwrap();
    assert_eq!(
        excepted.findings()[0].disposition(),
        FindingDisposition::Excepted
    );
    assert_eq!(
        excepted.findings()[0].enforcement(),
        FindingEnforcement::NonBlocking
    );
    assert_eq!(excepted.summary().excepted_non_blocking, 1);
    let unresolved = evaluate_finding_governance(
        &[],
        Some(&authority),
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
    )
    .unwrap();
    assert_eq!(
        unresolved.unresolved_active_exceptions(),
        &["EX-FINDING-0001"]
    );
    authority.retire_exception("EX-FINDING-0001").unwrap();
    assert_eq!(authority.exceptions()[0].state(), ExceptionState::Retired);
    let retired = evaluate_finding_governance(
        std::slice::from_ref(&violation),
        Some(&authority),
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
    )
    .unwrap();
    assert_eq!(
        retired.findings()[0].enforcement(),
        FindingEnforcement::Blocking
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R15-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R15
#[test]
fn combined_lifecycle_keeps_truths_orthogonal() {
    let baseline = finding(
        "ARCH-DEPENDENCY-001",
        "AF-ONE-0001",
        "mods/one/code/a.rs",
        "BASE",
        "baseline",
        1,
    );
    let excepted = finding(
        "ARCH-REALIZATION-001",
        "AF-TWO-0001",
        "mods/two/code/a.rs",
        "EXC",
        "excepted",
        1,
    );
    let new = finding(
        "REPO-MODULE-001",
        "AF-THREE-0001",
        "mods/three/code/a.rs",
        "NEW",
        "new",
        1,
    );
    let resolved = finding(
        "REPO-DOCS-001",
        "AF-FOUR-0001",
        "mods/four/README.md",
        "OLD",
        "resolved",
        1,
    );
    let mut authority = FindingGovernanceDocument::empty();
    authority
        .create_baseline(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            &[baseline.clone(), resolved],
        )
        .unwrap();
    authority
        .create_exception(
            "EX-REVIEWED-0001",
            excepted.finding_id(),
            "owner:review",
            "Reviewed exception.",
            std::slice::from_ref(&excepted),
        )
        .unwrap();
    let result = evaluate_finding_governance(
        &[baseline, excepted, new],
        Some(&authority),
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
    )
    .unwrap();
    assert_eq!(result.summary().baselined_non_blocking, 1);
    assert_eq!(result.summary().excepted_non_blocking, 1);
    assert_eq!(result.summary().new_blocking, 1);
    assert_eq!(result.summary().resolved_baseline_entries, 1);
    assert!(!result.is_success());
    assert!(
        evaluate_finding_governance(
            &[],
            Some(&authority),
            "STD-FORTRESS-ENGINEERING",
            "different-edition"
        )
        .is_err()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R15-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R15
#[test]
fn large_finding_set_uses_deterministic_keyed_matching() {
    let findings = (0..10_000)
        .map(|index| {
            finding(
                "ARCH-DEPENDENCY-001",
                &format!("AF-VOLUME-{index:05}"),
                &format!("mods/volume/code/{index:05}.rs"),
                "VOLUME",
                "volume finding",
                1,
            )
        })
        .collect::<Vec<_>>();
    let mut authority = FindingGovernanceDocument::empty();
    authority
        .create_baseline(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            &findings[..5_000],
        )
        .unwrap();
    let first = evaluate_finding_governance(
        &findings,
        Some(&authority),
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
    )
    .unwrap();
    let second = evaluate_finding_governance(
        &findings,
        Some(&authority),
        "STD-FORTRESS-ENGINEERING",
        "1.0.0-draft.1",
    )
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.summary().baselined_non_blocking, 5_000);
    assert_eq!(first.summary().new_blocking, 5_000);
}
