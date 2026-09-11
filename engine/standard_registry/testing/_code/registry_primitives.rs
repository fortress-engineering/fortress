//! Parent-local verification of identity and draft registry primitives.

use fortress_core::identity::{RuleId, RuleIdError, StableId, StableIdError};
use fortress_core::standard::{RuleStatus, StandardBundle, StandardLoadError, StandardRegistry};
use serde_json::json;

/// `T-AF-STANDARD-REGISTRY-0001-R01-001`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R01
#[test]
fn stable_identity_accepts_registered_nested_segments() {
    assert!(StableId::parse("T-TF-CLI-0001-R01-001").is_ok());
}

/// `T-AF-STANDARD-REGISTRY-0001-R01-002`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R01
#[test]
fn stable_identity_rejects_lowercase_segments() {
    let error = StableId::parse("arch-dependency-001");
    assert!(matches!(error, Err(StableIdError::UnknownNamespace(_))));
}

/// `T-AF-STANDARD-REGISTRY-0001-R01-003`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R01
#[test]
fn rule_identity_rejects_entity_only_namespace() {
    let error = RuleId::parse("PF-PROJECT-0001");
    assert!(matches!(error, Err(RuleIdError::NonRuleNamespace(_))));
}

/// `T-AF-STANDARD-REGISTRY-0001-R02-001`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R02
#[test]
fn draft_registry_is_structurally_valid() {
    let registry = StandardRegistry::draft_1_0();
    assert_eq!(registry.status(), RuleStatus::Draft);
    assert_eq!(registry.rules().len(), 23);
    assert!(registry.validate().is_ok());
}

/// `T-AF-STANDARD-REGISTRY-0001-R02-002`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R02
#[test]
fn draft_registry_exposes_stable_rule_metadata() {
    let registry = StandardRegistry::draft_1_0();
    let descriptor = registry.find("STD-ID-001");
    assert_eq!(
        descriptor.map(fortress_core::standard::RuleDescriptor::title),
        Some("Stable serialized identity")
    );
}

fn rule_document(id: &str, implies: &[&str], conflicts_with: &[&str]) -> String {
    serde_json::to_string(&json!({
        "$schema": "urn:fortress:schema:v1:rule",
        "schema_version": 1,
        "id": id,
        "title": id,
        "status": "draft",
        "statement": "Synthetic rule statement.",
        "rationale": "Synthetic rule rationale.",
        "failure_prevented": "Synthetic failure class.",
        "applicability": "Synthetic ecosystem.",
        "category": "contract",
        "integrity_tier": 1,
        "evaluation": "Synthetic logical evaluation.",
        "required_capabilities": [],
        "logic": {
            "implies": implies,
            "conflicts_with": conflicts_with,
        },
        "finding": {"message": "Synthetic finding.", "location": "repository"},
        "remediation": "Correct the synthetic rule logic.",
        "valid_example": "Satisfiable rules.",
        "invalid_example": "Contradictory rules.",
        "exception_policy": "No exceptions.",
        "introduced": "1.0.0-draft.1",
        "history": ["Synthetic conformance record."],
    }))
    .expect("synthetic rule JSON must serialize")
}

fn standard_with_rules(
    declarations: &[(&str, &[&str], &[&str])],
) -> Result<StandardBundle, StandardLoadError> {
    let paths: Vec<String> = declarations
        .iter()
        .map(|(id, _, _)| format!("rules/{id}.json"))
        .collect();
    let manifest = serde_json::to_string(&json!({
        "$schema": "urn:fortress:schema:v1:standard-manifest",
        "schema_version": 1,
        "id": "STD-FORTRESS-SYNTHETIC",
        "title": "Synthetic Standard",
        "edition": "1.0.0-draft.1",
        "status": "draft",
        "release_digest": null,
        "rules": paths,
    }))
    .expect("synthetic manifest JSON must serialize");
    let sources: Vec<String> = declarations
        .iter()
        .map(|(id, implies, conflicts)| rule_document(id, implies, conflicts))
        .collect();
    let documents: Vec<(&str, &str)> = paths
        .iter()
        .zip(&sources)
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect();
    StandardBundle::from_json_documents(&manifest, &documents)
}

/// `T-AF-STANDARD-REGISTRY-0001-R04-001`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R04
#[test]
fn satisfiable_rule_implication_cycle_is_valid() {
    let result = standard_with_rules(&[
        ("ARCH-ALPHA-001", &["ARCH-BETA-001"], &[]),
        ("ARCH-BETA-001", &["ARCH-ALPHA-001"], &[]),
    ]);
    assert!(result.is_ok());
}

/// `T-AF-STANDARD-REGISTRY-0001-R04-002`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R04
#[test]
fn unknown_rule_logic_target_is_rejected() {
    let result = standard_with_rules(&[("ARCH-ALPHA-001", &["ARCH-MISSING-001"], &[])]);
    assert!(matches!(
        result,
        Err(StandardLoadError::UnknownLogicRule { .. })
    ));
}

/// `T-AF-STANDARD-REGISTRY-0001-R04-003`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R04
#[test]
fn inherently_unsatisfiable_rule_is_rejected() {
    let result = standard_with_rules(&[
        ("ARCH-ALPHA-001", &["ARCH-BETA-001"], &["ARCH-BETA-001"]),
        ("ARCH-BETA-001", &[], &[]),
    ]);
    assert!(matches!(
        result,
        Err(StandardLoadError::InherentlyUnsatisfiableRule { .. })
    ));
}
