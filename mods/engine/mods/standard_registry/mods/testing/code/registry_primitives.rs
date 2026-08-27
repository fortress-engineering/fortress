//! Parent-local verification of identity and draft registry primitives.

use fortress_core::identity::{RuleId, RuleIdError, StableId, StableIdError};
use fortress_core::standard::{RuleStatus, StandardRegistry};

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
    assert_eq!(registry.rules().len(), 8);
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
