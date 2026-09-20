//! Contract vectors for strict JSON, public canonicalization, and reader versions.

use fortress_core::finding::{
    Defeater, DefeaterKind, DefeaterRetirementCondition, DefeaterScope, DefeaterScopeKind,
    DefeaterStrength,
};
use fortress_core::wire::{
    VersionDecision, VersionSupport, canonicalize_public_json, parse_public_json,
    parse_strict_json, reject_duplicate_json_keys_bytes,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// `T-AF-STANDARD-REGISTRY-0001-R03-005`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn duplicate_json_keys_fail_before_overwrite() {
    assert!(parse_strict_json::<Value>(r#"{"a":1,"a":2}"#).is_err());
    assert!(parse_strict_json::<Value>(r#"{"a":{"b":1,"b":2}}"#).is_err());
    assert!(reject_duplicate_json_keys_bytes(br#"{"a":{"b":1,"b":2}}"#).is_err());
    assert!(parse_strict_json::<Value>(r#"{"a":1,"b":2}"#).is_ok());
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-006`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn public_json_rejects_inexact_integers() {
    assert!(parse_public_json::<Value>("9007199254740991").is_ok());
    assert!(parse_public_json::<Value>("9007199254740992").is_err());
    assert!(parse_public_json::<Value>("18446744073709551616").is_err());
    assert!(parse_public_json::<Value>("-9007199254740992").is_err());
    assert!(parse_public_json::<Value>("1e999").is_err());
    assert!(parse_public_json::<Value>(r#""9007199254740992""#).is_ok());
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OptionalBounds {
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    maximum: Option<u64>,
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-007`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn optional_bounds_roundtrip_without_synthetic_nulls() {
    let lower: OptionalBounds = parse_public_json(r#"{"minimum":1}"#).expect("valid bound");
    assert_eq!(
        lower,
        OptionalBounds {
            minimum: Some(1),
            maximum: None
        }
    );
    assert_eq!(
        serde_json::to_string(&lower).expect("serialize"),
        r#"{"minimum":1}"#
    );
    let upper: OptionalBounds = parse_public_json(r#"{"maximum":2}"#).expect("valid bound");
    assert_eq!(
        upper,
        OptionalBounds {
            minimum: None,
            maximum: Some(2)
        }
    );
    assert_eq!(
        serde_json::to_string(&upper).expect("serialize"),
        r#"{"maximum":2}"#
    );
}

#[derive(Deserialize)]
enum ClosedMode {
    Known,
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-008`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn unknown_enum_and_version_are_explicit() {
    assert!(parse_public_json::<ClosedMode>(r#""Future""#).is_err());
    let support = VersionSupport::new(&[1, 3], &[2]);
    assert_eq!(support.resolve(1), VersionDecision::Accepted);
    assert_eq!(support.resolve(2), VersionDecision::RequiresMigration);
    assert_eq!(support.resolve(4), VersionDecision::Unsupported);
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-009`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn public_jcs_vectors_preserve_rfc_8785_bytes() {
    assert_eq!(
        canonicalize_public_json(r#"{"b":1,"a":2}"#).expect("JCS"),
        br#"{"a":2,"b":1}"#
    );
    assert_eq!(
        canonicalize_public_json(r#"{"z":-0.0,"a":"€"}"#).expect("JCS"),
        "{\"a\":\"€\",\"z\":0}".as_bytes()
    );
    assert_eq!(
        canonicalize_public_json(r#"{"n":1e30}"#).expect("JCS"),
        br#"{"n":1e+30}"#
    );
}

/// `T-AF-STANDARD-REGISTRY-0001-R03-014`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R03
#[test]
fn old_digest_semantics_are_unchanged() {
    let defeater = Defeater::new(
        DefeaterKind::NoSemanticCoverage,
        DefeaterStrength::Defeating,
        "analyzer",
        "1.0.0",
        DefeaterScope::new(DefeaterScopeKind::Module, "AF-EXAMPLE-0001").expect("scope"),
        "NO_SOURCE",
        BTreeMap::new(),
        Vec::new(),
        DefeaterRetirementCondition::SemanticCoverageEstablished,
    )
    .expect("historical defeater material");
    assert_eq!(
        defeater.id(),
        "defeater:v1:sha256:d7b0c8d8475a92f9458274e434ab13277ead8e2e756fabb52eafc173aa3fd476"
    );
}
