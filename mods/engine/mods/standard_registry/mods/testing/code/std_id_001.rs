//! Implementation exercise of specification-authored `STD-ID-001` fixtures.
//!
//! The fixture inputs and expected finding remain conformance material outside
//! this crate. These tests verify the implementation against them; they do not
//! generate or redefine the expected result.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::identity::StableId;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mods/standard_registry/mods/testing/data")
}

fn read_fixture(relative_path: &str) -> String {
    let path = fixture_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()))
}

/// `T-STD-ID-001-R01-001`
#[test]
fn valid_fixture_passes() {
    let input = read_fixture("std_id_valid.txt");
    assert!(StableId::parse(input.trim()).is_ok());
}

/// `T-STD-ID-001-R01-002`
#[test]
fn invalid_fixture_produces_expected_rule_finding() {
    let input = read_fixture("std_id_invalid.txt");
    let error = StableId::parse(input.trim()).expect_err("negative fixture must fail");
    let expected: serde_json::Value = serde_json::from_str(&read_fixture("std_id_expected.json"))
        .expect("expected finding must be valid JSON");

    assert_eq!(expected["rule_id"], error.rule_id());
    assert_eq!(expected["state"], "FAIL");
    assert_eq!(expected["input"], input.trim());
}

/// `T-STD-ID-001-R01-003`
#[test]
fn shortest_registered_boundary_fixture_passes() {
    let input = read_fixture("std_id_boundary.txt");
    assert!(StableId::parse(input.trim()).is_ok());
}
