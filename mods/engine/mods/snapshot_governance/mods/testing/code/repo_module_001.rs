//! Implementation exercise of specification-authored `REPO-MODULE-001` fixtures.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::placement::evaluate_module_grammar;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Fixture {
    observed_paths: Vec<String>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mods/snapshot_governance/mods/testing/data")
}

fn read(relative: &str) -> String {
    let path = root().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn load(relative: &str) -> Vec<String> {
    serde_json::from_str::<Fixture>(&read(relative))
        .expect("fixture JSON loads")
        .observed_paths
}

fn projection(findings: &[fortress_core::finding::CanonicalFinding]) -> Value {
    Value::Array(
        findings
            .iter()
            .map(|finding| {
                json!({
                    "path": finding.location().path(),
                    "message": finding.message(),
                })
            })
            .collect(),
    )
}

/// `T-REPO-MODULE-001-R01-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R09
#[test]
fn recursive_composite_and_atomic_modules_pass() {
    let paths = load("module_valid.json");
    let findings = evaluate_module_grammar(&paths, "1.0.0-draft.1").expect("evaluation completes");
    assert!(findings.is_empty());
}

/// `T-REPO-MODULE-001-R01-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R09
#[test]
fn invalid_recursive_grammar_matches_expected_findings() {
    let paths = load("module_invalid.json");
    let first = evaluate_module_grammar(&paths, "1.0.0-draft.1").expect("evaluation completes");
    let second = evaluate_module_grammar(&paths, "1.0.0-draft.1").expect("evaluation repeats");
    assert_eq!(first, second, "canonical findings must be deterministic");
    assert!(
        first
            .iter()
            .all(|finding| finding.finding_fingerprint().starts_with("sha256:"))
    );
    let expected: Value =
        serde_json::from_str(&read("module_expected.json")).expect("expected JSON loads");
    assert_eq!(projection(&first), expected);
}

/// `T-REPO-MODULE-001-R01-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R09
#[test]
fn one_atomic_child_is_the_minimum_recursive_boundary() {
    let paths = load("module_boundary.json");
    let findings = evaluate_module_grammar(&paths, "1.0.0-draft.1").expect("evaluation completes");
    assert!(findings.is_empty());
}

/// `T-REPO-MODULE-001-R01-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R09
#[test]
fn bounded_data_info_failures_are_exact_and_deterministic() {
    let paths = [
        "README.md",
        "contract.json",
        "code/main.rs",
        "data/config.json",
        "data/schema/request.json",
        "docs/code_docs.md",
        "docs/data_docs.md",
        "docs/info_docs.md",
        "info/cache/item.json",
    ]
    .map(str::to_owned);
    let findings = evaluate_module_grammar(&paths, "1.0.0-draft.1").expect("evaluation completes");
    assert_eq!(
        projection(&findings),
        json!([
          {
            "path": "data",
            "message": "MIXED_FLAT_AND_STRUCTURED_ELEMENT: Module `.` Element `data` path `data` violates an Element is either flat or role-structured; expected all direct files or all canonical role directories."
          },
          {
            "path": "info/cache",
            "message": "UNKNOWN_INFO_ROLE: Module `.` Element `info` path `info/cache` violates structured Elements begin with a frozen canonical role; expected report/snapshot/graph/index/manifest/evidence/metric/log."
          }
        ])
    );
}
