//! Independent metadata controls; these never score held-out source fixtures.

use fortress_core::qualification::{QualificationInputs, QualificationManifest, SupportedScope};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn scope() -> SupportedScope {
    SupportedScope::from_json_str(&json!({
        "$schema":"urn:fortress:schema:v1:supported-qualification-scope","schema_version":1,
        "scope_id":"fixture-scope","effects":["filesystem.write","process.spawn"],
        "strata":["NEGATIVE","POSITIVE","UNKNOWN"],"exclusions":["No population or human validation."],
        "promotes_default_blocking":false,"human_validation":"RECOMMENDED_FUTURE_RESEARCH_NOT_PERFORMED"
    }).to_string()).unwrap()
}

fn record() -> (Value, QualificationInputs) {
    let mut identities = [
        "analyzer",
        "candidate_source",
        "catalog",
        "contexts",
        "corpus",
        "harness",
        "heldout_selection",
        "native_source",
        "oracle",
        "outcomes",
        "profiles",
        "protocol",
        "registry",
        "schemas",
        "staged_cli",
        "supported_scope",
        "toolchain",
    ]
    .into_iter()
    .map(|name| (name.to_owned(), format!("sha256:{}", "a".repeat(64))))
    .collect::<BTreeMap<_, _>>();
    identities.insert("supported_scope".into(), scope().digest().unwrap());
    let inputs = QualificationInputs { identities };
    (
        json!({"$schema":"urn:fortress:derived:v1:semantic-qualification","schema_version":1,
        "status":"PASS","scope_id":"fixture-scope","inputs":inputs,
        "counts":{"declared_cases":12,"completed_cases":12,"required_cases":8,"required_passed":8,"mismatches":0,
            "positive":2,"negative":2,"conditional_negative":0,"unknown":2,"not_applicable":1,"invalid":1,"execution_failures":0,"authorization":2,"undeclared":2,
            "distinct_source_sites":2,"claims":8,"causal_paths":5,"declared_mutations":3,"exercised_mutations":3,
            "equal_differentials":11,"equal_metadata_controls":11,"invalid_port_equivalences":1,"external_positive_scopes":1},
        "limitations":{"independent_human_adjudication":false,"population_precision":null,
            "real_world_false_positive_rate":null,"statistical_confidence":null,"independent_external_assurance":false,
            "reasons":["Automated deterministic envelope only.","No independent human validation."]}}),
        inputs,
    )
}

fn admitted(value: &Value, current: &QualificationInputs) -> bool {
    QualificationManifest::from_json_str(&value.to_string())
        .is_ok_and(|m| m.admit_for(current, &scope()).is_ok())
}

/// `T-AF-STANDARD-REGISTRY-0001-R07-001`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R07
#[test]
fn exact_scope_and_every_requalification_input_are_required() {
    let (value, current) = record();
    assert!(admitted(&value, &current));
    for name in current.identities.keys() {
        let mut stale = current.clone();
        stale
            .identities
            .insert(name.clone(), format!("sha256:{}", "b".repeat(64)));
        assert!(
            !admitted(&value, &stale),
            "stale {name} must invalidate reuse"
        );
        let mut missing = value.clone();
        missing["inputs"]["identities"]
            .as_object_mut()
            .unwrap()
            .remove(name);
        assert!(!admitted(&missing, &current));
    }
    let mut foreign = value.clone();
    foreign["scope_id"] = json!("another-scope");
    assert!(!admitted(&foreign, &current));
}

/// `T-AF-STANDARD-REGISTRY-0001-R07-002`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R07
#[test]
fn missing_cases_zero_coverage_failed_mutations_and_omitted_calls_are_not_qualification() {
    let (value, current) = record();
    for field in ["positive", "negative"] {
        let mut bad = value.clone();
        bad["counts"][field] = json!(0);
        bad["counts"]["unknown"] = json!(4);
        assert!(
            !admitted(&bad, &current),
            "a balanced but one-sided corpus cannot qualify"
        );
    }
    for (field, invalid) in [
        ("completed_cases", 11_u64),
        ("required_passed", 7),
        ("mismatches", 1),
        ("positive", 0),
        ("negative", 0),
        ("distinct_source_sites", 0),
        ("claims", 0),
        ("causal_paths", 0),
        ("exercised_mutations", 2),
        ("equal_differentials", 10),
        ("external_positive_scopes", 0),
        ("conditional_negative", 2),
        ("declared_cases", 9_007_199_254_740_992),
    ] {
        let mut bad = value.clone();
        bad["counts"][field] = json!(invalid);
        assert!(!admitted(&bad, &current), "{field} must fail closed");
    }
    for status in ["FAIL", "INCOMPLETE", "NOT_RUN"] {
        let mut bad = value.clone();
        bad["status"] = json!(status);
        assert!(!admitted(&bad, &current));
    }
}

/// `T-AF-STANDARD-REGISTRY-0001-R07-003`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R07
#[test]
fn unsupported_assurance_and_ambiguous_records_are_refused() {
    let (value, current) = record();
    for field in [
        "independent_human_adjudication",
        "independent_external_assurance",
    ] {
        let mut bad = value.clone();
        bad["limitations"][field] = json!(true);
        assert!(!admitted(&bad, &current));
    }
    for field in [
        "population_precision",
        "real_world_false_positive_rate",
        "statistical_confidence",
    ] {
        let mut bad = value.clone();
        bad["limitations"][field] = json!(0.99);
        assert!(!admitted(&bad, &current));
        bad["limitations"].as_object_mut().unwrap().remove(field);
        assert!(!admitted(&bad, &current));
    }
    let duplicate = value.to_string().replacen(
        "\"status\":\"PASS\"",
        "\"status\":\"PASS\",\"status\":\"PASS\"",
        1,
    );
    assert!(QualificationManifest::from_json_str(&duplicate).is_err());
    let mut unknown = value;
    unknown["accuracy"] = json!("CERTIFIED");
    assert!(!admitted(&unknown, &current));
}
