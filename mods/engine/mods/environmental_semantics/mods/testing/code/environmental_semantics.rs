//! Parent-local conformance for Environmental Semantics v1.

use std::path::{Path, PathBuf};

use fortress_core::audit::compile_repository_environmental_analysis;
use fortress_core::environmental_semantics::{
    EnvironmentContractError, EnvironmentContractSource, EnvironmentalAnalysisEvaluation,
    analyze_environmental_semantics, canonicalize_environment_contract_json,
    load_environment_contracts,
};
use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::information_flow::{
    InformationFlowPolicySource, analyze_information_flow,
    canonicalize_information_flow_policy_json, load_information_flow_policy,
};
use fortress_core::program_semantics::{
    ExecutableSymbol, ProgramSemanticInput, ProgramSemanticModel, compile_program_semantic_model,
};
use fortress_core::semantic_analysis::{analyze_program_domains, load_function_contracts};
use fortress_core::state_effect_analysis::{analyze_state_effects, load_state_contracts};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repository root exists")
}

fn psm() -> ProgramSemanticModel {
    let source = r"
pub fn boundary(key: &str) -> bool {
    let value = std::path::Path::new(key).exists();
    handler();
    recover();
    value
}
fn handler() {}
fn recover() {}
";
    compile_program_semantic_model(&ProgramSemanticInput::new(
        "PF-ENVIRONMENT-FIXTURE",
        ImplementationObservationInput::new(
            "sha256:fixture",
            vec![
                SnapshotBoundFile::from_bytes(
                    "mods/sample/data/Cargo.toml",
                    b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../code/lib.rs'\n",
                ),
                SnapshotBoundFile::from_bytes("mods/sample/code/lib.rs", source.as_bytes()),
            ],
            vec![
                ModuleTerritory::new("PF-ENVIRONMENT-FIXTURE", ""),
                ModuleTerritory::new("AF-SAMPLE-0001", "mods/sample"),
            ],
        ),
        Vec::<String>::new(),
        Vec::<(String, String)>::new(),
    ))
    .expect("environment fixture PSM compiles")
}

fn symbol_id(model: &ProgramSemanticModel, suffix: &str) -> String {
    model
        .symbols()
        .iter()
        .find(|symbol| symbol.qualified_name().ends_with(suffix))
        .map(ExecutableSymbol::id)
        .map_or_else(|| panic!("symbol `{suffix}` exists"), str::to_owned)
}

fn policy() -> fortress_core::information_flow::InformationFlowPolicy {
    let raw = serde_json::json!({
        "$schema": "urn:fortress:schema:v1:information-flow-policy",
        "schema_version": 1,
        "facets": [
            {
                "id": "FLOW-CONFIDENTIALITY",
                "direction": "higher_is_more_restricted",
                "levels": ["PUBLIC", "SECRET"]
            },
            {
                "id": "FLOW-INTEGRITY",
                "direction": "higher_is_stronger",
                "levels": ["UNTRUSTED", "VALIDATED"]
            }
        ]
    })
    .to_string();
    let source =
        canonicalize_information_flow_policy_json("policy", &raw).expect("policy canonicalizes");
    load_information_flow_policy(vec![InformationFlowPolicySource::new(
        "data/information_flow_policy.json",
        source,
    )])
    .expect("policy resolves")
}

fn handling(model: &ProgramSemanticModel, continuation: &str) -> serde_json::Value {
    serde_json::json!({
        "continuation": symbol_id(model, continuation),
        "terminal": true,
        "retry": false,
        "idempotency_key_parameter": null,
        "duplicate_strategy": "NONE"
    })
}

fn outcome(model: &ProgramSemanticModel, id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "completion": "COMPLETED",
        "response": "ONE_RESPONSE",
        "timing": "WITHIN_DEADLINE",
        "result": "SUCCESS",
        "domain": null,
        "information_flow": [],
        "state": null,
        "forbidden_effects": [],
        "resource": null,
        "handling": handling(model, "handler")
    })
}

fn operation(model: &ProgramSemanticModel) -> serde_json::Value {
    serde_json::json!({
        "id": "EX-FIXTURE-OPERATION",
        "actor": "ENV-FIXTURE-ACTOR",
        "boundary": symbol_id(model, "boundary"),
        "retry_policy": "NEVER",
        "retryable_outcomes": [],
        "idempotency": "IDEMPOTENT",
        "idempotency_key_parameter": null,
        "delivery": "AT_MOST_ONCE",
        "interruption_sensitive": false,
        "atomicity": "UNKNOWN",
        "effect_steps": [],
        "recovery": null,
        "outcomes": [outcome(model, "EX-OUT-FIXTURE-SUCCESS")]
    })
}

fn source(operation: &serde_json::Value, owner: &str) -> EnvironmentContractSource {
    let raw = serde_json::json!({
        "$schema": "urn:fortress:schema:v1:environment-contracts",
        "schema_version": 1,
        "operations": [operation]
    })
    .to_string();
    EnvironmentContractSource::new(
        owner,
        "mods/sample/data/environment_contracts.json",
        canonicalize_environment_contract_json("environment_contracts.json", &raw)
            .expect("environment contract canonicalizes"),
    )
}

#[allow(clippy::needless_pass_by_value)]
fn evaluate(operation: serde_json::Value) -> EnvironmentalAnalysisEvaluation {
    let model = psm();
    let functions = load_function_contracts(&model, Vec::new()).expect("empty functions resolve");
    let semantic = analyze_program_domains(&model, &functions, "1.0.0-draft.1")
        .expect("semantic substrate evaluates");
    let states = load_state_contracts(&model, Vec::new()).expect("empty state authority resolves");
    let state_effect =
        analyze_state_effects(&model, &semantic, &states, &functions, "1.0.0-draft.1")
            .expect("state/effect substrate evaluates");
    let policy = policy();
    let information_flow = analyze_information_flow(
        &model,
        &semantic,
        &state_effect,
        &policy,
        &functions,
        "1.0.0-draft.1",
    )
    .expect("information-flow substrate evaluates");
    let contracts = load_environment_contracts(
        &model,
        &states,
        &policy,
        vec![source(&operation, "AF-SAMPLE-0001")],
    )
    .expect("environment contract resolves");
    analyze_environmental_semantics(
        &model,
        &semantic,
        &state_effect,
        &information_flow,
        &contracts,
        &functions,
        "1.0.0-draft.1",
    )
    .expect("environment semantics evaluate")
}

fn document(evaluation: &EnvironmentalAnalysisEvaluation) -> serde_json::Value {
    serde_json::from_str(
        &evaluation
            .model()
            .to_canonical_json()
            .expect("environment result serializes"),
    )
    .expect("environment result parses")
}

fn first_outcome_mut(operation: &mut serde_json::Value) -> &mut serde_json::Value {
    &mut operation["outcomes"][0]
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R01-001`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R01
#[test]
fn validates_exact_owned_external_boundary() {
    let model = psm();
    let states = load_state_contracts(&model, Vec::new()).expect("states");
    let contracts = load_environment_contracts(
        &model,
        &states,
        &policy(),
        vec![source(&operation(&model), "AF-SAMPLE-0001")],
    )
    .expect("owned boundary resolves");
    assert_eq!(contracts.operations().len(), 1);
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R01-002`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R01
#[test]
fn canonical_contract_and_digest_are_deterministic() {
    let model = psm();
    let fixture = source(&operation(&model), "AF-SAMPLE-0001");
    let states = load_state_contracts(&model, Vec::new()).expect("states");
    let first = load_environment_contracts(&model, &states, &policy(), vec![fixture.clone()])
        .expect("first resolves");
    let second = load_environment_contracts(&model, &states, &policy(), vec![fixture])
        .expect("second resolves");
    assert_eq!(first.digest(), second.digest());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R01-003`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R01
#[test]
fn rejects_unknown_and_foreign_boundary_symbols() {
    let model = psm();
    let states = load_state_contracts(&model, Vec::new()).expect("states");
    let mut unknown = operation(&model);
    unknown["boundary"] = serde_json::json!(
        "rust_symbol:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert!(matches!(
        load_environment_contracts(
            &model,
            &states,
            &policy(),
            vec![source(&unknown, "AF-SAMPLE-0001")]
        ),
        Err(EnvironmentContractError::UnknownSymbol { .. })
    ));
    assert!(matches!(
        load_environment_contracts(
            &model,
            &states,
            &policy(),
            vec![source(&operation(&model), "AF-FOREIGN-0001")]
        ),
        Err(EnvironmentContractError::ForeignSymbol { .. })
    ));
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R01-004`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R01
#[test]
fn preserves_generic_outcome_dimensions() {
    let model = psm();
    let mut fixture = operation(&model);
    let item = first_outcome_mut(&mut fixture);
    item["completion"] = serde_json::json!("UNKNOWN_COMPLETION");
    item["response"] = serde_json::json!("NO_RESPONSE");
    item["timing"] = serde_json::json!("AFTER_DEADLINE");
    item["result"] = serde_json::json!("FAILURE");
    let json = document(&evaluate(fixture));
    assert_eq!(
        json["operations"][0]["outcomes"][0]["completion"],
        "UNKNOWN_COMPLETION"
    );
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R01-005`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R01
#[test]
fn reuses_value_domain_and_information_flow_vocabularies() {
    let model = psm();
    let mut fixture = operation(&model);
    let item = first_outcome_mut(&mut fixture);
    item["domain"] = serde_json::json!({"kind":"boolean","include":[true]});
    item["information_flow"] = serde_json::json!([
        {"facet":"FLOW-INTEGRITY","level":"UNTRUSTED"}
    ]);
    let json = document(&evaluate(fixture));
    assert_eq!(json["operations"][0]["information_flow"], "PROVEN");
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R01-006`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R01
#[test]
fn rejects_unknown_state_and_accepts_closed_effect_vocabulary() {
    let model = psm();
    let states = load_state_contracts(&model, Vec::new()).expect("states");
    let mut fixture = operation(&model);
    first_outcome_mut(&mut fixture)["state"] = serde_json::json!("STATE-UNKNOWN");
    assert!(matches!(
        load_environment_contracts(
            &model,
            &states,
            &policy(),
            vec![source(&fixture, "AF-SAMPLE-0001")]
        ),
        Err(EnvironmentContractError::UnknownState { .. })
    ));
    let mut effect = operation(&model);
    first_outcome_mut(&mut effect)["forbidden_effects"] = serde_json::json!(["may_panic"]);
    assert!(evaluate(effect).model().violations().is_empty());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R01-007`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R01
#[test]
fn resource_unavailable_requires_explicit_resource() {
    let model = psm();
    let states = load_state_contracts(&model, Vec::new()).expect("states");
    let mut fixture = operation(&model);
    first_outcome_mut(&mut fixture)["result"] = serde_json::json!("RESOURCE_UNAVAILABLE");
    assert!(matches!(
        load_environment_contracts(
            &model,
            &states,
            &policy(),
            vec![source(&fixture, "AF-SAMPLE-0001")]
        ),
        Err(EnvironmentContractError::MissingResource { .. })
    ));
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R01-008`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R01
#[test]
fn rejects_nondeterministic_outcome_order() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["outcomes"] =
        serde_json::json!([outcome(&model, "EX-OUT-Z"), outcome(&model, "EX-OUT-A")]);
    let states = load_state_contracts(&model, Vec::new()).expect("states");
    assert!(matches!(
        load_environment_contracts(
            &model,
            &states,
            &policy(),
            vec![source(&fixture, "AF-SAMPLE-0001")]
        ),
        Err(EnvironmentContractError::NonCanonicalOrder(_))
    ));
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R02-001`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R02
#[test]
fn handles_success_and_explicit_rejection() {
    let model = psm();
    let mut rejected = outcome(&model, "EX-OUT-FIXTURE-REJECTED");
    rejected["result"] = serde_json::json!("REJECTED");
    let mut fixture = operation(&model);
    fixture["outcomes"] = serde_json::json!([rejected, outcome(&model, "EX-OUT-FIXTURE-SUCCESS")]);
    let result = evaluate(fixture);
    assert!(result.environment_findings().is_empty());
    assert_eq!(document(&result)["coverage"]["handled"], 2);
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R02-002`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R02
#[test]
fn unhandled_timeout_is_a_hard_environment_contradiction() {
    let model = psm();
    let mut fixture = operation(&model);
    let item = first_outcome_mut(&mut fixture);
    item["id"] = serde_json::json!("EX-OUT-FIXTURE-TIMEOUT");
    item["completion"] = serde_json::json!("UNKNOWN_COMPLETION");
    item["response"] = serde_json::json!("NO_RESPONSE");
    item["timing"] = serde_json::json!("AFTER_DEADLINE");
    item["handling"] = serde_json::Value::Null;
    let result = evaluate(fixture);
    assert_eq!(result.environment_findings().len(), 1);
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R02-003`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R02
#[test]
fn no_response_can_terminate_as_defined_failure() {
    let model = psm();
    let mut fixture = operation(&model);
    let item = first_outcome_mut(&mut fixture);
    item["response"] = serde_json::json!("NO_RESPONSE");
    item["result"] = serde_json::json!("FAILURE");
    assert!(evaluate(fixture).environment_findings().is_empty());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R02-004`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R02
#[test]
fn malformed_response_can_be_explicitly_handled() {
    let model = psm();
    let mut fixture = operation(&model);
    first_outcome_mut(&mut fixture)["result"] = serde_json::json!("MALFORMED");
    assert!(evaluate(fixture).environment_findings().is_empty());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R02-005`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R02
#[test]
fn duplicate_delivery_with_idempotent_handler_is_safe() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["delivery"] = serde_json::json!("MAY_DUPLICATE");
    let item = first_outcome_mut(&mut fixture);
    item["response"] = serde_json::json!("MULTIPLE_RESPONSES");
    item["handling"]["duplicate_strategy"] = serde_json::json!("IDEMPOTENT_HANDLER");
    assert!(evaluate(fixture).retry_findings().is_empty());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R02-006`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R02
#[test]
fn duplicate_unsafe_handler_is_rejected() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["delivery"] = serde_json::json!("MAY_DUPLICATE");
    let result = evaluate(fixture);
    assert_eq!(result.retry_findings().len(), 1);
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R02-007`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R02
#[test]
fn definite_failure_retry_respects_safe_policy() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["retry_policy"] = serde_json::json!("SAFE");
    let item = first_outcome_mut(&mut fixture);
    item["completion"] = serde_json::json!("NOT_COMPLETED");
    item["handling"]["retry"] = serde_json::json!(true);
    assert!(evaluate(fixture).retry_findings().is_empty());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R02-008`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R02
#[test]
fn unknown_completion_non_idempotent_retry_is_rejected() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["retry_policy"] = serde_json::json!("SAFE");
    fixture["idempotency"] = serde_json::json!("NON_IDEMPOTENT");
    let item = first_outcome_mut(&mut fixture);
    item["completion"] = serde_json::json!("UNKNOWN_COMPLETION");
    item["handling"]["retry"] = serde_json::json!(true);
    assert_eq!(evaluate(fixture).retry_findings().len(), 1);
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R02-009`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R02
#[test]
fn idempotent_unknown_completion_retry_is_coherent() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["retry_policy"] = serde_json::json!("SAFE");
    let item = first_outcome_mut(&mut fixture);
    item["completion"] = serde_json::json!("UNKNOWN_COMPLETION");
    item["handling"]["retry"] = serde_json::json!(true);
    assert!(evaluate(fixture).retry_findings().is_empty());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R02-010`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R02
#[test]
fn idempotency_key_identity_must_be_preserved() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["retry_policy"] = serde_json::json!("SAFE");
    fixture["idempotency"] = serde_json::json!("IDEMPOTENT_WITH_KEY");
    fixture["idempotency_key_parameter"] = serde_json::json!("key");
    let item = first_outcome_mut(&mut fixture);
    item["handling"]["retry"] = serde_json::json!(true);
    assert_eq!(evaluate(fixture.clone()).retry_findings().len(), 1);
    first_outcome_mut(&mut fixture)["handling"]["idempotency_key_parameter"] =
        serde_json::json!("key");
    assert!(evaluate(fixture).retry_findings().is_empty());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R03-001`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R03
#[test]
fn late_and_unbounded_outcomes_are_qualitatively_handled() {
    let model = psm();
    for timing in ["AFTER_DEADLINE", "UNBOUNDED"] {
        let mut fixture = operation(&model);
        first_outcome_mut(&mut fixture)["timing"] = serde_json::json!(timing);
        assert!(evaluate(fixture).environment_findings().is_empty());
    }
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R03-002`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R03
#[test]
fn external_payload_flow_labels_are_preserved() {
    let model = psm();
    let mut fixture = operation(&model);
    first_outcome_mut(&mut fixture)["information_flow"] = serde_json::json!([
        {"facet":"FLOW-CONFIDENTIALITY","level":"SECRET"}
    ]);
    let json = document(&evaluate(fixture));
    assert_eq!(
        json["operations"][0]["outcomes"][0]["information_flow"][0]["level"],
        "SECRET"
    );
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R03-003`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R03
#[test]
fn outcome_forbidden_effect_is_checked_against_state_effect_summary() {
    let model = psm();
    let mut fixture = operation(&model);
    first_outcome_mut(&mut fixture)["forbidden_effects"] =
        serde_json::json!(["external_interaction"]);
    assert_eq!(evaluate(fixture).environment_findings().len(), 1);
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R03-004`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R03
#[test]
fn interruption_before_durable_effect_remains_partial_not_failure() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["interruption_sensitive"] = serde_json::json!(true);
    fixture["atomicity"] = serde_json::json!("NON_ATOMIC");
    let result = evaluate(fixture);
    assert!(result.recovery_findings().is_empty());
    assert!(result.model().failure_test_obligations().len() >= 2);
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R03-005`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R03
#[test]
fn interruption_between_non_atomic_effects_requires_recovery() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["interruption_sensitive"] = serde_json::json!(true);
    fixture["atomicity"] = serde_json::json!("NON_ATOMIC");
    fixture["effect_steps"] = serde_json::json!([
        {"id":"STEP-FIRST","durable":true},
        {"id":"STEP-SECOND","durable":true}
    ]);
    assert_eq!(evaluate(fixture).recovery_findings().len(), 1);
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R03-006`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R03
#[test]
fn trusted_atomic_effect_group_needs_no_intermediate_recovery() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["interruption_sensitive"] = serde_json::json!(true);
    fixture["atomicity"] = serde_json::json!("ATOMIC");
    fixture["effect_steps"] = serde_json::json!([
        {"id":"STEP-FIRST","durable":true},
        {"id":"STEP-SECOND","durable":true}
    ]);
    assert!(evaluate(fixture).recovery_findings().is_empty());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R03-007`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R03
#[test]
fn reachable_recovery_handler_defines_bounded_restart() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["interruption_sensitive"] = serde_json::json!(true);
    fixture["atomicity"] = serde_json::json!("NON_ATOMIC");
    fixture["effect_steps"] = serde_json::json!([
        {"id":"STEP-FIRST","durable":true},
        {"id":"STEP-SECOND","durable":true}
    ]);
    fixture["recovery"] = serde_json::json!({
        "handler": symbol_id(&model, "recover"),
        "permitted_states": [],
        "forbidden_states": [],
        "restart": "CONTINUE",
        "idempotency_key_parameter": null
    });
    assert!(evaluate(fixture).recovery_findings().is_empty());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R03-008`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R03
#[test]
fn non_idempotent_recovery_retry_is_rejected() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["idempotency"] = serde_json::json!("NON_IDEMPOTENT");
    fixture["interruption_sensitive"] = serde_json::json!(true);
    fixture["atomicity"] = serde_json::json!("NON_ATOMIC");
    fixture["effect_steps"] = serde_json::json!([
        {"id":"STEP-FIRST","durable":true},
        {"id":"STEP-SECOND","durable":true}
    ]);
    fixture["recovery"] = serde_json::json!({
        "handler": symbol_id(&model, "recover"),
        "permitted_states": [],
        "forbidden_states": [],
        "restart": "RETRY_OPERATION",
        "idempotency_key_parameter": null
    });
    assert_eq!(evaluate(fixture).recovery_findings().len(), 1);
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R03-009`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R03
#[test]
fn resource_unavailable_is_a_defined_generic_outcome() {
    let model = psm();
    let mut fixture = operation(&model);
    let item = first_outcome_mut(&mut fixture);
    item["result"] = serde_json::json!("RESOURCE_UNAVAILABLE");
    item["resource"] = serde_json::json!("worker_capacity");
    assert!(evaluate(fixture).environment_findings().is_empty());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R03-010`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R03
#[test]
fn every_outcome_derives_one_deterministic_fault_scenario() {
    let model = psm();
    let mut failure = outcome(&model, "EX-OUT-FIXTURE-FAILURE");
    failure["result"] = serde_json::json!("FAILURE");
    let mut fixture = operation(&model);
    fixture["outcomes"] = serde_json::json!([failure, outcome(&model, "EX-OUT-FIXTURE-SUCCESS")]);
    let result = evaluate(fixture);
    assert_eq!(result.model().failure_test_obligations().len(), 2);
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R04-001`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R04
#[test]
fn findings_are_partitioned_by_environment_retry_and_recovery_rules() {
    let model = psm();
    let mut fixture = operation(&model);
    fixture["delivery"] = serde_json::json!("MAY_DUPLICATE");
    first_outcome_mut(&mut fixture)["handling"] = serde_json::Value::Null;
    let result = evaluate(fixture);
    assert_eq!(result.environment_findings().len(), 1);
    assert_eq!(result.retry_findings().len(), 0);
    assert_eq!(result.recovery_findings().len(), 0);
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R04-002`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R04
#[test]
fn environmental_json_and_digest_are_byte_deterministic() {
    let model = psm();
    let first = evaluate(operation(&model));
    let second = evaluate(operation(&model));
    assert_eq!(
        first.model().to_canonical_json().expect("first JSON"),
        second.model().to_canonical_json().expect("second JSON")
    );
    assert_eq!(
        first.model().digest().expect("first digest"),
        second.model().digest().expect("second digest")
    );
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R04-003`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R04
#[test]
fn unknown_atomicity_remains_explicit_without_becoming_failure() {
    let model = psm();
    let result = evaluate(operation(&model));
    let json = document(&result);
    assert_eq!(json["operations"][0]["atomicity"], "UNKNOWN");
    assert!(result.recovery_findings().is_empty());
}

/// `T-AF-ENVIRONMENTAL-SEMANTICS-0001-R04-004`
/// Fortress requirement: AF-ENVIRONMENTAL-SEMANTICS-0001-R04
#[test]
fn live_fortress_environmental_analysis_is_coherent() {
    let evaluation = compile_repository_environmental_analysis(repository_root())
        .expect("live Fortress environmental analysis compiles");
    assert_eq!(evaluation.model().operations().len(), 1);
    assert!(evaluation.environment_findings().is_empty());
    assert!(evaluation.retry_findings().is_empty());
    assert!(evaluation.recovery_findings().is_empty());
}
