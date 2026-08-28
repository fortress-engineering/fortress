//! Parent-local conformance for Information Flow.

use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::information_flow::{
    InformationFlowAnalysisError, InformationFlowEvaluation, InformationFlowPolicy,
    InformationFlowPolicyError, InformationFlowPolicySource, analyze_information_flow,
    canonicalize_information_flow_policy_json, load_information_flow_policy,
};
use fortress_core::program_semantics::{
    ExecutableSymbol, ProgramSemanticInput, ProgramSemanticModel, compile_program_semantic_model,
};
use fortress_core::semantic_analysis::{
    FunctionContractError, FunctionContractSource, ResolvedFunctionContracts,
    analyze_program_domains, canonicalize_function_contract_json, load_function_contracts,
};
use fortress_core::state_effect_analysis::{analyze_state_effects, load_state_contracts};

fn policy_source(facets: serde_json::Value) -> InformationFlowPolicySource {
    let mut document = serde_json::json!({
        "$schema": "urn:fortress:schema:v1:information-flow-policy",
        "schema_version": 1,
        "facets": []
    });
    document["facets"] = facets;
    let raw = document.to_string();
    let source = canonicalize_information_flow_policy_json("fixture", &raw)
        .expect("policy fixture canonicalizes");
    InformationFlowPolicySource::new("data/information_flow_policy.json", source)
}

fn policy() -> InformationFlowPolicy {
    load_information_flow_policy(vec![policy_source(serde_json::json!([
        {
            "id": "FLOW-CONFIDENTIALITY",
            "direction": "higher_is_more_restricted",
            "levels": ["PUBLIC", "INTERNAL", "SENSITIVE", "SECRET"]
        },
        {
            "id": "FLOW-INTEGRITY",
            "direction": "higher_is_stronger",
            "levels": ["UNTRUSTED", "VALIDATED", "TRUSTED"]
        }
    ]))])
    .expect("fixture policy resolves")
}

fn psm(source: &str) -> ProgramSemanticModel {
    let input = ProgramSemanticInput::new(
        "PF-FLOW-FIXTURE",
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
                ModuleTerritory::new("PF-FLOW-FIXTURE", ""),
                ModuleTerritory::new("AF-SAMPLE-0001", "mods/sample"),
            ],
        ),
        Vec::<String>::new(),
        Vec::<(String, String)>::new(),
    );
    compile_program_semantic_model(&input).expect("information-flow fixture PSM compiles")
}

fn symbol_id(model: &ProgramSemanticModel, suffix: &str) -> String {
    model
        .symbols()
        .iter()
        .find(|symbol| symbol.qualified_name().ends_with(suffix))
        .map(ExecutableSymbol::id)
        .map_or_else(|| panic!("symbol `{suffix}` exists"), str::to_owned)
}

fn function_sources(
    model: &ProgramSemanticModel,
    owner: &str,
    entries: &[(&str, serde_json::Value)],
) -> Vec<FunctionContractSource> {
    let mut functions = entries
        .iter()
        .map(|(suffix, information_flow)| {
            serde_json::json!({
                "symbol": symbol_id(model, suffix),
                "requires": [],
                "ensures": [],
                "state_requires": [],
                "state_ensures": [],
                "effects": null,
                "information_flow": information_flow
            })
        })
        .collect::<Vec<_>>();
    functions.sort_by(|left, right| left["symbol"].as_str().cmp(&right["symbol"].as_str()));
    let raw = serde_json::json!({
        "$schema": "urn:fortress:schema:v3:function-contracts",
        "schema_version": 3,
        "functions": functions
    })
    .to_string();
    vec![FunctionContractSource::new(
        owner,
        "mods/sample/data/function_contracts.json",
        canonicalize_function_contract_json("function_contracts.json", &raw)
            .expect("function-flow fixture canonicalizes"),
    )]
}

fn flow(
    sources: serde_json::Value,
    requires: serde_json::Value,
    ensures: serde_json::Value,
    transforms: serde_json::Value,
) -> serde_json::Value {
    let mut declaration = serde_json::json!({
        "sources": [],
        "requires": [],
        "ensures": [],
        "transforms": []
    });
    declaration["sources"] = sources;
    declaration["requires"] = requires;
    declaration["ensures"] = ensures;
    declaration["transforms"] = transforms;
    declaration
}

fn evaluate(
    model: &ProgramSemanticModel,
    policy: &InformationFlowPolicy,
    contracts: &ResolvedFunctionContracts,
) -> Result<InformationFlowEvaluation, InformationFlowAnalysisError> {
    let semantic = analyze_program_domains(model, contracts, "1.0.0-draft.1")
        .expect("semantic substrate evaluates");
    let states = load_state_contracts(model, Vec::new()).expect("empty state authority resolves");
    let state_effect = analyze_state_effects(model, &semantic, &states, contracts, "1.0.0-draft.1")
        .expect("state/effect substrate evaluates");
    analyze_information_flow(
        model,
        &semantic,
        &state_effect,
        policy,
        contracts,
        "1.0.0-draft.1",
    )
}

fn json(evaluation: &InformationFlowEvaluation) -> serde_json::Value {
    serde_json::from_str(
        &evaluation
            .model()
            .to_canonical_json()
            .expect("flow result serializes"),
    )
    .expect("flow result parses")
}

/// `T-AF-INFORMATION-FLOW-0001-R01-001`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R01
#[test]
fn validates_project_defined_facet_algebra() {
    let policy = policy();
    assert_eq!(policy.facets().count(), 2);
    assert_eq!(
        policy
            .facet("FLOW-INTEGRITY")
            .expect("facet")
            .levels()
            .len(),
        3
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R01-002`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R01
#[test]
fn rejects_duplicate_policy_facets_and_levels() {
    let duplicate_level = load_information_flow_policy(vec![policy_source(serde_json::json!([{
        "id": "FLOW-INTEGRITY", "direction": "higher_is_stronger", "levels": ["LOW", "LOW"]
    }]))]);
    assert!(matches!(
        duplicate_level,
        Err(InformationFlowPolicyError::InvalidFacet { .. })
    ));
    let duplicate_facet = load_information_flow_policy(vec![policy_source(serde_json::json!([
        {"id": "FLOW-X", "direction": "higher_is_stronger", "levels": ["LOW", "HIGH"]},
        {"id": "FLOW-X", "direction": "higher_is_stronger", "levels": ["LOW", "HIGH"]}
    ]))]);
    assert!(matches!(
        duplicate_facet,
        Err(InformationFlowPolicyError::NonCanonicalOrder(_))
    ));
}

/// `T-AF-INFORMATION-FLOW-0001-R01-003`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R01
#[test]
fn rejects_invalid_direction_and_nonroot_policy() {
    let raw = r#"{"$schema":"urn:fortress:schema:v1:information-flow-policy","schema_version":1,"facets":[{"id":"FLOW-X","direction":"sideways","levels":["LOW","HIGH"]}]}"#;
    assert!(matches!(
        load_information_flow_policy(vec![InformationFlowPolicySource::new(
            "data/information_flow_policy.json",
            raw,
        )]),
        Err(InformationFlowPolicyError::InvalidJson { .. })
    ));
    assert!(matches!(
        load_information_flow_policy(vec![InformationFlowPolicySource::new(
            "mods/sample/data/information_flow_policy.json",
            "{}",
        )]),
        Err(InformationFlowPolicyError::NonRootPolicy(_))
    ));
}

/// `T-AF-INFORMATION-FLOW-0001-R01-004`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R01
#[test]
fn rejects_unknown_facet_and_level_references() {
    let model = psm("fn accept(input: String) {}\n");
    for (facet, level, unknown_facet) in [
        ("FLOW-UNKNOWN", "LOW", true),
        ("FLOW-INTEGRITY", "IMPOSSIBLE", false),
    ] {
        let contracts = load_function_contracts(
            &model,
            function_sources(
                &model,
                "AF-SAMPLE-0001",
                &[(
                    "accept",
                    flow(
                        serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":facet,"level":level}]),
                        serde_json::json!([]),
                        serde_json::json!([]),
                        serde_json::json!([]),
                    ),
                )],
            ),
        )
        .expect("contract shape resolves");
        let result = evaluate(&model, &policy(), &contracts);
        assert!(if unknown_facet {
            matches!(
                result,
                Err(InformationFlowAnalysisError::UnknownFacet { .. })
            )
        } else {
            matches!(
                result,
                Err(InformationFlowAnalysisError::UnknownLevel { .. })
            )
        });
    }
}

/// `T-AF-INFORMATION-FLOW-0001-R01-005`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R01
#[test]
fn rejects_foreign_symbol_flow_authority() {
    let model = psm("fn accept(input: String) {}\n");
    let result = load_function_contracts(
        &model,
        function_sources(
            &model,
            "AF-FOREIGN-0001",
            &[(
                "accept",
                flow(
                    serde_json::json!([]),
                    serde_json::json!([]),
                    serde_json::json!([]),
                    serde_json::json!([]),
                ),
            )],
        ),
    );
    assert!(matches!(
        result,
        Err(FunctionContractError::ForeignSymbol { .. })
    ));
}

/// `T-AF-INFORMATION-FLOW-0001-R02-001`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R02
#[test]
fn propagates_assignment_and_return_flow() {
    let model = psm("fn copy(input: String) -> String { let value = input; value }\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "copy",
        flow(
            serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"VALIDATED"}]),
            serde_json::json!([{"target":{"kind":"return"},"facet":"FLOW-INTEGRITY","minimum":"VALIDATED"}]),
            serde_json::json!([]), serde_json::json!([]),
        ),
    )])).expect("contracts resolve");
    let evaluation = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    assert!(
        evaluation.findings().is_empty(),
        "{:#?}",
        evaluation.findings()
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R02-002`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R02
#[test]
fn propagates_argument_parameter_and_return_interprocedurally() {
    let model = psm(
        "fn sink(value: String) -> String { value } fn source(input: String) -> String { sink(input) }\n",
    );
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[
        ("sink", flow(serde_json::json!([]), serde_json::json!([{"target":{"kind":"parameter","name":"value"},"facet":"FLOW-INTEGRITY","minimum":"VALIDATED"}]), serde_json::json!([]), serde_json::json!([]))),
        ("source", flow(serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"VALIDATED"}]), serde_json::json!([]), serde_json::json!([]), serde_json::json!([]))),
    ])).expect("contracts resolve");
    let evaluation = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    assert!(
        evaluation.findings().is_empty(),
        "{:#?}",
        evaluation.findings()
    );
    assert!(
        json(&evaluation)["coverage"]["interprocedural_flow_facts"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R02-003`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R02
#[test]
fn propagates_tuple_and_wrapper_payloads() {
    let model = psm("fn wrap(input: String) -> Option<(String, bool)> { Some((input, true)) }\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "wrap", flow(
            serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-CONFIDENTIALITY","level":"SENSITIVE"}]),
            serde_json::json!([{"target":{"kind":"return"},"facet":"FLOW-CONFIDENTIALITY","maximum":"SENSITIVE"}]),
            serde_json::json!([]), serde_json::json!([]),
        ),
    )])).expect("contracts resolve");
    assert!(
        evaluate(&model, &policy(), &contracts)
            .expect("flow evaluates")
            .findings()
            .is_empty()
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R02-004`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R02
#[test]
fn propagates_result_payloads() {
    let model = psm("fn wrap(input: String) -> Result<String, ()> { Ok(input) }\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "wrap", flow(
            serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"TRUSTED"}]),
            serde_json::json!([{"target":{"kind":"return"},"facet":"FLOW-INTEGRITY","minimum":"TRUSTED"}]),
            serde_json::json!([]), serde_json::json!([]),
        ),
    )])).expect("contracts resolve");
    assert!(
        evaluate(&model, &policy(), &contracts)
            .expect("flow evaluates")
            .findings()
            .is_empty()
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R02-005`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R02
#[test]
fn propagates_field_write_to_later_field_read() {
    let model = psm(
        "struct Cache { value: String } impl Cache { fn store(&mut self, input: String) { self.value = input; } fn read(&self) -> String { self.value.clone() } }\n",
    );
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[
        ("Cache::read", flow(serde_json::json!([]), serde_json::json!([{"target":{"kind":"return"},"facet":"FLOW-INTEGRITY","minimum":"VALIDATED"}]), serde_json::json!([]), serde_json::json!([]))),
        ("Cache::store", flow(serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"VALIDATED"}]), serde_json::json!([]), serde_json::json!([]), serde_json::json!([]))),
    ])).expect("contracts resolve");
    let evaluation = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    assert!(
        evaluation.findings().is_empty(),
        "{}",
        evaluation.model().to_canonical_json().expect("JSON")
    );
    assert!(
        json(&evaluation)["coverage"]["field_flow_facts"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R02-006`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R02
#[test]
fn conservatively_joins_multiple_source_levels() {
    let model = psm("fn choose(input: String) -> String { input }\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "choose", flow(
            serde_json::json!([
                {"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"TRUSTED"},
                {"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"UNTRUSTED"}
            ]),
            serde_json::json!([{"target":{"kind":"return"},"facet":"FLOW-INTEGRITY","minimum":"VALIDATED"}]),
            serde_json::json!([]), serde_json::json!([]),
        ),
    )])).expect("contracts resolve");
    let evaluation = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    assert_eq!(
        json(&evaluation)["violations"][0]["contradicting_levels"][0],
        "UNTRUSTED"
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R02-007`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R02
#[test]
fn recursive_flow_reaches_a_deterministic_fixed_point() {
    let model = psm(
        "fn recur(input: String, stop: bool) -> String { if stop { input } else { recur(input, true) } }\n",
    );
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "recur", flow(
            serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"VALIDATED"}]),
            serde_json::json!([{"target":{"kind":"return"},"facet":"FLOW-INTEGRITY","minimum":"VALIDATED"}]),
            serde_json::json!([]), serde_json::json!([]),
        ),
    )])).expect("contracts resolve");
    let first = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    let second = evaluate(&model, &policy(), &contracts).expect("flow repeats");
    assert_eq!(
        first.model().to_canonical_json().unwrap(),
        second.model().to_canonical_json().unwrap()
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R02-008`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R02
#[test]
fn opaque_and_unresolved_outputs_remain_unknown() {
    let model = psm("fn opaque() -> String { unknown_target() }\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "opaque", flow(
            serde_json::json!([]),
            serde_json::json!([{"target":{"kind":"return"},"facet":"FLOW-INTEGRITY","minimum":"VALIDATED"}]),
            serde_json::json!([]), serde_json::json!([]),
        ),
    )])).expect("contracts resolve");
    let evaluation = evaluate(&model, &policy(), &contracts).expect("uncertainty is not failure");
    assert!(evaluation.findings().is_empty());
    assert_eq!(json(&evaluation)["coverage"]["unknown_sinks"], 1);
}

/// `T-AF-INFORMATION-FLOW-0001-R03-001`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R03
#[test]
fn rejects_insufficient_integrity_with_counter_domain() {
    let model = psm("fn privileged(input: String) {}\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "privileged", flow(
            serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"UNTRUSTED"}]),
            serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","minimum":"VALIDATED"}]),
            serde_json::json!([]), serde_json::json!([]),
        ),
    )])).expect("contracts resolve");
    let evaluation = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    assert_eq!(
        json(&evaluation)["violations"][0]["contradicting_levels"][0],
        "UNTRUSTED"
    );
    assert_eq!(evaluation.findings().len(), 1);
}

/// `T-AF-INFORMATION-FLOW-0001-R03-002`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R03
#[test]
fn rejects_excessive_confidentiality_with_counter_domain() {
    let model = psm("fn log(message: String) {}\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "log", flow(
            serde_json::json!([{"target":{"kind":"parameter","name":"message"},"facet":"FLOW-CONFIDENTIALITY","level":"SECRET"}]),
            serde_json::json!([{"target":{"kind":"parameter","name":"message"},"facet":"FLOW-CONFIDENTIALITY","maximum":"INTERNAL"}]),
            serde_json::json!([]), serde_json::json!([]),
        ),
    )])).expect("contracts resolve");
    let evaluation = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    assert_eq!(
        json(&evaluation)["violations"][0]["contradicting_levels"][0],
        "SECRET"
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R03-003`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R03
#[test]
fn ordinary_computation_cannot_improve_trust_implicitly() {
    let model = psm("fn rename(input: String) -> String { input.clone() }\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "rename", flow(
            serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"UNTRUSTED"}]),
            serde_json::json!([{"target":{"kind":"return"},"facet":"FLOW-INTEGRITY","minimum":"VALIDATED"}]),
            serde_json::json!([]), serde_json::json!([]),
        ),
    )])).expect("contracts resolve");
    assert_eq!(
        evaluate(&model, &policy(), &contracts)
            .expect("flow evaluates")
            .findings()
            .len(),
        1
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R03-004`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R03
#[test]
fn explicit_endorsement_changes_integrity_with_diagnostic() {
    let model = psm("fn validate(input: String) -> String { input }\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "validate", flow(
            serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"UNTRUSTED"}]),
            serde_json::json!([{"target":{"kind":"return"},"facet":"FLOW-INTEGRITY","minimum":"VALIDATED"}]),
            serde_json::json!([]),
            serde_json::json!([{"kind":"endorsement","input":{"kind":"parameter","name":"input"},"output":{"kind":"return"},"facet":"FLOW-INTEGRITY","from":"UNTRUSTED","to":"VALIDATED"}]),
        ),
    )])).expect("contracts resolve");
    let evaluation = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    assert!(evaluation.findings().is_empty());
    assert_eq!(evaluation.model().trusted_transition_diagnostics().len(), 1);
}

/// `T-AF-INFORMATION-FLOW-0001-R03-005`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R03
#[test]
fn explicit_declassification_changes_confidentiality_with_diagnostic() {
    let model = psm("fn redact(input: String) -> String { input }\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "redact", flow(
            serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-CONFIDENTIALITY","level":"SECRET"}]),
            serde_json::json!([{"target":{"kind":"return"},"facet":"FLOW-CONFIDENTIALITY","maximum":"PUBLIC"}]),
            serde_json::json!([]),
            serde_json::json!([{"kind":"declassification","input":{"kind":"parameter","name":"input"},"output":{"kind":"return"},"facet":"FLOW-CONFIDENTIALITY","from":"SECRET","to":"PUBLIC"}]),
        ),
    )])).expect("contracts resolve");
    let evaluation = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    assert!(evaluation.findings().is_empty());
    assert!(
        json(&evaluation)["trusted_transition_diagnostics"][0]["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R03-006`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R03
#[test]
fn invalid_trusted_transition_direction_fails() {
    let model = psm("fn weaken(input: String) -> String { input }\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "weaken", flow(
            serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"TRUSTED"}]),
            serde_json::json!([]), serde_json::json!([]),
            serde_json::json!([{"kind":"endorsement","input":{"kind":"parameter","name":"input"},"output":{"kind":"return"},"facet":"FLOW-INTEGRITY","from":"TRUSTED","to":"UNTRUSTED"}]),
        ),
    )])).expect("contracts resolve");
    assert!(matches!(
        evaluate(&model, &policy(), &contracts),
        Err(InformationFlowAnalysisError::InvalidTrustedTransition { .. })
    ));
}

/// `T-AF-INFORMATION-FLOW-0001-R03-007`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R03
#[test]
fn independent_facets_remain_context_specific() {
    let model = psm("fn consume(input: String) {}\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "consume", flow(
            serde_json::json!([
                {"target":{"kind":"parameter","name":"input"},"facet":"FLOW-CONFIDENTIALITY","level":"PUBLIC"},
                {"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"UNTRUSTED"}
            ]),
            serde_json::json!([
                {"target":{"kind":"parameter","name":"input"},"facet":"FLOW-CONFIDENTIALITY","maximum":"INTERNAL"},
                {"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","minimum":"VALIDATED"}
            ]),
            serde_json::json!([]), serde_json::json!([]),
        ),
    )])).expect("contracts resolve");
    let evaluation = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    assert_eq!(evaluation.findings().len(), 1);
    assert_eq!(
        json(&evaluation)["violations"][0]["facet"],
        "FLOW-INTEGRITY"
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R04-001`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R04
#[test]
fn policy_canonicalization_is_deterministic() {
    let raw = serde_json::json!({
        "$schema": "urn:fortress:schema:v1:information-flow-policy",
        "schema_version": 1,
        "facets": [{
            "id": "FLOW-INTEGRITY", "direction": "higher_is_stronger", "levels": ["LOW", "HIGH"]
        }]
    })
    .to_string();
    let first = canonicalize_information_flow_policy_json("fixture", &raw)
        .expect("canonicalization succeeds");
    let second = canonicalize_information_flow_policy_json("fixture", &first)
        .expect("canonicalization is idempotent");
    assert_eq!(first, second);
}

/// `T-AF-INFORMATION-FLOW-0001-R04-002`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R04
#[test]
fn analysis_artifact_and_digest_are_deterministic() {
    let model = psm("fn identity(input: String) -> String { input }\n");
    let contracts = load_function_contracts(&model, function_sources(&model, "AF-SAMPLE-0001", &[(
        "identity", flow(
            serde_json::json!([{"target":{"kind":"parameter","name":"input"},"facet":"FLOW-INTEGRITY","level":"VALIDATED"}]),
            serde_json::json!([]), serde_json::json!([]), serde_json::json!([]),
        ),
    )])).expect("contracts resolve");
    let first = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    let second = evaluate(&model, &policy(), &contracts).expect("flow repeats");
    assert_eq!(
        first.model().to_canonical_json().unwrap(),
        second.model().to_canonical_json().unwrap()
    );
    assert_eq!(
        first.model().digest().unwrap(),
        second.model().digest().unwrap()
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R04-003`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R04
#[test]
fn unsupported_implicit_and_external_semantics_remain_explicit() {
    let model = psm("fn branch(secret: bool) -> i32 { if secret { 1 } else { 0 } }\n");
    let contracts = load_function_contracts(&model, Vec::new()).expect("empty contracts resolve");
    let evaluation = evaluate(&model, &policy(), &contracts).expect("flow evaluates");
    assert!(
        evaluation
            .model()
            .unsupported_semantics()
            .contains(&"complete_implicit_control_information_flow".to_owned())
    );
    assert!(
        evaluation
            .model()
            .unsupported_semantics()
            .contains(&"external_api_information_flow_without_contract".to_owned())
    );
    let result = json(&evaluation);
    assert_eq!(result["coverage"]["source_classification"], "UNKNOWN");
    assert_eq!(result["coverage"]["sink_verification"], "UNKNOWN");
    assert_eq!(result["coverage"]["trusted_transition_coverage"], "UNKNOWN");
}
