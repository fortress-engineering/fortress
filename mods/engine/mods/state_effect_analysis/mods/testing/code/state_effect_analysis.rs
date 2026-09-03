//! Parent-local State and Effect Analysis v1 conformance.

use std::path::{Path, PathBuf};

use fortress_core::audit::compile_repository_state_effect_analysis;
use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::program_semantics::{
    ExecutableSymbol, ProgramSemanticInput, ProgramSemanticModel, compile_program_semantic_model,
};
use fortress_core::semantic_analysis::{
    FunctionContractError, FunctionContractSource, FunctionEffect, ResolvedFunctionContracts,
    SemanticAnalysisEvaluation, analyze_program_domains, canonicalize_function_contract_json,
    load_function_contracts,
};
use fortress_core::state_effect_analysis::{
    EffectCapability, EffectEvidenceKind, ResolvedStateContracts, StateContractError,
    StateContractSource, StateEffectAnalysisError, StateEffectAnalysisEvaluation,
    analyze_state_effects, canonicalize_state_contract_json, capability_for_effect,
    load_state_contracts,
};

type FunctionFixture<'a> = (&'a str, &'a [&'a str], &'a [&'a str], Option<&'a [&'a str]>);

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repository root exists")
}

fn psm(source: &str) -> ProgramSemanticModel {
    let input = ProgramSemanticInput::new(
        "PF-STATE-FIXTURE",
        ImplementationObservationInput::new(
            "sha256:fixture",
            vec![
                SnapshotBoundFile::from_bytes(
                    "mods/sample/data/Cargo.toml",
                    b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../code/lib.rs'\n[dependencies]\ngetrandom='0.3'\nrand='0.9'\n",
                ),
                SnapshotBoundFile::from_bytes("mods/sample/code/lib.rs", source.as_bytes()),
            ],
            vec![
                ModuleTerritory::new("PF-STATE-FIXTURE", ""),
                ModuleTerritory::new("AF-SAMPLE-0001", "mods/sample"),
            ],
        ),
        Vec::<String>::new(),
        Vec::<(String, String)>::new(),
    );
    compile_program_semantic_model(&input).expect("state fixture PSM compiles")
}

fn nominal_id(model: &ProgramSemanticModel, suffix: &str) -> String {
    model
        .nominal_types()
        .iter()
        .find(|item| item.qualified_name().ends_with(suffix))
        .map(|item| item.id().to_owned())
        .expect("nominal exists")
}

fn symbol_id(model: &ProgramSemanticModel, suffix: &str) -> String {
    model
        .symbols()
        .iter()
        .find(|item| item.qualified_name().ends_with(suffix))
        .map(ExecutableSymbol::id)
        .map(str::to_owned)
        .expect("symbol exists")
}

fn state_source(model: &ProgramSemanticModel) -> StateContractSource {
    let nominal = nominal_id(model, "Connection");
    let raw = format!(
        r#"{{"$schema":"urn:fortress:schema:v1:state-contracts","schema_version":1,"types":[{{"type":"{nominal}","states":[{{"id":"STATE-CONNECTION-CLOSED","when":[{{"field":"closed","domain":{{"kind":"boolean","include":[true]}}}}]}},{{"id":"STATE-CONNECTION-OPEN","when":[{{"field":"closed","domain":{{"kind":"boolean","include":[false]}}}}]}}]}}]}}"#,
    );
    StateContractSource::new(
        "AF-SAMPLE-0001",
        "mods/sample/data/state_contracts.json",
        canonicalize_state_contract_json("state_contracts.json", &raw)
            .expect("state contract canonicalizes"),
    )
}

fn custom_state_source(document: &serde_json::Value) -> StateContractSource {
    let raw = document.to_string();
    StateContractSource::new(
        "AF-SAMPLE-0001",
        "mods/sample/data/state_contracts.json",
        canonicalize_state_contract_json("state_contracts.json", &raw)
            .expect("custom state contract canonicalizes"),
    )
}

fn function_sources(
    model: &ProgramSemanticModel,
    entries: &[FunctionFixture<'_>],
) -> Vec<FunctionContractSource> {
    function_sources_for_version(
        model,
        entries,
        "urn:fortress:schema:v3:function-contracts",
        3,
    )
}

fn function_sources_for_version(
    model: &ProgramSemanticModel,
    entries: &[FunctionFixture<'_>],
    schema: &str,
    schema_version: u16,
) -> Vec<FunctionContractSource> {
    let mut functions = entries
        .iter()
        .map(|(suffix, requires, ensures, effects)| {
            let symbol = symbol_id(model, suffix);
            let state_requires = requires
                .iter()
                .map(|state| serde_json::json!({"target": "self", "state": state}))
                .collect::<Vec<_>>();
            let state_ensures = ensures
                .iter()
                .map(|state| serde_json::json!({"target": "self", "state": state}))
                .collect::<Vec<_>>();
            let effects = effects.map(|values| serde_json::json!({"allowed": values}));
            serde_json::json!({
                "symbol": symbol,
                "requires": [],
                "ensures": [],
                "state_requires": state_requires,
                "state_ensures": state_ensures,
                "effects": effects
            })
        })
        .collect::<Vec<_>>();
    functions.sort_by(|left, right| left["symbol"].as_str().cmp(&right["symbol"].as_str()));
    let raw = serde_json::json!({
        "$schema": schema,
        "schema_version": schema_version,
        "functions": functions
    })
    .to_string();
    vec![FunctionContractSource::new(
        "AF-SAMPLE-0001",
        "mods/sample/data/function_contracts.json",
        canonicalize_function_contract_json("function_contracts.json", &raw)
            .expect("function contracts canonicalize"),
    )]
}

fn function_sources_v4(
    model: &ProgramSemanticModel,
    entries: &[FunctionFixture<'_>],
) -> Vec<FunctionContractSource> {
    function_sources_for_version(
        model,
        entries,
        "urn:fortress:schema:v4:function-contracts",
        4,
    )
}

fn evaluate(
    model: &ProgramSemanticModel,
    state_contracts: &ResolvedStateContracts,
    function_contracts: &ResolvedFunctionContracts,
) -> StateEffectAnalysisEvaluation {
    let semantic: SemanticAnalysisEvaluation =
        analyze_program_domains(model, function_contracts, "1.0.0-draft.1")
            .expect("value-domain analysis succeeds");
    analyze_state_effects(
        model,
        &semantic,
        state_contracts,
        function_contracts,
        "1.0.0-draft.1",
    )
    .expect("state/effect analysis succeeds")
}

fn connection_model(body: &str) -> ProgramSemanticModel {
    psm(&format!(
        "struct Connection {{ closed: bool }} impl Connection {{ {body} }}\n"
    ))
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R01-001`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R01
#[test]
fn state_contract_validates_owned_boolean_typestate() {
    let model = connection_model("fn close(mut self) -> Self { self.closed = true; self }");
    let contracts = load_state_contracts(&model, vec![state_source(&model)])
        .expect("owned state authority resolves");
    assert_eq!(contracts.types().count(), 1);
    assert!(contracts.get_state("STATE-CONNECTION-OPEN").is_some());
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R01-002`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R01
#[test]
fn foreign_state_authority_and_unknown_fields_fail_exactly() {
    let model = connection_model("fn close(mut self) -> Self { self.closed = true; self }");
    let source = state_source(&model);
    let foreign = StateContractSource::new("AF-FOREIGN-0001", source.path(),
        canonicalize_state_contract_json(source.path(), &serde_json::json!({
            "$schema": "urn:fortress:schema:v1:state-contracts", "schema_version": 1,
            "types": [{"type": nominal_id(&model, "Connection"), "states": [{"id": "STATE-FOREIGN", "when": [{"field": "closed", "domain": {"kind": "boolean", "include": [true]}}]}]}]
        }).to_string()).expect("canonical foreign contract"));
    assert!(matches!(
        load_state_contracts(&model, vec![foreign]),
        Err(StateContractError::ForeignType { .. })
    ));

    let raw = serde_json::json!({
        "$schema": "urn:fortress:schema:v1:state-contracts", "schema_version": 1,
        "types": [{"type": nominal_id(&model, "Connection"), "states": [{"id": "STATE-UNKNOWN", "when": [{"field": "missing", "domain": {"kind": "boolean", "include": [true]}}]}]}]
    }).to_string();
    let unknown = StateContractSource::new(
        "AF-SAMPLE-0001",
        "mods/sample/data/state_contracts.json",
        canonicalize_state_contract_json("state_contracts.json", &raw)
            .expect("canonical unknown-field contract"),
    );
    assert!(matches!(
        load_state_contracts(&model, vec![unknown]),
        Err(StateContractError::UnknownField { .. })
    ));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R01-003`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R01
#[test]
fn function_contract_v3_retains_state_and_effect_obligations() {
    let model = connection_model("fn close(mut self) -> Self { self.closed = true; self }");
    let sources = function_sources(
        &model,
        &[(
            "Connection::close",
            &["STATE-CONNECTION-OPEN"],
            &["STATE-CONNECTION-CLOSED"],
            Some(&["receiver_state_write"]),
        )],
    );
    let contracts =
        load_function_contracts(&model, sources).expect("Function Contract v3 resolves");
    let contract = contracts
        .get(&symbol_id(&model, "Connection::close"))
        .expect("contract exists");
    assert_eq!(contract.state_requires().len(), 1);
    assert_eq!(contract.state_ensures().len(), 1);
    assert!(contract.effects().is_some());
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R02-001`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R02
#[test]
fn exact_possible_and_unclassified_states_are_distinct() {
    let model = connection_model(
        "fn close(mut self) -> Self { self.closed = true; self } fn inspect(&self) -> bool { self.closed }",
    );
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(
        &model,
        function_sources(
            &model,
            &[(
                "Connection::close",
                &["STATE-CONNECTION-OPEN"],
                &["STATE-CONNECTION-CLOSED"],
                None,
            )],
        ),
    )
    .expect("functions resolve");
    let value: serde_json::Value = serde_json::from_str(
        &evaluate(&model, &states, &functions)
            .model()
            .to_canonical_json()
            .expect("serializes"),
    )
    .expect("parses");
    assert!(
        value["summaries"]
            .as_array()
            .expect("summaries")
            .iter()
            .any(|summary| summary["output_receiver_state"]["kind"] == "EXACT"),
        "{value}"
    );
    assert!(
        value["summaries"]
            .as_array()
            .expect("summaries")
            .iter()
            .any(|summary| summary["input_receiver_state"]["kind"] == "POSSIBLE")
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R02-002`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R02
#[test]
fn direct_receiver_mutation_proves_state_transition() {
    let model = connection_model("fn close(mut self) -> Self { self.closed = true; self }");
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(
        &model,
        function_sources(
            &model,
            &[(
                "Connection::close",
                &["STATE-CONNECTION-OPEN"],
                &["STATE-CONNECTION-CLOSED"],
                Some(&["receiver_state_write"]),
            )],
        ),
    )
    .expect("functions resolve");
    let evaluation = evaluate(&model, &states, &functions);
    assert!(evaluation.state_findings().is_empty());
    assert!(evaluation.effect_findings().is_empty());
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R02-003`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R02
#[test]
fn opaque_external_mutation_preserves_uncertainty() {
    let model = connection_model(
        "fn touch(&mut self) { std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst); }",
    );
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(&model, Vec::new()).expect("empty contracts resolve");
    let json = evaluate(&model, &states, &functions)
        .model()
        .to_canonical_json()
        .expect("serializes");
    assert!(json.contains("unclassified_external_operation"));
    assert!(json.contains("external_interaction"));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R03-001`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R03
#[test]
fn closed_receiver_cannot_call_open_only_method_after_transition() {
    let model = connection_model(
        "fn close(&mut self) { self.closed = true; } fn send(&self) {} fn run(&mut self) { self.close(); self.send(); }",
    );
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(
        &model,
        function_sources(
            &model,
            &[
                (
                    "Connection::close",
                    &["STATE-CONNECTION-OPEN"],
                    &["STATE-CONNECTION-CLOSED"],
                    None,
                ),
                ("Connection::run", &["STATE-CONNECTION-OPEN"], &[], None),
                ("Connection::send", &["STATE-CONNECTION-OPEN"], &[], None),
            ],
        ),
    )
    .expect("functions resolve");
    let evaluation = evaluate(&model, &states, &functions);
    assert_eq!(evaluation.state_findings().len(), 1);
    assert!(
        evaluation
            .model()
            .to_canonical_json()
            .expect("serializes")
            .contains("STATE-CONNECTION-CLOSED")
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R03-002`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R03
#[test]
fn forbidden_direct_and_transitive_effects_are_reported() {
    let model = connection_model(
        "fn write(&mut self) { self.closed = true; } fn wrapper(&mut self) { self.write(); }",
    );
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(
        &model,
        function_sources(
            &model,
            &[(
                "Connection::wrapper",
                &[],
                &[],
                Some(&["receiver_state_read"]),
            )],
        ),
    )
    .expect("functions resolve");
    let evaluation = evaluate(&model, &states, &functions);
    assert_eq!(evaluation.effect_findings().len(), 1);
    let json = evaluation.model().to_canonical_json().expect("serializes");
    assert!(json.contains("receiver_state_write"));
    assert!(json.contains("Connection::write") || json.contains("rust_symbol"));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R03-003`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R03
#[test]
fn external_panic_and_recursive_effect_coverage_remain_explicit() {
    let model = connection_model(
        "fn recurse(&mut self, stop: bool) { if stop { self.closed = true; } else { self.recurse(true); } } fn fail(&self) { panic!(\"x\"); } fn external(&self) { std::mem::drop(self); }",
    );
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(&model, Vec::new()).expect("empty contracts resolve");
    let json = evaluate(&model, &states, &functions)
        .model()
        .to_canonical_json()
        .expect("serializes");
    assert!(json.contains("may_panic"));
    assert!(json.contains("external_interaction"));
    assert!(json.contains("receiver_state_write"));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R01-004`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R01
#[test]
fn enum_and_option_fields_support_owned_state_authority() {
    let model = psm(
        "enum Phase { Closed, Open } struct EnumMachine { phase: Phase } struct OptionMachine { token: Option<u8> }\n",
    );
    let mut types = vec![
        serde_json::json!({
            "type": nominal_id(&model, "EnumMachine"),
            "states": [
                {"id": "STATE-ENUM-CLOSED", "when": [{"field": "phase", "domain": {"kind": "enum_variants", "include": ["Closed"]}}]},
                {"id": "STATE-ENUM-OPEN", "when": [{"field": "phase", "domain": {"kind": "enum_variants", "include": ["Open"]}}]}
            ]
        }),
        serde_json::json!({
            "type": nominal_id(&model, "OptionMachine"),
            "states": [
                {"id": "STATE-OPTION-NONE", "when": [{"field": "token", "domain": {"kind": "option_states", "include": ["none"], "some": null}}]},
                {"id": "STATE-OPTION-SOME", "when": [{"field": "token", "domain": {"kind": "option_states", "include": ["some"], "some": null}}]}
            ]
        }),
    ];
    types.sort_by(|left, right| left["type"].as_str().cmp(&right["type"].as_str()));
    let contracts = load_state_contracts(
        &model,
        vec![custom_state_source(&serde_json::json!({
            "$schema": "urn:fortress:schema:v1:state-contracts",
            "schema_version": 1,
            "types": types
        }))],
    )
    .expect("enum and Option states resolve");
    assert_eq!(contracts.types().count(), 2);
    assert!(contracts.get_state("STATE-ENUM-OPEN").is_some());
    assert!(contracts.get_state("STATE-OPTION-SOME").is_some());
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R01-005`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R01
#[test]
fn provably_overlapping_states_are_rejected() {
    let model = connection_model("fn inspect(&self) -> bool { self.closed }");
    let source = custom_state_source(&serde_json::json!({
        "$schema": "urn:fortress:schema:v1:state-contracts",
        "schema_version": 1,
        "types": [{
            "type": nominal_id(&model, "Connection"),
            "states": [
                {"id": "STATE-OVERLAP-A", "when": [{"field": "closed", "domain": {"kind": "boolean", "include": [true]}}]},
                {"id": "STATE-OVERLAP-B", "when": [{"field": "closed", "domain": {"kind": "boolean", "include": [false, true]}}]}
            ]
        }]
    }));
    assert!(matches!(
        load_state_contracts(&model, vec![source]),
        Err(StateContractError::OverlappingStates { .. })
    ));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R01-006`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R01
#[test]
fn unknown_function_state_obligation_is_invalid() {
    let model = connection_model("fn inspect(&self) -> bool { self.closed }");
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(
        &model,
        function_sources(
            &model,
            &[("Connection::inspect", &["STATE-MISSING"], &[], None)],
        ),
    )
    .expect("interface-level Function Contract resolves");
    let semantic = analyze_program_domains(&model, &functions, "1.0.0-draft.1")
        .expect("value-domain analysis succeeds");
    assert!(matches!(
        analyze_state_effects(&model, &semantic, &states, &functions, "1.0.0-draft.1"),
        Err(StateEffectAnalysisError::InvalidFunctionState { .. })
    ));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R02-004`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R02
#[test]
fn concrete_domain_outside_partial_state_set_is_unclassified() {
    let model = psm(
        "struct Counter { phase: u8 } impl Counter { fn drift(&mut self) { self.phase = 2; } }\n",
    );
    let states = load_state_contracts(
        &model,
        vec![custom_state_source(&serde_json::json!({
            "$schema": "urn:fortress:schema:v1:state-contracts",
            "schema_version": 1,
            "types": [{
                "type": nominal_id(&model, "Counter"),
                "states": [
                    {"id": "STATE-COUNTER-ONE", "when": [{"field": "phase", "domain": {"kind": "integer_interval", "min": 1, "max": 1, "exclude": []}}]},
                    {"id": "STATE-COUNTER-ZERO", "when": [{"field": "phase", "domain": {"kind": "integer_interval", "min": 0, "max": 0, "exclude": []}}]}
                ]
            }]
        }))],
    )
    .expect("partial integer states resolve");
    let functions = load_function_contracts(&model, Vec::new()).expect("empty functions resolve");
    let json = evaluate(&model, &states, &functions)
        .model()
        .to_canonical_json()
        .expect("serializes");
    assert!(json.contains("\"kind\": \"UNCLASSIFIED\""), "{json}");
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R02-005`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R02
#[test]
fn nonreceiver_field_reads_and_writes_are_owned_effects() {
    let model = psm(
        "struct Owned { ready: bool } fn inspect(value: &Owned) -> bool { value.ready } fn mutate(mut value: Owned) { value.ready = true; }\n",
    );
    let states = load_state_contracts(&model, Vec::new()).expect("empty states resolve");
    let functions = load_function_contracts(&model, Vec::new()).expect("empty functions resolve");
    let json = evaluate(&model, &states, &functions)
        .model()
        .to_canonical_json()
        .expect("serializes");
    assert!(json.contains("owned_state_read"));
    assert!(json.contains("owned_state_write"));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R02-006`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R02
#[test]
fn unresolved_receiver_call_invalidates_precise_state() {
    let model = connection_model("fn touch(&mut self) { self.unknown(); }");
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(&model, Vec::new()).expect("empty functions resolve");
    let json = evaluate(&model, &states, &functions)
        .model()
        .to_canonical_json()
        .expect("serializes");
    assert!(json.contains("receiver_state_invalidated_by_opaque_call"));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R03-004`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R03
#[test]
fn contradictory_state_postcondition_is_rejected() {
    let model = connection_model("fn close(&mut self) { self.closed = false; }");
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(
        &model,
        function_sources(
            &model,
            &[(
                "Connection::close",
                &["STATE-CONNECTION-OPEN"],
                &["STATE-CONNECTION-CLOSED"],
                None,
            )],
        ),
    )
    .expect("functions resolve");
    let evaluation = evaluate(&model, &states, &functions);
    assert_eq!(evaluation.state_findings().len(), 1);
    assert!(
        evaluation
            .model()
            .to_canonical_json()
            .expect("serializes")
            .contains("state postcondition")
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R03-005`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R03
#[test]
fn direct_effect_policies_distinguish_allowed_forbidden_and_pure() {
    let model = psm(
        "struct Connection { closed: bool } impl Connection { fn inspect(&self) -> bool { self.closed } fn write(&mut self) { self.closed = true; } } fn pure(value: bool) -> bool { value }\n",
    );
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(
        &model,
        function_sources(
            &model,
            &[
                (
                    "Connection::inspect",
                    &[],
                    &[],
                    Some(&["receiver_state_read"]),
                ),
                (
                    "Connection::write",
                    &[],
                    &[],
                    Some(&["receiver_state_read"]),
                ),
                ("pure", &[], &[], Some(&[])),
            ],
        ),
    )
    .expect("effect contracts resolve");
    let evaluation = evaluate(&model, &states, &functions);
    assert_eq!(evaluation.effect_findings().len(), 1);
    assert!(
        evaluation
            .model()
            .to_canonical_json()
            .expect("serializes")
            .contains("receiver_state_write")
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R03-006`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R03
#[test]
fn safe_current_caller_does_not_narrow_uncontracted_callee_state() {
    let model = connection_model(
        "fn helper(&self) {} fn forward(&self) { self.helper(); } fn run(&self) { self.forward(); }",
    );
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(
        &model,
        function_sources(
            &model,
            &[
                ("Connection::helper", &["STATE-CONNECTION-OPEN"], &[], None),
                ("Connection::run", &["STATE-CONNECTION-OPEN"], &[], None),
            ],
        ),
    )
    .expect("functions resolve");
    let evaluation = evaluate(&model, &states, &functions);
    assert_eq!(evaluation.state_findings().len(), 1);
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R03-007`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R03
#[test]
fn unsafe_execution_is_explicit_and_policy_checked() {
    let model = connection_model("unsafe fn danger(&mut self) { self.closed = true; }");
    let states = load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
    let functions = load_function_contracts(
        &model,
        function_sources(
            &model,
            &[(
                "Connection::danger",
                &[],
                &[],
                Some(&["receiver_state_write"]),
            )],
        ),
    )
    .expect("functions resolve");
    let evaluation = evaluate(&model, &states, &functions);
    assert_eq!(evaluation.effect_findings().len(), 1);
    assert!(
        evaluation
            .model()
            .to_canonical_json()
            .expect("serializes")
            .contains("unsafe_execution")
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R04-001`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R04
#[test]
fn state_effect_artifact_and_digest_are_deterministic() {
    let model = connection_model("fn close(mut self) -> Self { self.closed = true; self }");
    let run = || {
        let states =
            load_state_contracts(&model, vec![state_source(&model)]).expect("states resolve");
        let functions = load_function_contracts(
            &model,
            function_sources(
                &model,
                &[(
                    "Connection::close",
                    &["STATE-CONNECTION-OPEN"],
                    &["STATE-CONNECTION-CLOSED"],
                    Some(&["receiver_state_write"]),
                )],
            ),
        )
        .expect("functions resolve");
        evaluate(&model, &states, &functions)
    };
    let first = run();
    let second = run();
    assert_eq!(
        first.model().to_canonical_json().expect("first"),
        second.model().to_canonical_json().expect("second")
    );
    assert_eq!(
        first.model().digest().expect("first digest"),
        second.model().digest().expect("second digest")
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R04-002`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R04
#[test]
fn absent_state_semantics_do_not_change_value_domain_findings() {
    let model = psm("fn identity(value: bool) -> bool { value }\n");
    let states = load_state_contracts(&model, Vec::new()).expect("empty states resolve");
    let functions = load_function_contracts(&model, Vec::new()).expect("empty functions resolve");
    let semantic =
        analyze_program_domains(&model, &functions, "1.0.0-draft.1").expect("semantic succeeds");
    let before = semantic.findings().len();
    let state = analyze_state_effects(&model, &semantic, &states, &functions, "1.0.0-draft.1")
        .expect("state succeeds");
    assert_eq!(before, semantic.findings().len());
    assert!(state.state_findings().is_empty());
    assert!(state.effect_findings().is_empty());
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R04-003`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R04
#[test]
fn live_fortress_state_effect_analysis_executes_without_supported_contradictions() {
    let evaluation = compile_repository_state_effect_analysis(repository_root())
        .expect("live State and Effect Analysis compiles");
    assert!(evaluation.state_findings().is_empty());
    assert!(evaluation.effect_findings().is_empty());
    assert!(evaluation.model().coverage().functions() > 0);
    let canonical = evaluation
        .model()
        .to_canonical_json()
        .expect("fresh analysis serializes");
    assert!(canonical.ends_with('\n'));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R05-001`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R05
#[test]
#[allow(clippy::too_many_lines)]
fn refined_effect_ground_truth_exceeds_required_accuracy() {
    let model = psm(r#"
use std::io::{Read, Write};
fn pure(value: u8) -> u8 { value + 1 }
fn filesystem_read() { let _ = std::fs::read("input"); }
fn filesystem_write() { let _ = std::fs::write("output", b"x"); }
fn filesystem_copy() { let _ = std::fs::copy("input", "output"); }
fn filesystem_file_read(mut file: std::fs::File) { let _ = file.read(&mut []); }
fn filesystem_file_write(mut file: std::fs::File) { let _ = file.write(b"x"); }
fn network_connect() { let _ = std::net::TcpStream::connect("127.0.0.1:1"); }
fn network_listen() { let _ = std::net::TcpListener::bind("127.0.0.1:1"); }
fn network_io(mut stream: std::net::TcpStream) { let _ = stream.write(b"x"); let _ = stream.read(&mut []); }
fn process_spawn() { let mut command: std::process::Command = std::process::Command::new("echo"); let _ = command.spawn(); }
fn environment_read() { let _ = std::env::var("HOME"); }
fn environment_write() { unsafe { std::env::set_var("A", "B"); } }
fn wall_time() { let _ = std::time::SystemTime::now(); }
fn monotonic_time() { let _ = std::time::Instant::now(); }
fn random_read() { let mut bytes = [0_u8; 4]; let _ = getrandom::fill(&mut bytes); }
fn panic_macro() { panic!("failure"); }
fn unreachable_macro() { unreachable!(); }
fn todo_macro() { todo!(); }
fn assertion(value: bool) { assert!(value); }
fn unwrap_option(value: Option<u8>) { let _ = value.unwrap(); }
fn expect_result(value: Result<u8, ()>) { let _ = value.expect("value"); }
fn indexing(value: &[u8]) { let _ = value[1]; }
fn division_zero() { let _ = 1 / 0; }
unsafe fn unsafe_function() {}
fn unsafe_block() { unsafe { std::ptr::read(std::ptr::null()); } }
"#);
    let states = load_state_contracts(&model, Vec::new()).expect("empty states resolve");
    let functions = load_function_contracts(&model, Vec::new()).expect("empty functions resolve");
    let evaluation = evaluate(&model, &states, &functions);
    let expected: [(&str, &[FunctionEffect]); 24] = [
        ("filesystem_read", &[FunctionEffect::FilesystemRead]),
        ("filesystem_write", &[FunctionEffect::FilesystemWrite]),
        (
            "filesystem_copy",
            &[
                FunctionEffect::FilesystemRead,
                FunctionEffect::FilesystemWrite,
            ],
        ),
        ("filesystem_file_read", &[FunctionEffect::FilesystemRead]),
        ("filesystem_file_write", &[FunctionEffect::FilesystemWrite]),
        ("network_connect", &[FunctionEffect::NetworkConnect]),
        ("network_listen", &[FunctionEffect::NetworkListen]),
        ("network_io", &[FunctionEffect::NetworkIo]),
        ("process_spawn", &[FunctionEffect::ProcessSpawn]),
        ("environment_read", &[FunctionEffect::EnvironmentRead]),
        ("environment_write", &[FunctionEffect::EnvironmentWrite]),
        ("wall_time", &[FunctionEffect::TimeWallRead]),
        ("monotonic_time", &[FunctionEffect::TimeMonotonicRead]),
        ("random_read", &[FunctionEffect::RandomRead]),
        ("panic_macro", &[FunctionEffect::MayPanic]),
        ("unreachable_macro", &[FunctionEffect::MayPanic]),
        ("todo_macro", &[FunctionEffect::MayPanic]),
        ("assertion", &[FunctionEffect::MayPanic]),
        ("unwrap_option", &[FunctionEffect::MayPanic]),
        ("expect_result", &[FunctionEffect::MayPanic]),
        ("indexing", &[FunctionEffect::MayPanic]),
        ("division_zero", &[FunctionEffect::MayPanic]),
        ("unsafe_function", &[FunctionEffect::UnsafeExecution]),
        ("unsafe_block", &[FunctionEffect::UnsafeExecution]),
    ];
    let mut correct = 0_usize;
    let mut failures = Vec::new();
    for (suffix, effects) in expected {
        let symbol = symbol_id(&model, suffix);
        let summary = evaluation
            .model()
            .summaries()
            .iter()
            .find(|summary| summary.symbol() == symbol)
            .expect("ground-truth summary exists");
        for effect in effects {
            if summary.direct_effects().contains(effect) {
                correct += 1;
            } else {
                failures.push(format!("{suffix}:{}", effect.stable_id()));
            }
        }
        let refined_external = summary
            .direct_effects()
            .iter()
            .copied()
            .filter(|observed| {
                observed.is_external_resource_effect()
                    && *observed != FunctionEffect::ExternalInteraction
            })
            .collect::<Vec<_>>();
        let expected_external = effects
            .iter()
            .copied()
            .filter(|effect| effect.is_external_resource_effect())
            .collect::<Vec<_>>();
        if expected_external.is_empty() {
            assert!(refined_external.is_empty(), "{suffix}:{refined_external:?}");
        } else {
            assert_eq!(refined_external, expected_external, "{suffix}");
        }
    }
    assert!(
        correct * 100 >= 25 * 90,
        "correct={correct} total=25 failures={failures:?}",
    );
    assert_eq!(correct, 25, "failures={failures:?}");
    let pure = symbol_id(&model, "pure");
    assert!(
        evaluation
            .model()
            .summaries()
            .iter()
            .find(|summary| summary.symbol() == pure)
            .expect("pure summary")
            .direct_effects()
            .is_empty()
    );
    let canonical = evaluation
        .model()
        .to_canonical_json()
        .expect("ground truth serializes");
    assert!(canonical.contains("std::fs::read"));
    assert!(canonical.contains("program_semantics.external_target"));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R05-002`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R05
#[test]
fn effect_capability_pairs_are_independently_expressible() {
    assert_ne!(
        FunctionEffect::FilesystemWrite,
        FunctionEffect::NetworkConnect
    );
    assert_ne!(
        FunctionEffect::ProcessSpawn,
        FunctionEffect::EnvironmentRead
    );
    assert_ne!(
        FunctionEffect::EnvironmentRead,
        FunctionEffect::EnvironmentWrite
    );
    assert!(!FunctionEffect::ExternalInteraction.policy_covers(FunctionEffect::UnsafeExecution));
    assert!(FunctionEffect::ExternalInteraction.policy_covers(FunctionEffect::FilesystemRead));
    assert_eq!(
        capability_for_effect(FunctionEffect::FilesystemWrite),
        Some(EffectCapability::Filesystem)
    );
    assert_eq!(
        capability_for_effect(FunctionEffect::NetworkConnect),
        Some(EffectCapability::NetworkClient)
    );
    assert_eq!(
        capability_for_effect(FunctionEffect::NetworkListen),
        Some(EffectCapability::NetworkServer)
    );
    assert_eq!(
        capability_for_effect(FunctionEffect::EnvironmentRead),
        capability_for_effect(FunctionEffect::EnvironmentWrite)
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R05-003`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R05
#[test]
fn legacy_external_policy_is_an_explicit_refined_umbrella() {
    let model = psm("fn write() { let _ = std::fs::write(\"output\", b\"x\"); }\n");
    let states = load_state_contracts(&model, Vec::new()).expect("empty states resolve");
    let legacy = load_function_contracts(
        &model,
        function_sources(
            &model,
            &[("write", &[], &[], Some(&["external_interaction"]))],
        ),
    )
    .expect("legacy umbrella resolves");
    assert!(
        evaluate(&model, &states, &legacy)
            .effect_findings()
            .is_empty()
    );

    let refined = load_function_contracts(
        &model,
        function_sources_v4(&model, &[("write", &[], &[], Some(&["filesystem.write"]))]),
    )
    .expect("refined policy resolves");
    assert!(
        evaluate(&model, &states, &refined)
            .effect_findings()
            .is_empty()
    );

    let wrong = load_function_contracts(
        &model,
        function_sources_v4(&model, &[("write", &[], &[], Some(&["network.connect"]))]),
    )
    .expect("distinct policy resolves");
    assert_eq!(evaluate(&model, &states, &wrong).effect_findings().len(), 1);

    let raw = serde_json::json!({
        "$schema": "urn:fortress:schema:v3:function-contracts",
        "schema_version": 3,
        "functions": [{
            "symbol": symbol_id(&model, "write"), "requires": [], "ensures": [],
            "state_requires": [], "state_ensures": [],
            "effects": {"allowed": ["filesystem.write"]}
        }]
    })
    .to_string();
    assert!(matches!(
        canonicalize_function_contract_json("legacy.json", &raw),
        Err(FunctionContractError::EffectRequiresV4 { .. })
    ));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R05-004`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R05
#[test]
fn panic_and_unsafe_structure_is_detected_in_nested_positions() {
    let model = psm(
        "fn nested(value: Option<u8>) -> u8 { let item = value.expect(\"item\"); if item > 0 { assert!(item < 10); } unsafe { std::ptr::read(&item) } }\n",
    );
    let states = load_state_contracts(&model, Vec::new()).expect("empty states resolve");
    let functions = load_function_contracts(&model, Vec::new()).expect("empty functions resolve");
    let evaluation = evaluate(&model, &states, &functions);
    let summary = evaluation
        .model()
        .summaries()
        .iter()
        .find(|summary| summary.symbol() == symbol_id(&model, "nested"))
        .expect("nested summary");
    assert!(summary.direct_effects().contains(&FunctionEffect::MayPanic));
    assert!(
        summary
            .direct_effects()
            .contains(&FunctionEffect::UnsafeExecution)
    );
    assert!(
        summary
            .effect_evidence()
            .iter()
            .any(|evidence| evidence.operation() == "rust.unsafe_block")
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R05-005`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R05
#[test]
fn two_hop_effect_closure_retains_origin_and_call_chain() {
    let model = psm(r#"
fn filesystem_origin() { let _ = std::fs::write("output", b"x"); }
fn filesystem_helper() { filesystem_origin(); }
fn filesystem_entry() { filesystem_helper(); }
fn network_origin() { let _ = std::net::TcpStream::connect("127.0.0.1:1"); }
fn network_helper() { network_origin(); }
fn network_entry() { network_helper(); }
fn process_origin() { let mut command: std::process::Command = std::process::Command::new("echo"); let _ = command.spawn(); }
fn process_helper() { process_origin(); }
fn process_entry() { process_helper(); }
fn environment_origin() { let _ = std::env::var("HOME"); }
fn environment_helper() { environment_origin(); }
fn environment_entry() { environment_helper(); }
fn time_origin() { let _ = std::time::Instant::now(); }
fn time_helper() { time_origin(); }
fn time_entry() { time_helper(); }
fn random_origin() { let mut bytes = [0_u8; 4]; let _ = getrandom::fill(&mut bytes); }
fn random_helper() { random_origin(); }
fn random_entry() { random_helper(); }
fn panic_origin() { panic!("failure"); }
fn panic_helper() { panic_origin(); }
fn panic_entry() { panic_helper(); }
fn unsafe_origin() { unsafe { std::ptr::read(std::ptr::null::<u8>()); } }
fn unsafe_helper() { unsafe_origin(); }
fn unsafe_entry() { unsafe_helper(); }
"#);
    let states = load_state_contracts(&model, Vec::new()).expect("empty states resolve");
    let functions = load_function_contracts(&model, Vec::new()).expect("empty functions resolve");
    let evaluation = evaluate(&model, &states, &functions);
    let cases = [
        ("filesystem", FunctionEffect::FilesystemWrite),
        ("network", FunctionEffect::NetworkConnect),
        ("process", FunctionEffect::ProcessSpawn),
        ("environment", FunctionEffect::EnvironmentRead),
        ("time", FunctionEffect::TimeMonotonicRead),
        ("random", FunctionEffect::RandomRead),
        ("panic", FunctionEffect::MayPanic),
        ("unsafe", FunctionEffect::UnsafeExecution),
    ];
    for (name, effect) in cases {
        let entry = symbol_id(&model, &format!("{name}_entry"));
        let origin = symbol_id(&model, &format!("{name}_origin"));
        let summary = evaluation
            .model()
            .summaries()
            .iter()
            .find(|summary| summary.symbol() == entry)
            .expect("entry summary");
        assert!(summary.transitive_effects().contains(&effect), "{name}");
        let evidence = summary
            .effect_evidence()
            .iter()
            .find(|evidence| evidence.effect() == effect)
            .expect("transitive evidence");
        assert_eq!(evidence.kind(), EffectEvidenceKind::Transitive);
        assert_eq!(evidence.entry_symbol(), entry);
        assert_eq!(evidence.source_symbol(), origin);
        assert_eq!(evidence.call_chain().len(), 3);
        assert_eq!(evidence.capability(), capability_for_effect(effect));
    }
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R05-006`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R05
#[test]
fn unresolved_method_names_never_gain_refined_specificity() {
    let model = psm(
        "struct Writer; impl Writer { fn write(&self) {} fn unwrap(&self) {} } fn unknown<T>(value: T) { value.write(); } fn local(value: Writer) { value.write(); value.unwrap(); } fn foreign_file(value: getrandom::File) { value.write(); }\n",
    );
    let states = load_state_contracts(&model, Vec::new()).expect("empty states resolve");
    let functions = load_function_contracts(&model, Vec::new()).expect("empty functions resolve");
    let evaluation = evaluate(&model, &states, &functions);
    for suffix in ["unknown", "local", "foreign_file"] {
        let symbol = symbol_id(&model, suffix);
        let summary = evaluation
            .model()
            .summaries()
            .iter()
            .find(|summary| summary.symbol() == symbol)
            .expect("summary exists");
        assert!(
            !summary
                .direct_effects()
                .contains(&FunctionEffect::FilesystemWrite)
        );
        assert!(
            !summary
                .direct_effects()
                .contains(&FunctionEffect::NetworkIo)
        );
        assert!(!summary.direct_effects().contains(&FunctionEffect::MayPanic));
    }
}
