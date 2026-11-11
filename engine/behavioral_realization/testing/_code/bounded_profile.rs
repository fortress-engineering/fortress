//! Bounded checkpoint qualification from independently authored workflow sources.
use fortress_core::behavioral_realization::{
    BehaviorRealizationContractSource, BehaviorSelection,
    canonicalize_behavior_realization_contract_json, compile_bounded_behavior,
    load_behavior_realization_contracts,
};
use fortress_core::behavioral_semantics::compile_intended_bfg;
use fortress_core::contract_coherency::{
    ContractStandardIndex, ModuleContract, compile_contract_coherency_graph,
};
use fortress_core::environmental_semantics::{
    analyze_environmental_semantics, load_environment_contracts,
};
use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::information_flow::{analyze_information_flow, load_information_flow_policy};
use fortress_core::program_semantics::{ProgramSemanticInput, compile_program_semantic_model};
use fortress_core::semantic_analysis::{analyze_program_domains, load_function_contracts};
use fortress_core::state_effect_analysis::{analyze_state_effects, load_state_contracts};
use serde_json::{Value, json};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
const EDITION: &str = "1.0.0-draft.2";
fn evaluate(source: &str, selected: bool) -> Value {
    evaluate_mode(source, selected, 0, "authorize", "mutate")
}
fn evaluate_mode(source: &str, selected: bool, mode: u8, first: &str, second: &str) -> Value {
    let WorkflowFixture {
        ccg,
        intended,
        input,
        authenticate,
    } = workflow_fixture(source, mode == 5);
    let psm = prepare_mode(&input, mode);
    let functions = workflow_functions(&psm, mode);
    let semantic = analyze_program_domains(&psm, &functions, EDITION).unwrap();
    let states = load_state_contracts(&psm, vec![]).unwrap();
    let effects = analyze_state_effects(&psm, &semantic, &states, &functions, EDITION).unwrap();
    let policy = load_information_flow_policy(vec![]).unwrap();
    let flow =
        analyze_information_flow(&psm, &semantic, &effects, &policy, &functions, EDITION).unwrap();
    let environments = load_environment_contracts(&psm, &states, &policy, vec![]).unwrap();
    let environment = analyze_environmental_semantics(
        &psm,
        &semantic,
        &effects,
        &flow,
        &environments,
        &functions,
        EDITION,
    )
    .unwrap();
    let source = workflow_bindings(&psm, first, second, authenticate, mode);
    let bindings = load_behavior_realization_contracts(
        &ccg,
        &intended,
        &psm,
        effects.model(),
        flow.model(),
        environment.model(),
        vec![BehaviorRealizationContractSource::new(
            "PF-BEHAVIOR-FIXTURE",
            "_data/behavior_realization_contracts.json",
            source,
        )],
    )
    .unwrap();
    assert_readable_preview(&psm, first, second);
    if mode == 4 {
        let different = input.clone().with_selected_context(
            "sample/library:sample",
            ["extra"],
            ["feature=extra"],
            "x86_64-pc-windows-msvc",
        );
        let different = compile_program_semantic_model(&different).unwrap();
        assert!(
            compile_bounded_behavior(
                &ccg,
                &intended,
                &different,
                semantic.model(),
                effects.model(),
                flow.model(),
                environment.model(),
                &bindings,
                &BehaviorSelection {
                    project: true,
                    modules: BTreeSet::new()
                }
            )
            .is_err()
        );
    }
    let result = compile_bounded_behavior(
        &ccg,
        &intended,
        &psm,
        semantic.model(),
        effects.model(),
        flow.model(),
        environment.model(),
        &bindings,
        &BehaviorSelection {
            project: selected,
            modules: BTreeSet::new(),
        },
    )
    .unwrap();
    let value = serde_json::to_value(&result).unwrap();
    for claim in result.claims() {
        fortress_core::behavioral_realization::validate_behavior_claim_projection(
            claim,
            &psm.program_context().digest(),
        )
        .unwrap();
    }
    value
}
fn claim(value: &Value) -> &Value {
    &value["claims"][0]
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-001`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn supported_authorization_bypass_has_counterexample() {
    let v = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(){mutate();authorize();}",
        true,
    );
    assert_eq!(claim(&v)["verdict"], "SUPPORTED_VIOLATION");
    assert!(!claim(&v)["counterexample"].as_array().unwrap().is_empty());
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-002`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn compliant_complete_path_satisfies_bounded_requirement() {
    let v = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(){authorize();mutate();}",
        true,
    );
    assert_eq!(claim(&v)["verdict"], "NO_SUPPORTED_VIOLATION");
    assert_eq!(claim(&v)["coverage"]["complete"], true);
    assert_eq!(claim(&v)["execution_evidence"], "NOT_SUPPLIED");
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-003`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn unresolved_path_prevents_no_bypass_claim() {
    let v = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(callback:fn()){authorize();callback();mutate();}",
        true,
    );
    assert_eq!(claim(&v)["verdict"], "NOT_EVALUABLE");
    assert!(!claim(&v)["defeaters"].as_array().unwrap().is_empty());
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-004`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn unselected_behavior_is_not_pass() {
    let v = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(){authorize();mutate();}",
        false,
    );
    assert_eq!(claim(&v)["verdict"], "NOT_APPLICABLE");
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-005`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn early_return_bypass_is_supported() {
    let v = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(){authorize();return;mutate();}",
        true,
    );
    assert_eq!(claim(&v)["verdict"], "SUPPORTED_VIOLATION");
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-006`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn opaque_guard_is_not_clean() {
    let v = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(flag:bool){if flag{authorize();}mutate();}",
        true,
    );
    assert_eq!(claim(&v)["verdict"], "NOT_EVALUABLE");
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-007`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn literal_branch_is_exact() {
    let v = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(){if true{authorize();}mutate();}",
        true,
    );
    assert_eq!(claim(&v)["verdict"], "NO_SUPPORTED_VIOLATION");
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-008`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn static_claim_never_asserts_runtime_execution() {
    let v = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(){authorize();mutate();}",
        true,
    );
    assert_eq!(claim(&v)["execution_evidence"], "NOT_SUPPLIED");
    assert_eq!(claim(&v)["authorization"], "NOT_ESTABLISHED");
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-009`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn external_bounded_profile_is_authorable() {
    for (source, first, second, verdict) in [
        (
            "fn persist(){} fn confirm(){} fn entry(){persist();confirm();}",
            "persist",
            "confirm",
            "NO_SUPPORTED_VIOLATION",
        ),
        (
            "fn persist(){} fn confirm(){} fn entry(){confirm();persist();}",
            "persist",
            "confirm",
            "SUPPORTED_VIOLATION",
        ),
    ] {
        assert_eq!(
            claim(&evaluate_mode(source, true, 0, first, second))["verdict"],
            verdict
        );
    }
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-010`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn test_execution_does_not_replace_static_realization() {
    let value = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(callback:fn()){authorize();callback();mutate();}",
        true,
    );
    assert_eq!(claim(&value)["verdict"], "NOT_EVALUABLE");
    assert_eq!(claim(&value)["execution_evidence"], "NOT_SUPPLIED");
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-011`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn cold_prepared_reused_results_are_identical() {
    let source = "fn authorize(){} fn mutate(){} fn entry(){authorize();mutate();}";
    let cold = evaluate(source, true);
    for mode in [1, 2, 3] {
        assert_eq!(
            cold,
            evaluate_mode(source, true, mode, "authorize", "mutate")
        );
    }
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-012`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn frozen_workflow_corpus_preserves_supported_and_unknown_meanings() {
    let corpus: Value =
        serde_json::from_str(include_str!("../_data/bounded_cases_v1.json")).unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        let value = evaluate(case["source"].as_str().unwrap(), true);
        assert_eq!(
            claim(&value)["verdict"],
            case["expected_verdict"],
            "{}",
            case["id"]
        );
    }
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-013`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn repeated_checkpoint_is_not_silently_collapsed() {
    let value = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(){authorize();authorize();mutate();}",
        true,
    );
    assert_ne!(claim(&value)["verdict"], "NO_SUPPORTED_VIOLATION");
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-014`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn nested_call_contexts_return_to_their_own_call_sites() {
    let value = evaluate(
        "fn authorize(){} fn mutate(){} fn helper(){authorize();} fn entry(){helper();mutate();}",
        true,
    );
    assert_eq!(claim(&value)["verdict"], "NO_SUPPORTED_VIOLATION");
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-015`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn supported_counterexample_survives_a_later_unresolved_call() {
    let value = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(callback:fn()){mutate();callback();authorize();}",
        true,
    );
    assert_eq!(claim(&value)["verdict"], "SUPPORTED_VIOLATION");
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-016`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn tampered_projection_does_not_turn_unknown_into_pass() {
    let value = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(callback:fn()){authorize();callback();mutate();}",
        true,
    );
    let mut c = claim(&value).clone();
    let context = c["context_ref"].as_str().unwrap().to_owned();
    c["verdict"] = json!("NO_SUPPORTED_VIOLATION");
    assert!(
        fortress_core::behavioral_realization::validate_behavior_claim_projection(&c, &context)
            .is_err()
    );
    c["verdict"] = json!("NOT_EVALUABLE");
    c["instance_ref"] = json!("sha256:forged");
    assert!(
        fortress_core::behavioral_realization::validate_behavior_claim_projection(&c, &context)
            .is_err()
    );
}

fn selector_model(source: &str) -> fortress_core::program_semantics::ProgramSemanticModel {
    let input=ProgramSemanticInput::new("PF-SELECTOR-FIXTURE",ImplementationObservationInput::new("sha256:selector-fixture",vec![SnapshotBoundFile::from_bytes("sample/_data/Cargo.toml",b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n"),SnapshotBoundFile::from_bytes("sample/_code/lib.rs",source.as_bytes())],vec![ModuleTerritory::new("AF-SAMPLE-0001","sample")]),Vec::<String>::new(),Vec::<(String,String)>::new());
    compile_program_semantic_model(&input).unwrap()
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-017`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn parameter_rename_keeps_anchor() {
    let a = selector_model("fn work(token:u32){}");
    let b = selector_model("// shifted\nfn work(renamed:u32){}");
    let ar = a.symbol_reference_index();
    let br = b.symbol_reference_index();
    assert_eq!(
        ar.resolve_readable("sample::work")
            .unwrap()
            .unwrap()
            .symbol()
            .id(),
        br.resolve_readable("sample::work")
            .unwrap()
            .unwrap()
            .symbol()
            .id()
    );
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-018`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn checkpoint_selector_ambiguity_is_explicit() {
    let model = selector_model(
        "trait Left{fn run(&self);} trait Right{fn run(&self);} struct Item;impl Left for Item{fn run(&self){}} impl Right for Item{fn run(&self){}}",
    );
    let names = model
        .symbols()
        .iter()
        .map(fortress_core::program_semantics::ExecutableSymbol::qualified_name)
        .collect::<BTreeSet<_>>();
    let mut ambiguous = false;
    for name in names {
        let count = model
            .symbols()
            .iter()
            .filter(|s| s.qualified_name() == name)
            .count();
        if count > 1 {
            ambiguous = true;
            assert!(
                model
                    .symbol_reference_index()
                    .resolve_readable(name)
                    .is_err()
            );
        }
    }
    assert!(
        ambiguous,
        "fixture must contain duplicate qualified selectors"
    );
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-019`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn supplemental_workflows_match_independent_source_controls() {
    let corpus: Value =
        serde_json::from_str(include_str!("../_data/bounded_addendum_v1.json")).unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        let persist = case["id"].as_str().unwrap().contains("persist");
        let value = evaluate_mode(
            case["source"].as_str().unwrap(),
            true,
            0,
            if persist { "persist" } else { "authorize" },
            if persist { "confirm" } else { "mutate" },
        );
        assert_eq!(
            claim(&value)["verdict"],
            case["expected_verdict"],
            "{}",
            case["id"]
        );
    }
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-020`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn test_only_bypass_does_not_gain_production_blocking_authority() {
    let value = evaluate(
        "fn authorize(){} fn mutate(){} #[cfg(test)] fn entry(){mutate();authorize();}",
        true,
    );
    if claim(&value)["verdict"] == "SUPPORTED_VIOLATION" {
        assert_eq!(
            value["findings"][0]["enforcement_eligibility"],
            "ADVISORY_ONLY"
        );
    } else {
        assert_eq!(claim(&value)["verdict"], "NOT_EVALUABLE");
    }
}

fn prepare_mode(
    input: &ProgramSemanticInput,
    mode: u8,
) -> fortress_core::program_semantics::ProgramSemanticModel {
    if mode == 0 {
        compile_program_semantic_model(input).unwrap()
    } else {
        let cold =
            fortress_core::program_semantics::prepare_program_semantics(input, None).unwrap();
        if mode == 1 {
            cold.model
        } else if mode == 3 {
            let changed = input.clone().with_selected_context(
                "sample/library:sample",
                ["extra"],
                ["feature=extra"],
                "x86_64-pc-windows-msvc",
            );
            let unrelated =
                fortress_core::program_semantics::prepare_program_semantics(&changed, None)
                    .unwrap();
            let fallback = fortress_core::program_semantics::prepare_program_semantics(
                input,
                Some(&unrelated.preparation),
            )
            .unwrap();
            assert!(fallback.fallback.is_some());
            fallback.model
        } else {
            fortress_core::program_semantics::prepare_program_semantics(
                input,
                Some(&cold.preparation),
            )
            .unwrap()
            .model
        }
    }
}

fn assert_readable_preview(
    psm: &fortress_core::program_semantics::ProgramSemanticModel,
    first: &str,
    second: &str,
) {
    let preview = fortress_core::behavioral_realization::preview_behavior_contract(
        psm,
        &fortress_core::behavioral_realization::BehaviorAuthorParameters {
            feature: "AF-WORKFLOW-0001".into(),
            checkpoints: BTreeMap::from([
                ("CHK-START".into(), "sample::entry".into()),
                ("CHK-AUTH".into(), format!("sample::{first}")),
                ("CHK-MUTATE".into(), format!("sample::{second}")),
                ("CHK-END".into(), "sample::entry".into()),
            ]),
            returns: BTreeSet::from(["CHK-END".into()]),
        },
    )
    .unwrap();
    assert_eq!(preview["disposition"], "PROPOSED");
    assert_eq!(preview["accepted_authority"], false);
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-021`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn cosmetic_source_changes_preserve_the_original_violated_obligation_identity() {
    let a = evaluate(
        "fn authorize(token:u32){} fn mutate(){} fn entry(){mutate();authorize(7);}",
        true,
    );
    let b = evaluate(
        "// relocated source line\nfn authorize(renamed:u32){} fn mutate(){} fn entry(){mutate();authorize(7);}",
        true,
    );
    assert_eq!(
        a["findings"][0]["finding_id"].as_str().unwrap(),
        b["findings"][0]["finding_id"].as_str().unwrap()
    );
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-022`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn malformed_authoring_cannot_become_accepted_authority() {
    use fortress_core::behavioral_realization::BehaviorAuthorParameters;
    let duplicate = r#"{"feature":"AF-WORKFLOW-0001","checkpoints":{"CHK-START":"sample::entry"},"returns":["CHK-START","CHK-START"]}"#;
    assert!(serde_json::from_str::<BehaviorAuthorParameters>(duplicate).is_err());
    for value in [
        json!({"feature":"../escape","checkpoints":{"CHK-START":"sample::entry"}}),
        json!({"feature":"AF-WORKFLOW-0001","checkpoints":{}}),
        json!({"feature":"AF-WORKFLOW-0001","checkpoints":{"CHK-START":"sample::entry"},"returns":["CHK-OTHER"]}),
    ] {
        let params: BehaviorAuthorParameters = serde_json::from_value(value).unwrap();
        assert!(params.validate_shape().is_err());
    }
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-023`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn substituted_context_cannot_reuse_original_semantic_evidence() {
    evaluate_mode(
        "fn authorize(){} fn mutate(){} fn entry(){authorize();mutate();}",
        true,
        4,
        "authorize",
        "mutate",
    );
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-024`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn unmodeled_feature_is_explicitly_unevaluable() {
    let value = evaluate_mode(
        "fn authorize(){} fn mutate(){} fn entry(){authorize();mutate();}",
        true,
        5,
        "authorize",
        "mutate",
    );
    assert_eq!(claim(&value)["verdict"], "NOT_EVALUABLE");
    assert!(
        claim(&value)["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&json!("UNMODELED_FEATURE"))
    );
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-025`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn recursive_control_does_not_establish_terminal_or_bypass_absence() {
    let value = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(){entry();authorize();mutate();}",
        true,
    );
    assert_eq!(claim(&value)["verdict"], "NOT_EVALUABLE");
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-026`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn external_outcome_and_effect_summaries_do_not_establish_complete_execution() {
    let value = evaluate(
        "fn authorize(){} fn mutate(){} fn entry(){authorize();let _=std::fs::read(\"input\");mutate();}",
        true,
    );
    assert_eq!(claim(&value)["verdict"], "NOT_EVALUABLE");
    assert_eq!(claim(&value)["execution_evidence"], "NOT_SUPPLIED");
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-027`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn constructing_an_async_entry_is_not_execution_of_its_checkpoint_path() {
    let value = evaluate(
        "fn authorize(){} fn mutate(){} async fn entry(){authorize();mutate();}",
        true,
    );
    assert_eq!(claim(&value)["verdict"], "NOT_EVALUABLE");
}

struct WorkflowFixture {
    ccg: fortress_core::contract_coherency::ContractCoherencyGraph,
    intended: fortress_core::behavioral_semantics::IntendedBehavioralFlowGraph,
    input: ProgramSemanticInput,
    authenticate: bool,
}
fn workflow_fixture(source: &str, unmodeled: bool) -> WorkflowFixture {
    let mut contract = json!({"$schema":"urn:fortress:schema:v2:module-contract","schema_version":2,"id":"PF-BEHAVIOR-FIXTURE","display_name":"Workflow","ecosystem":{"repository_grammar":1,"standard":{"id":"STD-FORTRESS-ENGINEERING","edition":EDITION}},"provides":[],"requires":[],"relationships":[],"constraints":[],"guarantees":[],"features":[{"id":"AF-WORKFLOW-0001","version":"0.1.0","requirements":[]}],"behavior":[{"id":"CHK-START","feature":"AF-WORKFLOW-0001","kind":"trigger","transitions":[{"target":"CHK-AUTH"}]},{"id":"CHK-AUTH","feature":"AF-WORKFLOW-0001","kind":"action","transitions":[{"target":"CHK-MUTATE"}]},{"id":"CHK-MUTATE","feature":"AF-WORKFLOW-0001","kind":"action","transitions":[{"target":"CHK-END"}]},{"id":"CHK-END","feature":"AF-WORKFLOW-0001","kind":"terminal","outcome":"completed","transitions":[]}]});
    let authenticate = source.contains("fn authenticate");
    if authenticate {
        contract["behavior"][0]["transitions"][0]["target"] = json!("CHK-IDENTITY");
        contract["behavior"].as_array_mut().unwrap().push(json!({"id":"CHK-IDENTITY","feature":"AF-WORKFLOW-0001","kind":"action","transitions":[{"target":"CHK-AUTH"}]}));
    }
    if unmodeled {
        contract["behavior"] = json!([]);
    }
    contract["behavior"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let contract: ModuleContract = serde_json::from_value(contract).unwrap();
    let files=BTreeMap::from([("contract.json".into(),contract.to_canonical_json().unwrap().into_bytes()),("_data/Cargo.toml".into(),b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../code/lib.rs'\n".to_vec()),("code/lib.rs".into(),source.as_bytes().to_vec())]);
    let index =
        ContractStandardIndex::new("STD-FORTRESS-ENGINEERING", EDITION, ["BEHAVIOR-FLOW-001"]);
    let compilation = compile_contract_coherency_graph(&files, &index, None);
    let ccg = compilation
        .graph()
        .unwrap_or_else(|| panic!("{:?}", compilation.violations()))
        .clone();
    let intended = compile_intended_bfg(&ccg).unwrap();
    let input = ProgramSemanticInput::new(
        "PF-BEHAVIOR-FIXTURE",
        ImplementationObservationInput::new(
            format!("sha256:{:x}", sha2::Sha256::digest(source.as_bytes())),
            files
                .iter()
                .map(|(p, b)| SnapshotBoundFile::from_bytes(p, b.clone()))
                .collect(),
            vec![ModuleTerritory::new("PF-BEHAVIOR-FIXTURE", "")],
        ),
        Vec::<String>::new(),
        Vec::<(String, String)>::new(),
    );
    WorkflowFixture {
        ccg,
        intended,
        input,
        authenticate,
    }
}

fn workflow_bindings(
    psm: &fortress_core::program_semantics::ProgramSemanticModel,
    first: &str,
    second: &str,
    authenticate: bool,
    mode: u8,
) -> String {
    let mut source = json!({"$schema":"urn:fortress:schema:v3:behavior-realization-contracts","schema_version":3,"context_ref":psm.program_context().digest(),"features":[{"feature":"AF-WORKFLOW-0001","checkpoints":[{"checkpoint":"CHK-AUTH","anchors":[{"kind":"symbol_entry","symbol":format!("sample::{first}")}]},{"checkpoint":"CHK-END","anchors":[{"kind":"symbol_return","symbol":"sample::entry"}]},{"checkpoint":"CHK-MUTATE","anchors":[{"kind":"symbol_entry","symbol":format!("sample::{second}")}]},{"checkpoint":"CHK-START","anchors":[{"kind":"symbol_entry","symbol":"sample::entry"}]}]}]});
    if authenticate {
        source["features"][0]["checkpoints"].as_array_mut().unwrap().push(json!({"checkpoint":"CHK-IDENTITY","anchors":[{"kind":"symbol_entry","symbol":"sample::authenticate"}]}));
        source["features"][0]["checkpoints"]
            .as_array_mut()
            .unwrap()
            .sort_by(|a, b| a["checkpoint"].as_str().cmp(&b["checkpoint"].as_str()));
    }
    if mode == 5 {
        source["features"] = json!([]);
    }
    if mode == 7 {
        source["features"][0]["checkpoints"][0]["anchors"][0] =
            json!({"kind":"symbol_return","symbol":"sample::authorize","boolean":false});
    }
    if mode == 6 {
        source["features"][0]["checkpoints"][1]["anchors"][0]["boolean"] = json!(false);
    }
    let source = source.to_string();
    canonicalize_behavior_realization_contract_json(&source).unwrap()
}

fn workflow_functions(
    psm: &fortress_core::program_semantics::ProgramSemanticModel,
    mode: u8,
) -> fortress_core::semantic_analysis::ResolvedFunctionContracts {
    let sources = if mode == 6 {
        let symbol = psm
            .symbol_reference_index()
            .resolve_readable("sample::entry")
            .unwrap()
            .unwrap()
            .symbol()
            .id()
            .to_owned();
        let value = json!({"$schema":"urn:fortress:schema:v3:function-contracts","schema_version":3,"functions":[{"symbol":symbol,"requires":[{"parameter":"flag","domain":{"kind":"boolean","include":[false]}}],"ensures":[],"state_requires":[],"state_ensures":[],"effects":null,"information_flow":null}]});
        let source = fortress_core::semantic_analysis::canonicalize_function_contract_json(
            "fixture",
            &value.to_string(),
        )
        .unwrap();
        vec![
            fortress_core::semantic_analysis::FunctionContractSource::new(
                "PF-BEHAVIOR-FIXTURE",
                "_data/function_contracts.json",
                source,
            ),
        ]
    } else {
        vec![]
    };
    load_function_contracts(psm, sources).unwrap()
}
/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-028`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn declared_value_premises_do_not_prove_a_refined_terminal_outcome() {
    let value = evaluate_mode(
        "fn authorize(){} fn mutate(){} fn entry(flag:bool)->bool{authorize();mutate();flag}",
        true,
        6,
        "authorize",
        "mutate",
    );
    assert_eq!(claim(&value)["verdict"], "NOT_EVALUABLE");
    assert_eq!(
        claim(&value)["coverage"]["unsupported_anchors"],
        json!(["CHK-END"])
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-029`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn supported_prefix_bypass_survives_an_unproved_terminal_anchor() {
    let value = evaluate_mode(
        "fn authorize(){} fn mutate(){} fn entry(flag:bool)->bool{mutate();authorize();flag}",
        true,
        6,
        "authorize",
        "mutate",
    );
    assert_eq!(claim(&value)["verdict"], "SUPPORTED_VIOLATION");
    assert!(
        !claim(&value)["counterexample"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!claim(&value)["defeaters"].as_array().unwrap().is_empty());
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R05-030`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R05
#[test]
fn unproved_dominator_anchor_is_not_proof_of_bypass() {
    let value = evaluate_mode(
        "fn authorize(flag:bool)->bool{flag} fn mutate(){} fn entry(flag:bool){let _=authorize(flag);mutate();}",
        true,
        7,
        "authorize",
        "mutate",
    );
    assert_eq!(claim(&value)["verdict"], "NOT_EVALUABLE");
    assert!(claim(&value)["findings"].as_array().unwrap().is_empty());
}
