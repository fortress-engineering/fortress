//! Exact-source operation-summary and retained source-review controls.

use std::collections::{BTreeMap, BTreeSet};

use fortress_core::architecture_realization::reconcile_implementation;
use fortress_core::contract_coherency::{
    ContractStandardIndex, ModuleContract, compile_contract_coherency_graph,
};
use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile, observe_rust_implementation,
};
use fortress_core::program_semantics::{
    ContextKnowledge, ProgramSemanticInput, ProgramSemanticModel, SemanticType,
    compile_program_semantic_model,
};
use fortress_core::semantic_analysis::{
    FunctionEffect, analyze_program_domains, load_function_contracts,
};
use fortress_core::semantic_conformance::{
    SemanticConformanceEvaluation, evaluate_semantic_conformance,
};
use fortress_core::state_effect_analysis::{
    OperationClassificationState, OperationSummaryCatalog, OperationSummaryInstantiation,
    StateEffectAnalysisError, StateEffectAnalysisModel, StateEffectSummary, SummaryAcceptance,
    SummaryAuthorityClass, SummaryContext, SummaryEffectBound, SummaryPremise,
    analyze_state_effects, analyze_state_effects_with_summaries, load_state_contracts,
    local_callback_premise, primitive_destructor_premise,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CATALOG: &str = fortress_core::standard::installed_operation_summaries();
const COMPARISON: &str = include_str!("../_data/operation_summary_qualification_v1.json");
const CONSTRUCTOR: &str = "std::fs::OpenOptions::new";
const DROP: &str = "std::mem::drop";
const CALLBACK: &str = "rust_method::Option::is_some_and";
const RUST_SOURCE_ARCHIVE: &str =
    "sha256:59f02b4f23fd8d7193a3cb17ea192255ccf02f1109783d7988521334891d27ae";

fn catalog() -> OperationSummaryCatalog {
    OperationSummaryCatalog::from_json_str(CATALOG).expect("installed summary catalog validates")
}

fn catalog_value() -> Value {
    serde_json::from_str(CATALOG).expect("catalog is JSON")
}

fn summary_value(operation: &str) -> Value {
    catalog_value()["summaries"]
        .as_array()
        .expect("summary array")
        .iter()
        .find(|entry| entry["operation_selector"] == operation)
        .expect("reviewed operation exists")
        .clone()
}

fn selected_catalog(summary: &Value) -> OperationSummaryCatalog {
    let mut document = catalog_value();
    document["summaries"] = json!([summary]);
    OperationSummaryCatalog::from_json_str(&document.to_string()).expect("test catalog validates")
}

fn context(operation: &str) -> SummaryContext {
    let entry = summary_value(operation);
    SummaryContext {
        source_digest: ContextKnowledge::Known(
            entry["toolchain_or_package_source_digest"]
                .as_str()
                .expect("source digest")
                .into(),
        ),
        version: ContextKnowledge::Known(
            entry["supported_versions"][0]
                .as_str()
                .expect("version")
                .into(),
        ),
        target: ContextKnowledge::Known("x86_64-pc-windows-msvc".into()),
        features: ContextKnowledge::Known(Vec::new()),
        type_bindings: ContextKnowledge::Known(
            serde_json::from_value(entry["type_constraints"].clone()).expect("type binding set"),
        ),
    }
}

fn psm_input(source: &str) -> ProgramSemanticInput {
    ProgramSemanticInput::new(
        "PF-SUMMARY-FIXTURE",
        ImplementationObservationInput::new(
            "sha256:fixture",
            vec![
                SnapshotBoundFile::from_bytes(
                    "sample/_data/Cargo.toml",
                    b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n[dependencies]\ngetrandom='0.3'\nunsupported_dependency='1'\n",
                ),
                SnapshotBoundFile::from_bytes("sample/_code/lib.rs", source.as_bytes()),
            ],
            vec![
                ModuleTerritory::new("PF-SUMMARY-FIXTURE", ""),
                ModuleTerritory::new("AF-SAMPLE-0001", "sample"),
            ],
        ),
        Vec::<String>::new(),
        Vec::<(String, String)>::new(),
    )
}

fn psm(source: &str) -> ProgramSemanticModel {
    compile_program_semantic_model(&psm_input(source)).expect("source-review fixture PSM compiles")
}

fn premise(bound: Vec<FunctionEffect>, refs: Vec<String>) -> SummaryPremise {
    SummaryPremise {
        bound: SummaryEffectBound::Known(bound),
        refs,
    }
}

fn reviewed_u8_drop_premise(model: &ProgramSemanticModel, source: &str) -> SummaryPremise {
    // This exact fixture was reviewed independently of PSM's final-segment type normalization.
    // The producer's normalized Integer(u8) alone cannot distinguish a shadowed nominal type.
    assert_eq!(
        source,
        "fn candidate(value: u8) { std::mem::drop(value); }\n"
    );
    premise(
        Vec::new(),
        vec![format!(
            "source-reviewed:primitive-u8:sha256:{:x}:{}",
            Sha256::digest(source.as_bytes()),
            model.digest().expect("source-bound PSM digest")
        )],
    )
}

fn candidate_parameter_type(model: &ProgramSemanticModel) -> &str {
    let candidate = model
        .symbols()
        .iter()
        .find(|symbol| symbol.qualified_name().ends_with("::candidate"))
        .expect("actual candidate symbol");
    assert_eq!(candidate.parameters().len(), 1);
    candidate.parameters()[0].parameter_type().type_id()
}

fn dependency_features_are_not_host_features() {
    let model = compile_program_semantic_model(
        &psm_input(
            "fn candidate() { let mut bytes = [0_u8; 4]; let _ = getrandom::fill(&mut bytes); }\n",
        )
        .with_selected_context(
            "sample/library:sample",
            ["application"],
            Vec::<String>::new(),
            "x86_64-pc-windows-msvc",
        ),
    )
    .expect("observed host features");
    let call = model
        .calls()
        .iter()
        .find(|call| call.external_target() == Some("getrandom::fill"))
        .expect("dependency operation");
    let functions = load_function_contracts(&model, Vec::new()).expect("functions");
    let states = load_state_contracts(&model, Vec::new()).expect("states");
    let semantic = analyze_program_domains(&model, &functions, "1.0.0-draft.1").expect("semantic");
    let bindings = BTreeMap::from([(
        call.evidence()[0].operation_site_id().to_owned(),
        OperationSummaryInstantiation {
            context: context("getrandom::fill"),
            context_observation_refs: vec![format!(
                "dependency-feature-observation:{}",
                model.digest().expect("PSM digest")
            )],
            premises: BTreeMap::new(),
            acceptance: None,
        },
    )]);
    analyze_state_effects_with_summaries(
        &model,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &catalog(),
        &bindings,
    )
    .expect("dependency empty features differ validly from application host features");
}

fn conservative_local_premises() {
    let unit = psm("fn candidate(value: ()) { std::mem::drop(value); }\n");
    let unit_type = candidate_parameter_type(&unit);
    assert!(
        unit.types()
            .iter()
            .any(|value| value.id() == unit_type && matches!(value.semantic(), SemanticType::Unit))
    );
    let known_unit = primitive_destructor_premise(&unit, unit_type);
    assert_eq!(known_unit.bound, SummaryEffectBound::Known(Vec::new()));
    assert!(
        known_unit
            .refs
            .iter()
            .any(|reference| reference.contains(&unit.digest().expect("unit PSM digest")))
    );
    for source in [
        "fn candidate(value: u8) { std::mem::drop(value); }\n",
        "mod domain { #[allow(non_camel_case_types)] pub struct u8; impl Drop for u8 { fn drop(&mut self) { let _ = std::fs::write(\"out\", b\"changed\"); } } } fn candidate(value: domain::u8) { std::mem::drop(value); }\n",
    ] {
        let actual = psm(source);
        assert_eq!(
            primitive_destructor_premise(&actual, candidate_parameter_type(&actual)).bound,
            SummaryEffectBound::Unknown
        );
    }
    let callbacks = psm(
        "fn pure(value: u8) -> u8 { value } #[rewrite] fn rewritten(value: u8) -> u8 { value } #[rewrite] mod attributed { pub fn callback(value: u8) -> u8 { value } } fn effectful(value: u8) -> u8 { let _ = std::fs::write(\"out\", b\"changed\"); value } fn generic<T>(value: T) -> T { value }\n",
    );
    for suffix in [
        "::pure",
        "::rewritten",
        "::attributed::callback",
        "::effectful",
        "::generic",
    ] {
        let symbol = callbacks
            .symbols()
            .iter()
            .find(|symbol| symbol.qualified_name().ends_with(suffix))
            .expect("actual callback symbol");
        assert_eq!(
            local_callback_premise(&callbacks, symbol.id()).bound,
            SummaryEffectBound::Unknown,
            "actual callback: {suffix}"
        );
    }
    assert_eq!(
        local_callback_premise(&callbacks, "missing-symbol").bound,
        SummaryEffectBound::Unknown
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R06-001`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R06
#[test]
fn wrong_version_feature_target_invalidates_summary() {
    let installed = catalog();
    let rust_records = installed
        .summaries()
        .iter()
        .filter(|entry| {
            [
                "std::",
                "core::",
                "rust_method::",
                "rust_prelude::",
                "rust_type::",
            ]
            .iter()
            .any(|prefix| entry.operation_selector.starts_with(*prefix))
        })
        .collect::<Vec<_>>();
    assert_eq!(rust_records.len(), 117);
    for record in rust_records {
        assert_eq!(
            record.toolchain_or_package_source_digest,
            RUST_SOURCE_ARCHIVE
        );
        assert!(
            record
                .qualification_refs
                .contains(&"source:rust-src-1.97.1".into())
        );
    }
    let exact = context(CONSTRUCTOR);
    assert_eq!(
        installed
            .resolve(CONSTRUCTOR, &exact, &BTreeMap::new(), None)
            .upper_bound,
        SummaryEffectBound::Known(Vec::new())
    );
    let mut alternatives = Vec::new();
    let mut version = exact.clone();
    version.version = ContextKnowledge::Known("1.98.1".into());
    alternatives.push((version, "summary_version_mismatch"));
    let mut features = exact.clone();
    features.features = ContextKnowledge::Known(vec!["unreviewed-feature".into()]);
    alternatives.push((features, "summary_features_mismatch"));
    let mut target = exact.clone();
    target.target = ContextKnowledge::Known("wasm32-unknown-unknown".into());
    alternatives.push((target, "summary_target_mismatch"));
    let mut source = exact;
    source.source_digest = ContextKnowledge::Known(format!("sha256:{}", "f".repeat(64)));
    alternatives.push((source, "summary_source_digest_mismatch"));
    // An unchanged public wrapper file does not bind its platform implementation sources.
    let mut wrapper_file_only = context(CONSTRUCTOR);
    wrapper_file_only.source_digest = ContextKnowledge::Known(
        "sha256:50e3ed9eeb546023b0f6ac074c27d3718221e022cdf450f529466c336ddaec56".into(),
    );
    alternatives.push((wrapper_file_only, "summary_source_digest_mismatch"));
    alternatives.push((SummaryContext::default(), "summary_source_digest_unknown"));
    for (actual, reason) in alternatives {
        let outcome = installed.resolve(CONSTRUCTOR, &actual, &BTreeMap::new(), None);
        assert_eq!(outcome.upper_bound, SummaryEffectBound::Unknown);
        assert!(
            outcome.reasons.iter().any(|item| item == reason),
            "{outcome:?}"
        );
    }
    let mut memory_file_only = context(DROP);
    memory_file_only.source_digest = ContextKnowledge::Known(
        "sha256:9f450467849a7e829d2f57fe826518b7334df8a8eb206052d571ad7b5d018b9e".into(),
    );
    let rejected = installed.resolve(DROP, &memory_file_only, &BTreeMap::new(), None);
    assert_eq!(rejected.upper_bound, SummaryEffectBound::Unknown);
    assert!(
        rejected
            .reasons
            .contains(&"summary_source_digest_mismatch".into())
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R06-002`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R06
#[test]
fn overlapping_summary_selectors_conflict_deterministically() {
    let mut first = summary_value(CONSTRUCTOR);
    first["id"] = json!("first");
    let mut second = first.clone();
    second["id"] = json!("second");
    second["effect_upper_bound"] = json!({"state":"KNOWN","effects":["filesystem.write"]});
    let mut document = catalog_value();
    document["summaries"] = json!([first, second]);
    let forward = OperationSummaryCatalog::from_json_str(&document.to_string()).unwrap_err();
    document["summaries"]
        .as_array_mut()
        .expect("array")
        .reverse();
    let reversed = OperationSummaryCatalog::from_json_str(&document.to_string()).unwrap_err();
    assert_eq!(forward, reversed);
    assert!(forward.to_string().contains("SelectorConflict"));
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R06-003`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R06
#[test]
fn unknown_callback_or_drop_preserves_opacity() {
    conservative_local_premises();
    let installed = catalog();
    let actual = psm("fn candidate(value: u8) { std::mem::drop(value); }\n");
    let missing = installed.resolve(DROP, &context(DROP), &BTreeMap::new(), None);
    assert_eq!(missing.upper_bound, SummaryEffectBound::Unknown);
    assert!(
        missing
            .reasons
            .iter()
            .any(|reason| reason == "summary_dependency_unresolved:drop:argument:0")
    );
    let premises = BTreeMap::from([(
        "drop:argument:0".into(),
        reviewed_u8_drop_premise(
            &actual,
            "fn candidate(value: u8) { std::mem::drop(value); }\n",
        ),
    )]);
    let bounded = installed.resolve(DROP, &context(DROP), &premises, None);
    assert_eq!(bounded.upper_bound, SummaryEffectBound::Known(Vec::new()));
    assert!(
        bounded
            .premise_refs
            .iter()
            .any(|reference| reference.starts_with("source-reviewed:primitive-u8:"))
    );
    let mut wrong_type = context(DROP);
    wrong_type.type_bindings = ContextKnowledge::Known(vec!["T=Writer".into()]);
    assert_eq!(
        installed
            .resolve(DROP, &wrong_type, &premises, None)
            .upper_bound,
        SummaryEffectBound::Unknown
    );

    // A test authority exercises the dependency algebra; production callback authority stays partial.
    let mut callback = summary_value(CALLBACK);
    callback["authority_class"] = json!("QUALIFIED");
    callback["completeness"] = json!("COMPLETE");
    callback["qualification_refs"] = json!(["test-authority:dependency-composition"]);
    let callback_catalog = selected_catalog(&callback);
    assert_eq!(
        callback_catalog
            .resolve(CALLBACK, &context(CALLBACK), &BTreeMap::new(), None)
            .upper_bound,
        SummaryEffectBound::Unknown
    );
    let dependencies = BTreeMap::from([
        (
            "callback:argument:0".into(),
            premise(
                vec![FunctionEffect::FilesystemWrite],
                vec!["test-premise:callback-effect-bound".into()],
            ),
        ),
        (
            "drop:callback:argument:0".into(),
            premise(
                Vec::new(),
                vec!["test-premise:function-item-no-captures".into()],
            ),
        ),
    ]);
    assert_eq!(
        callback_catalog
            .resolve(CALLBACK, &context(CALLBACK), &dependencies, None)
            .upper_bound,
        SummaryEffectBound::Known(vec![FunctionEffect::FilesystemWrite])
    );
    assert_eq!(
        installed
            .resolve(CALLBACK, &context(CALLBACK), &dependencies, None)
            .upper_bound,
        SummaryEffectBound::Unknown
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R06-004`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R06
#[test]
fn assumed_summary_is_visible_in_assessment() {
    let mut assumed = summary_value(CONSTRUCTOR);
    assumed["authority_class"] = json!("ASSUMED");
    assumed["id"] = json!("assumed-constructor");
    let assumed_catalog = selected_catalog(&assumed);
    let denied =
        assumed_catalog.resolve(CONSTRUCTOR, &context(CONSTRUCTOR), &BTreeMap::new(), None);
    assert_eq!(denied.upper_bound, SummaryEffectBound::Unknown);
    assert_eq!(denied.authority, Some(SummaryAuthorityClass::Assumed));
    assert_eq!(
        denied.assumption_refs,
        ["operation_summary_assumption:assumed-constructor"]
    );
    let acceptance = SummaryAcceptance {
        profile_digest: format!("sha256:{}", "a".repeat(64)),
        accepted_summary_ids: vec!["assumed-constructor".into()],
    };
    let accepted = assumed_catalog.resolve(
        CONSTRUCTOR,
        &context(CONSTRUCTOR),
        &BTreeMap::new(),
        Some(&acceptance),
    );
    assert_eq!(accepted.upper_bound, SummaryEffectBound::Known(Vec::new()));
    assert_eq!(accepted.authority, Some(SummaryAuthorityClass::Assumed));
    assert!(
        accepted
            .assumption_refs
            .contains(&format!("accepted_profile:{}", acceptance.profile_digest))
    );

    let unaccepted = assumed_negative_claim(false);
    let unaccepted_json: Value =
        serde_json::from_str(&unaccepted.model().to_canonical_json().expect("claim JSON"))
            .expect("JSON");
    let unknown_claim = &unaccepted_json["modules"]
        .as_array()
        .expect("modules")
        .iter()
        .find(|module| module["module"] == "AF-SAMPLE-0001")
        .expect("sample Module")["conclusions"][0];
    assert_eq!(unknown_claim["verdict"], "NOT_EVALUABLE");
    let assessment = assumed_negative_claim(true);
    let assessment_json: Value = serde_json::from_str(
        &assessment
            .model()
            .to_canonical_json()
            .expect("assessment JSON"),
    )
    .expect("JSON");
    let conclusion = &assessment_json["modules"]
        .as_array()
        .expect("modules")
        .iter()
        .find(|module| module["module"] == "AF-SAMPLE-0001")
        .expect("sample Module")["conclusions"][0];
    assert_eq!(conclusion["verdict"], "NO_SUPPORTED_VIOLATION");
    let disclosed = conclusion.to_string();
    assert!(
        disclosed.contains("operation_summary_assumption:assumed-external-operation"),
        "{conclusion}"
    );
    assert!(
        disclosed.contains(&format!("accepted_profile:{}", acceptance.profile_digest)),
        "{conclusion}"
    );
    assert!(disclosed.contains("\"operator\":\"ALL\""), "{conclusion}");
}

fn contract(document: Value) -> Vec<u8> {
    serde_json::from_value::<ModuleContract>(document)
        .expect("contract shape")
        .to_canonical_json()
        .expect("canonical contract")
        .into_bytes()
}

fn assumed_negative_claim(accept: bool) -> SemanticConformanceEvaluation {
    const EDITION: &str = "1.0.0-draft.1";
    let files = BTreeMap::from([
        ("contract.json".into(), contract(json!({
            "$schema":"urn:fortress:schema:v2:module-contract","schema_version":2,
            "id":"PF-SUMMARY-FIXTURE","display_name":"Summary Fixture",
            "ecosystem":{"repository_grammar":1,"standard":{"id":"STD-FORTRESS-ENGINEERING","edition":EDITION}},
            "provides":[],"requires":[],"relationships":[],"constraints":[],"guarantees":[],"features":[],"behavior":[]
        }))),
        ("sample/contract.json".into(), contract(json!({
            "$schema":"urn:fortress:schema:v3:module-contract","schema_version":3,
            "id":"AF-SAMPLE-0001","display_name":"Sample","provides":[],"requires":[],
            "relationships":[],"constraints":[],"guarantees":[],"features":[],"behavior":[],
            "semantic_policy":{"default":"UNDECLARED","capabilities":{"allow":[],"deny":[]},
            "effects":{"allow":[],"deny":["filesystem.write"]}}
        }))),
        ("sample/_data/Cargo.toml".into(), b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n[dependencies]\nunsupported_dependency='1'\n".to_vec()),
        ("sample/_code/lib.rs".into(), b"pub fn candidate() { unsupported_dependency::execute(); }\n".to_vec()),
    ]);
    let standard =
        ContractStandardIndex::new("STD-FORTRESS-ENGINEERING", EDITION, ["ARCH-SEMANTIC-001"]);
    let compilation = compile_contract_coherency_graph(&files, &standard, None);
    let ccg = compilation
        .graph()
        .unwrap_or_else(|| panic!("CCG: {:?}", compilation.violations()));
    let input = ImplementationObservationInput::new(
        "sha256:summary-claim-fixture",
        files
            .iter()
            .map(|(path, bytes)| SnapshotBoundFile::from_bytes(path, bytes.clone()))
            .collect(),
        ccg.modules()
            .iter()
            .map(|(id, module)| ModuleTerritory::new(id, module.path()))
            .collect(),
    );
    let ownerships = input.ownerships().to_vec();
    let observed = observe_rust_implementation(&input).expect("implementation observes");
    let model = compile_program_semantic_model(&ProgramSemanticInput::new(
        "PF-SUMMARY-FIXTURE",
        input,
        Vec::<String>::new(),
        observed.module_dependencies().iter().map(|dependency| {
            (
                dependency.source_module().to_owned(),
                dependency.target_module().to_owned(),
            )
        }),
    ))
    .expect("PSM");
    let functions = load_function_contracts(&model, Vec::new()).expect("functions");
    let states = load_state_contracts(&model, Vec::new()).expect("states");
    let semantic = analyze_program_domains(&model, &functions, EDITION).expect("semantic");
    let mut document = catalog_value();
    let mut assumption = summary_value(CONSTRUCTOR);
    assumption["id"] = json!("assumed-external-operation");
    assumption["operation_selector"] = json!("unsupported_dependency::execute");
    assumption["authority_class"] = json!("ASSUMED");
    document["summaries"]
        .as_array_mut()
        .expect("array")
        .push(assumption);
    let authority = OperationSummaryCatalog::from_json_str(&document.to_string())
        .expect("installed plus assumption");
    let call = model
        .calls()
        .iter()
        .find(|call| call.external_target() == Some("unsupported_dependency::execute"))
        .expect("actual external operation");
    let site = call.evidence()[0].operation_site_id().to_owned();
    let bindings = BTreeMap::from([(
        site,
        OperationSummaryInstantiation {
            context: context(CONSTRUCTOR),
            context_observation_refs: vec![format!(
                "actual-source-context:{}",
                model.digest().expect("PSM digest")
            )],
            premises: BTreeMap::new(),
            acceptance: accept.then(|| SummaryAcceptance {
                profile_digest: format!("sha256:{}", "a".repeat(64)),
                accepted_summary_ids: vec!["assumed-external-operation".into()],
            }),
        },
    )]);
    let state = analyze_state_effects_with_summaries(
        &model, &semantic, &states, &functions, EDITION, &authority, &bindings,
    )
    .expect("state summaries with explicit assumption acceptance");
    assert_unsupported_lower_facts(state.model());
    let realization = reconcile_implementation(ccg, &observed, EDITION).expect("realization");
    evaluate_semantic_conformance(
        ccg,
        &model,
        state.model(),
        &realization,
        &ownerships,
        EDITION,
    )
    .expect("assumption-aware claim assessment")
}

fn assert_unsupported_lower_facts(state: &StateEffectAnalysisModel) {
    // Copying a historical no-op reference into assumed authority must not forge positive facts.
    let actual_summary = state
        .summaries()
        .iter()
        .find(|summary| {
            summary
                .operation_summaries()
                .iter()
                .any(|record| record.operation() == "unsupported_dependency::execute")
        })
        .expect("unsupported operation summary");
    assert!(
        actual_summary
            .operation_classifications()
            .iter()
            .any(
                |record| record.operation() == Some("unsupported_dependency::execute")
                    && record.state() == OperationClassificationState::Unsupported
            )
    );
    assert!(
        actual_summary
            .direct_effects()
            .contains(&FunctionEffect::ExternalInteraction)
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R06-005`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R06
#[test]
fn unsupported_package_remains_in_coverage() {
    let model = psm("fn candidate() { unsupported_dependency::execute(); }\n");
    let functions = load_function_contracts(&model, Vec::new()).expect("function contracts");
    let states = load_state_contracts(&model, Vec::new()).expect("state contracts");
    let semantic =
        analyze_program_domains(&model, &functions, "1.0.0-draft.1").expect("semantic facts");
    let evaluation = analyze_state_effects(&model, &semantic, &states, &functions, "1.0.0-draft.1")
        .expect("state/effect facts");
    let records = evaluation
        .model()
        .summaries()
        .iter()
        .flat_map(StateEffectSummary::operation_summaries)
        .collect::<Vec<_>>();
    let record = records
        .iter()
        .find(|record| record.operation() == "unsupported_dependency::execute")
        .expect("unsupported package call has a coverage record");
    assert_eq!(record.outcome().upper_bound, SummaryEffectBound::Unknown);
    assert!(
        record
            .outcome()
            .reasons
            .contains(&"no_summary_for_operation".into())
    );
}

#[derive(Clone, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
enum RecordedKnowledge<T> {
    Unknown,
    Known(T),
}

impl<T> From<RecordedKnowledge<T>> for ContextKnowledge<T> {
    fn from(value: RecordedKnowledge<T>) -> Self {
        match value {
            RecordedKnowledge::Unknown => Self::Unknown,
            RecordedKnowledge::Known(value) => Self::Known(value),
        }
    }
}

#[derive(Clone, Deserialize)]
struct RecordedContext {
    source_digest: RecordedKnowledge<String>,
    version: RecordedKnowledge<String>,
    target: RecordedKnowledge<String>,
    features: RecordedKnowledge<Vec<String>>,
    type_bindings: RecordedKnowledge<Vec<String>>,
}

impl From<RecordedContext> for SummaryContext {
    fn from(value: RecordedContext) -> Self {
        Self {
            source_digest: value.source_digest.into(),
            version: value.version.into(),
            target: value.target.into(),
            features: value.features.into(),
            type_bindings: value.type_bindings.into(),
        }
    }
}

#[derive(Deserialize)]
struct RecordedPremise {
    bound: SummaryEffectBound,
    refs: Vec<String>,
}

#[derive(Deserialize)]
struct ComparisonCase {
    id: String,
    operation: String,
    source: String,
    context: RecordedContext,
    premises: BTreeMap<String, RecordedPremise>,
    source_base_effects: Vec<FunctionEffect>,
    source_dependencies: Vec<String>,
    source_complete: bool,
    expected_authored_bound: SummaryEffectBound,
    expected_source_derived_bound: SummaryEffectBound,
    expected_hybrid_bound: SummaryEffectBound,
    required_positive_effects: Vec<FunctionEffect>,
}

#[derive(Deserialize)]
struct Comparison {
    cases: Vec<ComparisonCase>,
}

fn source_candidate(
    case: &ComparisonCase,
    selected: bool,
    premises: &BTreeMap<String, SummaryPremise>,
) -> SummaryEffectBound {
    if !selected || !case.source_complete {
        return SummaryEffectBound::Unknown;
    }
    let mut effects = case.source_base_effects.clone();
    for dependency in &case.source_dependencies {
        let Some(SummaryPremise {
            bound: SummaryEffectBound::Known(bound),
            refs,
        }) = premises.get(dependency)
        else {
            return SummaryEffectBound::Unknown;
        };
        if refs.is_empty() {
            return SummaryEffectBound::Unknown;
        }
        effects.extend(bound.iter().copied());
    }
    effects.sort_by_key(|effect| effect.stable_id());
    effects.dedup();
    SummaryEffectBound::Known(effects)
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R06-006`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R06
#[test]
fn qualified_summary_matches_ground_truth() {
    let comparison: Comparison = serde_json::from_str(COMPARISON).expect("retained controls parse");
    assert_eq!(comparison.cases.len(), 17);
    let installed = catalog();
    let mut authored_counterexamples = BTreeSet::new();
    for case in comparison.cases {
        let model = psm(&case.source);
        let functions = load_function_contracts(&model, Vec::new()).expect("functions");
        let states = load_state_contracts(&model, Vec::new()).expect("states");
        let semantic =
            analyze_program_domains(&model, &functions, "1.0.0-draft.1").expect("semantic facts");
        let analyzed =
            analyze_state_effects(&model, &semantic, &states, &functions, "1.0.0-draft.1")
                .expect("effect facts");
        let known_operation = installed
            .summaries()
            .iter()
            .any(|entry| entry.operation_selector == case.operation);
        let authored = if known_operation {
            SummaryEffectBound::Known(installed.observed_effects(&case.operation))
        } else {
            SummaryEffectBound::Unknown
        };
        let mut premises = case
            .premises
            .iter()
            .map(|(id, record)| {
                (
                    id.clone(),
                    SummaryPremise {
                        bound: record.bound.clone(),
                        refs: record.refs.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        if case.id == "drop-primitive-with-premise" {
            premises.insert(
                "drop:argument:0".into(),
                reviewed_u8_drop_premise(&model, &case.source),
            );
        }
        let actual_context: SummaryContext = case.context.clone().into();
        let hybrid = installed.resolve(&case.operation, &actual_context, &premises, None);
        let derived = source_candidate(&case, hybrid.selected_summary_id.is_some(), &premises);
        assert_eq!(
            authored, case.expected_authored_bound,
            "authored: {}",
            case.id
        );
        assert_eq!(
            derived, case.expected_source_derived_bound,
            "source-derived: {}",
            case.id
        );
        assert_eq!(
            hybrid.upper_bound, case.expected_hybrid_bound,
            "hybrid: {}",
            case.id
        );
        let observed = analyzed
            .model()
            .summaries()
            .iter()
            .flat_map(StateEffectSummary::direct_effects)
            .copied()
            .collect::<BTreeSet<_>>();
        for effect in &case.required_positive_effects {
            assert!(
                observed.contains(effect),
                "actual positive source control: {}: {effect:?}",
                case.id
            );
            if matches!(&authored, SummaryEffectBound::Known(bound) if !bound.contains(effect)) {
                authored_counterexamples.insert(case.id.clone());
            }
        }
    }
    assert_eq!(
        authored_counterexamples,
        BTreeSet::from([
            "callback-effectful-body".to_owned(),
            "drop-effectful-type".to_owned(),
        ])
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R06-007`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R06
#[test]
fn summary_change_invalidates_claim_not_unrelated_parse() {
    let model = psm("fn candidate() { let _ = std::fs::OpenOptions::new(); }\n");
    let parse_digest = model.digest().expect("PSM digest");
    let functions = load_function_contracts(&model, Vec::new()).expect("functions");
    let states = load_state_contracts(&model, Vec::new()).expect("states");
    let semantic =
        analyze_program_domains(&model, &functions, "1.0.0-draft.1").expect("semantic facts");
    let original = catalog();
    let mut changed_document = catalog_value();
    let mut assumption = summary_value(CONSTRUCTOR);
    assumption["id"] = json!("additional-assumed-operation");
    assumption["operation_selector"] = json!("test_dependency::pure");
    assumption["authority_class"] = json!("ASSUMED");
    changed_document["summaries"]
        .as_array_mut()
        .expect("array")
        .push(assumption);
    let changed = OperationSummaryCatalog::from_json_str(&changed_document.to_string())
        .expect("changed catalog");
    let before = analyze_state_effects_with_summaries(
        &model,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &original,
        &BTreeMap::new(),
    )
    .expect("original");
    let after = analyze_state_effects_with_summaries(
        &model,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &changed,
        &BTreeMap::new(),
    )
    .expect("changed");
    assert_ne!(original.digest(), changed.digest());
    assert_ne!(
        before.model().digest().expect("before effect digest"),
        after.model().digest().expect("after effect digest")
    );
    assert_eq!(parse_digest, model.digest().expect("PSM remains identical"));
    assert_eq!(
        before.model().operation_summary_catalog_digest(),
        original.digest()
    );
    assert_eq!(
        after.model().operation_summary_catalog_digest(),
        changed.digest()
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R06-008`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R06
#[test]
fn malformed_or_noncanonical_summary_cannot_become_authority() {
    let duplicate = CATALOG.replacen(
        "\"schema_version\": 1",
        "\"schema_version\": 1, \"schema_version\": 1",
        1,
    );
    assert!(OperationSummaryCatalog::from_json_str(&duplicate).is_err());
    let mut unknown = summary_value(CONSTRUCTOR);
    unknown["effect_upper_bound"] = json!({"state":"UNKNOWN","effects":[]});
    let mut document = catalog_value();
    document["summaries"] = json!([unknown]);
    assert!(OperationSummaryCatalog::from_json_str(&document.to_string()).is_err());
    let mut not_canonical = summary_value(CONSTRUCTOR);
    not_canonical["target_features_constraints"]["targets"] =
        json!(["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"]);
    document["summaries"] = json!([not_canonical]);
    assert!(OperationSummaryCatalog::from_json_str(&document.to_string()).is_err());
    let first = catalog();
    let mut reordered = catalog_value();
    reordered["summaries"]
        .as_array_mut()
        .expect("array")
        .reverse();
    let second = OperationSummaryCatalog::from_json_str(&reordered.to_string())
        .expect("order-neutral catalog");
    assert_eq!(first.digest(), second.digest());
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R06-009`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R06
#[test]
#[allow(clippy::too_many_lines)] // One integration fixture covers all exact-site authority refusals.
fn exact_site_constructor_instantiation_is_bound_to_current_psm() {
    dependency_features_are_not_host_features();
    let model = psm("fn candidate() { let _ = std::fs::OpenOptions::new(); }\n");
    let call = model
        .calls()
        .iter()
        .find(|call| call.external_target() == Some(CONSTRUCTOR))
        .expect("resolved actual constructor");
    let site = call.evidence()[0].operation_site_id().to_owned();
    let functions = load_function_contracts(&model, Vec::new()).expect("functions");
    let states = load_state_contracts(&model, Vec::new()).expect("states");
    let semantic =
        analyze_program_domains(&model, &functions, "1.0.0-draft.1").expect("semantic facts");
    let installed = catalog();
    let instantiation = OperationSummaryInstantiation {
        context: context(CONSTRUCTOR),
        context_observation_refs: vec![format!(
            "program-semantics:{}",
            model.digest().expect("actual PSM digest")
        )],
        premises: BTreeMap::new(),
        acceptance: None,
    };
    let bindings = BTreeMap::from([(site.clone(), instantiation.clone())]);
    let exact = analyze_state_effects_with_summaries(
        &model,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &installed,
        &bindings,
    )
    .expect("bound actual site");
    let outcome = exact
        .model()
        .summaries()
        .iter()
        .flat_map(StateEffectSummary::operation_summaries)
        .find(|record| record.operation() == CONSTRUCTOR)
        .expect("constructor coverage")
        .outcome();
    assert_eq!(outcome.upper_bound, SummaryEffectBound::Known(Vec::new()));
    let default = analyze_state_effects(&model, &semantic, &states, &functions, "1.0.0-draft.1")
        .expect("default analysis");
    assert!(
        default
            .model()
            .summaries()
            .iter()
            .flat_map(StateEffectSummary::operation_summaries)
            .any(|record| record.operation() == CONSTRUCTOR
                && record.outcome().upper_bound == SummaryEffectBound::Unknown)
    );
    let nonexistent =
        BTreeMap::from([("nonexistent-operation-site".into(), instantiation.clone())]);
    assert!(
        analyze_state_effects_with_summaries(
            &model,
            &semantic,
            &states,
            &functions,
            "1.0.0-draft.1",
            &installed,
            &nonexistent
        )
        .is_err()
    );
    let known_target = compile_program_semantic_model(
        &psm_input("fn candidate() { let _ = std::fs::OpenOptions::new(); }\n")
            .with_selected_context(
                "sample/library:sample",
                Vec::<String>::new(),
                Vec::<String>::new(),
                "x86_64-unknown-linux-gnu",
            ),
    )
    .expect("explicit Linux observation");
    let target_functions = load_function_contracts(&known_target, Vec::new()).expect("functions");
    let target_states = load_state_contracts(&known_target, Vec::new()).expect("states");
    let target_semantic =
        analyze_program_domains(&known_target, &target_functions, "1.0.0-draft.1")
            .expect("semantic");
    assert!(
        analyze_state_effects_with_summaries(
            &known_target,
            &target_semantic,
            &target_states,
            &target_functions,
            "1.0.0-draft.1",
            &installed,
            &bindings
        )
        .is_err()
    );
    for malformed_context in [
        SummaryContext {
            source_digest: ContextKnowledge::Known("not-a-source-digest".into()),
            ..instantiation.context.clone()
        },
        SummaryContext {
            source_digest: ContextKnowledge::Known(format!("sha256:{}", "A".repeat(64))),
            ..instantiation.context.clone()
        },
        SummaryContext {
            version: ContextKnowledge::Known(String::new()),
            ..instantiation.context.clone()
        },
        SummaryContext {
            target: ContextKnowledge::Known(" target-with-leading-space".into()),
            ..instantiation.context.clone()
        },
        SummaryContext {
            features: ContextKnowledge::Known(vec!["duplicate".into(), "duplicate".into()]),
            ..instantiation.context.clone()
        },
        SummaryContext {
            features: ContextKnowledge::Known(vec!["z".into(), "a".into()]),
            ..instantiation.context.clone()
        },
        SummaryContext {
            type_bindings: ContextKnowledge::Known(vec![String::new()]),
            ..instantiation.context.clone()
        },
        SummaryContext {
            type_bindings: ContextKnowledge::Known(vec!["T=u8".into(), "T=u8".into()]),
            ..instantiation.context.clone()
        },
    ] {
        let malformed = OperationSummaryInstantiation {
            context: malformed_context,
            ..instantiation.clone()
        };
        assert!(matches!(
            analyze_state_effects_with_summaries(
                &model,
                &semantic,
                &states,
                &functions,
                "1.0.0-draft.1",
                &installed,
                &BTreeMap::from([(site.clone(), malformed)])
            ),
            Err(StateEffectAnalysisError::InvalidSummaryContext(_))
        ));
    }
    let mut no_evidence = instantiation;
    no_evidence.context_observation_refs.clear();
    assert!(
        analyze_state_effects_with_summaries(
            &model,
            &semantic,
            &states,
            &functions,
            "1.0.0-draft.1",
            &installed,
            &BTreeMap::from([(site, no_evidence)])
        )
        .is_err()
    );
}
