//! Parent-local Function Contract and semantic-domain conformance.

use std::path::{Path, PathBuf};

use fortress_core::audit::{compile_repository_psm, compile_repository_semantic_analysis};
use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::program_semantics::native_body::{
    NativeBodyInput, NativeBodyLanguage, NativeBodyOutcome,
};
use fortress_core::program_semantics::{ProgramSemanticInput, compile_program_semantic_model};
use fortress_core::project::EvaluationKey;
use fortress_core::semantic_analysis::{
    DomainSpecification, FunctionContractError, FunctionContractSource, IntegerInterval,
    SemanticDomain, analyze_program_domains, canonicalize_function_contract_json,
    load_function_contracts,
};
use fortress_core::semantic_analysis::{
    NativeBooleanReturn, compare_native_boolean_return, infer_native_scalar_output,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root exists")
}

fn psm(source: &str) -> fortress_core::program_semantics::ProgramSemanticModel {
    let input = ProgramSemanticInput::new(
        "PF-SEMANTIC-FIXTURE",
        ImplementationObservationInput::new(
            "sha256:fixture",
            vec![
                SnapshotBoundFile::from_bytes(
                    "sample/_data/Cargo.toml",
                    b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n",
                ),
                SnapshotBoundFile::from_bytes("sample/_code/lib.rs", source.as_bytes()),
            ],
            vec![
                ModuleTerritory::new("PF-SEMANTIC-FIXTURE", ""),
                ModuleTerritory::new("AF-SAMPLE-0001", "sample"),
            ],
        ),
        Vec::new(),
        Vec::new(),
    );
    compile_program_semantic_model(&input).expect("semantic fixture PSM compiles")
}

fn symbol_id(psm: &fortress_core::program_semantics::ProgramSemanticModel, suffix: &str) -> String {
    psm.symbols()
        .iter()
        .find(|symbol| symbol.qualified_name().ends_with(suffix))
        .unwrap_or_else(|| panic!("symbol ending `{suffix}` exists"))
        .id()
        .into()
}

fn contract_source(module: &str, mut functions: Vec<Value>) -> FunctionContractSource {
    functions.sort_by(|left, right| left["symbol"].as_str().cmp(&right["symbol"].as_str()));
    let mut source = serde_json::to_string_pretty(&json!({
        "$schema": "urn:fortress:schema:v5:function-contracts",
        "schema_version": 5,
        "functions": functions
    }))
    .expect("contract fixture serializes");
    source.push('\n');
    source = canonicalize_function_contract_json("sample/_data/function_contracts.json", &source)
        .expect("contract fixture canonicalizes");
    FunctionContractSource::new(module, "sample/_data/function_contracts.json", source)
}

fn function_contract(symbol: &str, requires: Vec<Value>, ensures: Vec<Value>) -> Value {
    let requires = Value::Array(requires);
    let ensures = Value::Array(ensures);
    json!({
        "symbol": symbol,
        "requires": requires,
        "ensures": ensures,
        "state_requires": [],
        "state_ensures": [],
        "effects": null
    })
}

fn empty_contracts(
    psm: &fortress_core::program_semantics::ProgramSemanticModel,
) -> fortress_core::semantic_analysis::ResolvedFunctionContracts {
    load_function_contracts(psm, Vec::new()).expect("empty contract set resolves")
}

fn analyze(
    psm: &fortress_core::program_semantics::ProgramSemanticModel,
    contracts: &fortress_core::semantic_analysis::ResolvedFunctionContracts,
) -> fortress_core::semantic_analysis::SemanticAnalysisEvaluation {
    analyze_program_domains(psm, contracts, "1.0.0-draft.1").expect("semantic analysis completes")
}

/// `T-FUNCTION-CONTRACT-INFORMATION-FLOW-ROUNDTRIP-001`
/// Fortress classification: infrastructure
#[test]
fn exclusive_information_flow_bounds_round_trip_without_null_counterparts() {
    let source = r#"{
  "$schema": "urn:fortress:schema:v4:function-contracts",
  "schema_version": 4,
  "functions": [
    {
      "symbol": "rust_symbol:sha256:fixture",
      "requires": [],
      "ensures": [],
      "state_requires": [],
      "state_ensures": [],
      "effects": null,
      "information_flow": {
        "sources": [],
        "requires": [
          {
            "target": {
              "kind": "return"
            },
            "facet": "FLOW-CONFIDENTIALITY",
            "minimum": "PUBLIC"
          }
        ],
        "ensures": [],
        "transforms": []
      }
    }
  ]
}
"#;
    let canonical = canonicalize_function_contract_json("function_contracts.json", source)
        .expect("exclusive minimum canonicalizes");
    assert!(canonical.contains("\"minimum\": \"PUBLIC\""));
    assert!(!canonical.contains("\"maximum\""));
    assert_eq!(
        canonicalize_function_contract_json("function_contracts.json", &canonical)
            .expect("canonical contract repeats"),
        canonical
    );
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R01-001`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R01
#[test]
fn boolean_integer_and_widening_lattice_is_conservative() {
    let bool_type = "type:bool";
    let true_only = SemanticDomain::boolean(bool_type, [true]);
    let all_bool = SemanticDomain::boolean(bool_type, [false, true]);
    assert!(true_only.is_subset_of(&all_bool));
    assert_eq!(
        true_only.join(&SemanticDomain::boolean(bool_type, [false])),
        all_bool
    );
    assert!(
        true_only
            .intersection(&SemanticDomain::boolean(bool_type, [false]))
            .is_bottom()
    );

    let small = SemanticDomain::integer(
        "type:i32",
        [IntegerInterval::new(0, 10).expect("interval")],
        [],
    );
    let large = SemanticDomain::integer(
        "type:i32",
        [IntegerInterval::new(-5, 20).expect("interval")],
        [0],
    );
    assert!(small.intersection(&large).is_subset_of(&small));
    assert!(!large.is_subset_of(&small));
    assert!(
        !large
            .difference(&small)
            .expect("difference representable")
            .is_bottom()
    );
    assert!(small.widen(&large).is_top());
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R01-002`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R01
#[test]
fn option_result_enum_and_product_domains_preserve_state() {
    let payload = SemanticDomain::integer(
        "type:u8",
        [IntegerInterval::new(0, 255).expect("interval")],
        [],
    );
    let option = SemanticDomain::Option {
        type_id: "type:option".into(),
        none: true,
        some: Box::new(payload.clone()),
    };
    let some = SemanticDomain::Option {
        type_id: "type:option".into(),
        none: false,
        some: Box::new(payload.clone()),
    };
    assert!(some.is_subset_of(&option));
    assert!(!option.is_subset_of(&some));
    let result = SemanticDomain::Result {
        type_id: "type:result".into(),
        ok: Box::new(payload.clone()),
        err: Box::new(SemanticDomain::Opaque {
            type_id: "type:error".into(),
            top: true,
        }),
    };
    assert!(!result.is_bottom());
    let tuple = SemanticDomain::Tuple {
        type_id: "type:tuple".into(),
        elements: vec![SemanticDomain::boolean("type:bool", [true]), payload],
    };
    assert_eq!(tuple.intersection(&tuple), tuple);
    let enum_domain = SemanticDomain::Enum {
        type_id: "type:enum".into(),
        variants: [("Number".into(), None), ("Text".into(), None)]
            .into_iter()
            .collect(),
    };
    let number = SemanticDomain::Enum {
        type_id: "type:enum".into(),
        variants: [("Number".into(), None)].into_iter().collect(),
    };
    assert!(number.is_subset_of(&enum_domain));
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R01-003`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R01
#[test]
fn function_contracts_reject_unknown_foreign_and_invalid_domains() {
    let model = psm("pub fn bounded(value: u8) -> u8 { value }\n");
    let symbol = symbol_id(&model, "bounded");
    let invalid = contract_source(
        "AF-SAMPLE-0001",
        vec![function_contract(
            &symbol,
            vec![
                json!({"parameter":"value","domain":{"kind":"integer_interval","min":0,"max":300,"exclude":[]}}),
            ],
            Vec::new(),
        )],
    );
    assert!(matches!(
        load_function_contracts(&model, vec![invalid]),
        Err(FunctionContractError::InvalidDomain { .. })
    ));
    let foreign = contract_source(
        "AF-FOREIGN-0001",
        vec![function_contract(&symbol, Vec::new(), Vec::new())],
    );
    assert!(matches!(
        load_function_contracts(&model, vec![foreign]),
        Err(FunctionContractError::ForeignSymbol { .. })
    ));
    let unknown = contract_source(
        "AF-SAMPLE-0001",
        vec![function_contract(
            "rust_symbol:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Vec::new(),
            Vec::new(),
        )],
    );
    assert!(matches!(
        load_function_contracts(&model, vec![unknown]),
        Err(FunctionContractError::UnknownSymbol { .. })
    ));
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R01-004`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R01
#[test]
fn function_contracts_survive_parameter_renames_and_report_legacy_alias_use() {
    let before = psm("pub fn bounded(value: u8) -> u8 { value }\n");
    let after = psm("pub fn bounded(renamed: u8) -> u8 { renamed }\n");
    let before_id = symbol_id(&before, "bounded");
    let after_id = symbol_id(&after, "bounded");
    assert_eq!(before_id, after_id);
    let source = contract_source(
        "AF-SAMPLE-0001",
        vec![function_contract(&before_id, Vec::new(), Vec::new())],
    );
    let resolved = load_function_contracts(&after, vec![source]).expect("current target survives");
    assert!(resolved.get(&after_id).is_some());
    assert!(resolved.legacy_symbol_references().is_empty());

    let legacy = after
        .symbols()
        .iter()
        .find(|symbol| symbol.id() == after_id)
        .unwrap()
        .legacy_ids()[0]
        .clone();
    let mut legacy_source = serde_json::to_string_pretty(&json!({
        "$schema": "urn:fortress:schema:v4:function-contracts",
        "schema_version": 4,
        "functions": [function_contract(&legacy, Vec::new(), Vec::new())]
    }))
    .unwrap();
    legacy_source.push('\n');
    legacy_source =
        canonicalize_function_contract_json("sample/_data/function_contracts.json", &legacy_source)
            .unwrap();
    let legacy_source = FunctionContractSource::new(
        "AF-SAMPLE-0001",
        "sample/_data/function_contracts.json",
        legacy_source,
    );
    let resolved =
        load_function_contracts(&after, vec![legacy_source]).expect("legacy alias resolves");
    assert!(resolved.get(&after_id).is_some());
    assert_eq!(resolved.legacy_symbol_references().len(), 1);
    assert_eq!(
        resolved.legacy_symbol_references()[0].authored_reference(),
        legacy
    );
    assert_eq!(
        resolved.legacy_symbol_references()[0].canonical_reference(),
        after_id
    );
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R02-001`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R02
#[test]
fn option_result_and_boolean_branches_refine_path_domains() {
    let model = psm(
        "pub fn safe(value: Option<u8>) -> u8 { if value.is_some() { return value.unwrap(); } 0 }\n\
         pub fn result(value: Result<u8, ()>) -> u8 { if value.is_ok() { return value.unwrap(); } 0 }\n\
         pub fn choose(flag: bool) -> bool { if flag { true } else { false } }\n",
    );
    let evaluation = analyze(&model, &empty_contracts(&model));
    assert!(evaluation.findings().is_empty());
    assert_eq!(evaluation.model().summaries().len(), 3);
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R02-002`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R02
#[test]
fn call_and_return_domains_propagate_interprocedurally() {
    let model = psm(
        "fn identity(value: i32) -> i32 { value }\nfn caller(value: i32) -> i32 { let next = identity(value); next }\n",
    );
    let evaluation = analyze(&model, &empty_contracts(&model));
    assert!(evaluation.findings().is_empty());
    let json: Value = serde_json::from_str(
        &evaluation
            .model()
            .to_canonical_json()
            .expect("semantic JSON serializes"),
    )
    .expect("semantic JSON parses");
    assert!(
        json["coverage"]["interprocedural_transfers"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R02-003`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R02
#[test]
fn current_safe_callers_never_narrow_a_callee_admitted_domain() {
    let model = psm(
        "fn latent(value: Option<u8>) -> u8 { value.unwrap() }\nfn current() -> u8 { latent(Some(1)) }\n",
    );
    let evaluation = analyze(&model, &empty_contracts(&model));
    assert_eq!(evaluation.model().violations().len(), 1);
    assert!(
        evaluation.model().violations()[0]
            .message()
            .contains("not a subset")
    );
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R02-004`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R02
#[test]
fn recursion_and_while_let_converge_without_path_enumeration() {
    let model = psm(
        "fn recurse(value: i32) -> i32 { if value <= 0 { return 0; } recurse(value - 1) }\n\
         fn consume(mut value: Option<u8>) -> u8 { while let Some(next) = value { value = None; return next; } 0 }\n",
    );
    let evaluation = analyze(&model, &empty_contracts(&model));
    let json: Value =
        serde_json::from_str(&evaluation.model().to_canonical_json().expect("serializes"))
            .expect("parses");
    assert!(
        json["coverage"]["fixed_point_iterations"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(
        json["coverage"]["recursive_components"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R03-001`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R03
#[test]
fn every_call_site_must_satisfy_authored_preconditions() {
    let model = psm(
        "fn narrow(value: i32) -> i32 { value }\nfn safe() -> i32 { narrow(5) }\nfn unsafe_forward(value: i32) -> i32 { narrow(value) }\n",
    );
    let narrow = symbol_id(&model, "narrow");
    let source = contract_source(
        "AF-SAMPLE-0001",
        vec![function_contract(
            &narrow,
            vec![
                json!({"parameter":"value","domain":{"kind":"integer_interval","min":0,"max":10,"exclude":[]}}),
            ],
            Vec::new(),
        )],
    );
    let contracts = load_function_contracts(&model, vec![source]).expect("contract resolves");
    let evaluation = analyze(&model, &contracts);
    assert_eq!(evaluation.model().violations().len(), 1);
    assert!(
        evaluation.model().violations()[0]
            .counter_domain()
            .is_some()
    );
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R03-002`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R03
#[test]
fn postconditions_are_proved_and_exact_excess_is_reported() {
    let model = psm("fn good() -> i32 { 5 }\nfn bad() -> i32 { 0 - 5 }\n");
    let good = symbol_id(&model, "good");
    let bad = symbol_id(&model, "bad");
    let source = contract_source(
        "AF-SAMPLE-0001",
        vec![
            function_contract(
                &bad,
                Vec::new(),
                vec![
                    json!({"return":true,"domain":{"kind":"integer_interval","min":0,"max":100,"exclude":[]}}),
                ],
            ),
            function_contract(
                &good,
                Vec::new(),
                vec![
                    json!({"return":true,"domain":{"kind":"integer_interval","min":0,"max":100,"exclude":[]}}),
                ],
            ),
        ],
    );
    let evaluation = analyze(
        &model,
        &load_function_contracts(&model, vec![source]).expect("contracts resolve"),
    );
    assert_eq!(evaluation.model().violations().len(), 1);
    assert_eq!(evaluation.findings().len(), 1);
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R03-003`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R03
#[test]
fn partial_operations_and_impossible_state_assertions_are_checked() {
    let model = psm(
        "fn unsafe_option(value: Option<u8>) -> u8 { value.expect(\"required\") }\n\
         fn unsafe_result(value: Result<u8, ()>) -> u8 { value.unwrap() }\n\
         fn divide(value: i32, denominator: i32) -> i32 { value / denominator }\n\
         fn impossible() { unreachable!() }\n",
    );
    let evaluation = analyze(&model, &empty_contracts(&model));
    assert!(evaluation.model().violations().len() >= 4);
    assert_eq!(
        evaluation.findings().len(),
        evaluation.model().violations().len()
    );
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R03-004`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R03
#[test]
fn defined_error_outcomes_and_uncertainty_are_not_false_failures() {
    let model = psm(
        "fn validate(flag: bool) -> Result<u8, ()> { if flag { Ok(1) } else { Err(()) } }\n\
         fn opaque(value: i32) -> i32 { unknown_predicate(value); value }\n",
    );
    let evaluation = analyze(&model, &empty_contracts(&model));
    assert!(evaluation.findings().is_empty());
    let json: Value =
        serde_json::from_str(&evaluation.model().to_canonical_json().expect("serializes"))
            .expect("parses");
    assert!(
        json["coverage"]["unknown_properties"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(
        json["coverage"]["unsupported_properties"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R03-005`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R03
#[test]
fn unmodeled_pattern_selection_cannot_establish_impossible_state_reachability() {
    let model = psm(
        "fn excluded_range() { match 0_u8 { 1..=2 => { unreachable!(); }, _ => {} } }\n\
         fn prior_range() { match 0_u8 { 0..=0 => {}, _ => { unreachable!(); } } }\n\
         fn nested_range() { match Some(0_u8) { Some(1..=2) => { unreachable!(); }, _ => {} } }\n\
         fn loop_range() { while let 1..=2 = 0_u8 { unreachable!(); }; }\n\
         fn supported_branch(value: Option<u8>) { match value { Some(_) => { unreachable!(); }, None => {} } }\n\
         fn unconditional() { unreachable!(); }\n",
    );
    let evaluation = analyze(&model, &empty_contracts(&model));
    let model_json: Value = serde_json::from_str(&evaluation.model().to_canonical_json().unwrap())
        .expect("semantic model serializes");
    let checks = model_json["checks"].as_array().unwrap();
    let summaries = model_json["summaries"].as_array().unwrap();
    for function in [
        "excluded_range",
        "prior_range",
        "nested_range",
        "loop_range",
    ] {
        let symbol = symbol_id(&model, function);
        let check = checks
            .iter()
            .find(|record| record["producer_symbol"] == symbol)
            .unwrap_or_else(|| panic!("missing check for {function}"));
        assert_eq!(check["kind"], "impossible_state_assertion");
        assert_eq!(check["state"], "UNSUPPORTED");
        assert_eq!(
            check["provenance"]["derivation"],
            "unsupported_pattern_reachability"
        );
        let summary = summaries
            .iter()
            .find(|row| row["symbol"] == symbol)
            .unwrap();
        assert_eq!(summary["coverage"]["partial_operations"], "UNSUPPORTED");
    }
    let violations = model_json["violations"].as_array().unwrap();
    assert_eq!(violations.len(), 2);
    assert_eq!(evaluation.findings().len(), 2);
    for function in ["supported_branch", "unconditional"] {
        let symbol = symbol_id(&model, function);
        assert!(
            violations
                .iter()
                .any(|record| record["producer_symbol"] == symbol)
        );
    }
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R04-001`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R04
#[test]
fn canonical_semantic_analysis_is_byte_and_digest_deterministic() {
    let model = psm("fn stable(value: bool) -> bool { value }\n");
    let first = analyze(&model, &empty_contracts(&model));
    let second = analyze(&model, &empty_contracts(&model));
    assert_eq!(first, second);
    assert_eq!(
        first.model().to_canonical_json().expect("first JSON"),
        second.model().to_canonical_json().expect("second JSON")
    );
    assert_eq!(
        first.model().digest().expect("first digest"),
        second.model().digest().expect("second digest")
    );
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R04-002`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R04
#[test]
fn live_fortress_semantic_analysis_is_fresh_and_contradiction_free() {
    let root = repository_root();
    let psm = compile_repository_psm(&root).expect("live PSM compiles");
    let first = compile_repository_semantic_analysis(&root).expect("live semantics compile");
    let second = compile_repository_semantic_analysis(&root).expect("live semantics repeat");
    assert_eq!(first, second);
    assert_eq!(
        first.model().coverage().functions_analyzed(),
        psm.symbols().len()
    );
    assert_eq!(first.model().coverage().violations(), 0);
    assert!(first.findings().is_empty());
    assert!(first.model().coverage().function_contracts() > 0);
    assert!(
        first
            .model()
            .to_canonical_json()
            .expect("serializes")
            .ends_with('\n')
    );
}

#[allow(dead_code)]
fn domain_specification_is_publicly_constructible() -> DomainSpecification {
    DomainSpecification::Boolean {
        include: vec![true],
    }
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R06-001`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R06
#[test]
fn shared_scalar_domain_interpreter_retains_exact_native_scope() {
    let reference = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let key = EvaluationKey::new(reference, reference, reference);
    for (
        language,
        path,
        source,
        name_column,
        statement_start,
        statement_line,
        statement_column,
        scalar,
    ) in [
        (
            NativeBodyLanguage::Go,
            "package/f.go",
            "func F() int64 { return -9 }",
            6,
            17,
            1,
            18,
            "SIGNED_I64",
        ),
        (
            NativeBodyLanguage::Python,
            "package/f.py",
            "def F():\n    return -9",
            5,
            13,
            2,
            5,
            "INTEGER_LITERAL",
        ),
    ] {
        let name_start = name_column - 1;
        let occurrence = |start: usize, end: usize, line: usize, column: usize| {
            json!({
                "path": path, "start_byte": start, "end_byte": end,
                "start_line": line, "start_byte_column": column,
            })
        };
        let source_ref = format!("sha256:{:x}", Sha256::digest(source));
        let input = NativeBodyInput {
            language,
            evaluation: &key,
            exchange_ref: reference,
            producer_ref: reference,
            source_path: path,
            source_ref: &source_ref,
            source: source.as_bytes(),
            python_bool_parameters: &[],
        };
        let mut reply = json!({
            "status":"LOWERABLE",
            "symbol":{
                "name":"F", "span": occurrence(name_start, name_start + 1, 1, name_column),
                "declaration_span": occurrence(0, source.len(), 1, 1)
            },
            "parameters":[], "locals":[], "result_scalar":scalar,
            "body":[{
                "kind":"return",
                "span":occurrence(statement_start, statement_start + "return -9".len(), statement_line, statement_column),
                "value":{"kind":"integer","value":"-9"}
            }]
        });
        let analyze = |value: &Value| {
            let NativeBodyOutcome::Lowered(body) =
                input.admit(&serde_json::to_vec(value).unwrap()).unwrap()
            else {
                panic!("fixture is a typed exact native body");
            };
            infer_native_scalar_output(&body)
        };
        let Some(SemanticDomain::Integer {
            type_id,
            intervals,
            excluded,
        }) = analyze(&reply)
        else {
            panic!("fixture has an independently known scalar result");
        };
        let expected_type = if language == NativeBodyLanguage::Go {
            "native_scalar:go:int64"
        } else {
            "native_scalar:python:bounded_integer_literal"
        };
        assert_eq!(type_id, expected_type);
        assert_eq!(intervals, [IntegerInterval::new(-9, -9).unwrap()]);
        assert!(excluded.is_empty());

        // A bounded structurally admitted attachment cannot establish a return
        // domain if its selected control path leaves a residual fall-through.
        let branch = reply["body"][0].clone();
        reply["body"][0] = json!({
            "kind":"if", "span": branch["span"],
            "condition":{"kind":"boolean","value":false},
            "then_branch":[branch], "else_branch":[]
        });
        assert!(analyze(&reply).is_none());
    }
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R07-001`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R07
#[test]
fn scoped_native_boolean_return_needs_a_nonempty_closed_bound() {
    for (language, path, declaration, name_prefix, boolean) in [
        (
            NativeBodyLanguage::Go,
            "package/f.go",
            "func F() bool { return true }",
            "func ",
            true,
        ),
        (
            NativeBodyLanguage::Python,
            "package/f.py",
            "def F():\n    return False",
            "def ",
            false,
        ),
    ] {
        let reference = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let evaluation = EvaluationKey::new(reference, reference, reference);
        let source_ref = format!("sha256:{:x}", Sha256::digest(declaration));
        let input = NativeBodyInput {
            language,
            evaluation: &evaluation,
            exchange_ref: reference,
            producer_ref: reference,
            source_path: path,
            source_ref: &source_ref,
            source: declaration.as_bytes(),
            python_bool_parameters: &[],
        };
        let span = |start: usize, end: usize| {
            let before = &declaration[..start];
            let line = before.matches('\n').count() + 1;
            let column = before.rsplit('\n').next().unwrap().len() + 1;
            json!({
                "path": path, "start_byte": start, "end_byte": end,
                "start_line": line, "start_byte_column": column,
            })
        };
        let body_start = declaration.find("return").unwrap();
        let body_end = declaration.trim_end_matches([' ', '}']).len();
        let mut reply = json!({
            "status": "LOWERABLE",
            "symbol": {
                "name": "F", "span": span(name_prefix.len(), name_prefix.len() + 1),
                "declaration_span": span(0, declaration.len()),
            },
            "parameters": [], "locals": [], "result_scalar": "BOOL",
            "body": [{
                "kind": "return", "span": span(body_start, body_end),
                "value": {"kind": "boolean", "value": boolean},
            }],
        });
        let compare = |reply: &Value, required| {
            let NativeBodyOutcome::Lowered(body) =
                input.admit(&serde_json::to_vec(reply).unwrap()).unwrap()
            else {
                panic!("fixture independently supplies a structurally admitted body");
            };
            compare_native_boolean_return(&body, required)
        };
        assert_eq!(
            compare(&reply, boolean),
            NativeBooleanReturn::MatchesRequiredValue
        );
        assert_eq!(
            compare(&reply, !boolean),
            NativeBooleanReturn::ExcludesRequiredValue
        );

        let unreachable = reply["body"][0].take();
        reply["body"][0] = json!({
            "kind": "if",
            "span": unreachable["span"],
            "condition": {"kind": "boolean", "value": false},
            "then_branch": [unreachable],
            "else_branch": [],
        });
        assert_eq!(compare(&reply, boolean), NativeBooleanReturn::Unresolved);
    }
}
