//! Independent native Boolean table and incomplete model controls.

use fortress_core::observation::SourceView;
use fortress_core::portable::digest;
use fortress_core::program_semantics::native_body::{
    NativeBodyInput, NativeBodyLanguage, NativeBodyOutcome,
};
use fortress_core::program_semantics::python_scalar::{PythonScalarProducer, PythonScalarRequest};
use fortress_core::project::EvaluationKey;
use fortress_core::semantic_analysis::{
    NativeBooleanParameterDisposition, NativeBooleanSensitivity, NativeBooleanSensitivityReason,
    infer_native_scalar_output, inspect_native_boolean_sensitivity,
};
use serde::Deserialize;
use serde_json::{Value, json};

const REF: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PATH: &str = "src/subject.py";
const CASES: &[u8] = include_bytes!("../_data/native_sensitivity_cases_v1.json");

#[derive(Deserialize)]
struct Fixture {
    case: String,
    params: Vec<String>,
    source: String,
    model: String,
    native: Value,
    reply: Value,
}

fn replay(case: &Fixture) -> NativeBodyOutcome {
    let mut reply = case.reply.clone();
    let view = SourceView::from_bytes([(PATH, case.source.as_bytes().to_vec())]).unwrap();
    let evaluation = EvaluationKey::new(REF, REF, REF);
    let producer = PythonScalarProducer::new(
        reply["worker_ref"].as_str().unwrap(),
        reply["bootstrap_ref"].as_str().unwrap(),
        reply["runtime_ref"].as_str().unwrap(),
    )
    .unwrap();
    let parameters = case.params.iter().map(String::as_str).collect::<Vec<_>>();
    let request =
        PythonScalarRequest::bind(&view, &evaluation, PATH, "selected", &parameters, &producer)
            .unwrap();
    let request_payload = request.worker_payload(&view, &evaluation).unwrap();
    let current: Value = serde_json::from_slice(&request_payload).unwrap();
    reply["id"] = current["id"].clone();
    request
        .admit(&view, &evaluation, &serde_json::to_vec(&reply).unwrap())
        .unwrap()
}

fn known_changes(case: &str) -> &[&str] {
    match case {
        "direct-copy" | "negation" | "different-branches" | "joined-assignment" => &["flag"],
        "nested-gate" => &["public", "secret"],
        "four-parameter-boundary" => &["d"],
        "same-branches" | "overwritten-assignment" => &[],
        other => panic!("unexpected complete fixture {other}"),
    }
}

fn native_result(native: &[Value], inputs: &[bool]) -> bool {
    let row = inputs
        .iter()
        .rev()
        .fold(0, |row, input| (row * 2) + usize::from(*input));
    native[row].as_bool().unwrap()
}

fn compare_table(case: &Fixture, result: NativeBooleanSensitivity) {
    let NativeBooleanSensitivity::Complete {
        valuation_count,
        parameters,
        ..
    } = result
    else {
        panic!("{} has an exact native table", case.case);
    };
    let native = case.native.as_array().unwrap();
    assert_eq!(valuation_count, native.len());
    assert_eq!(
        parameters
            .iter()
            .map(|entry| &entry.parameter)
            .collect::<Vec<_>>(),
        case.params.iter().collect::<Vec<_>>(),
    );
    let changed = known_changes(&case.case);
    for (index, entry) in parameters.into_iter().enumerate() {
        match entry.disposition {
            NativeBooleanParameterDisposition::ReturnChanges {
                inputs_with_parameter_false: lower,
                inputs_with_parameter_true: upper,
                return_with_parameter_false,
                return_with_parameter_true,
            } => {
                assert!(changed.contains(&entry.parameter.as_str()));
                let pairs = lower.iter().zip(&upper).enumerate();
                assert_eq!(lower.len(), case.params.len());
                assert_eq!(upper.len(), case.params.len());
                assert!(!lower[index] && upper[index]);
                assert!(
                    pairs
                        .filter(|(position, _)| *position != index)
                        .all(|(_, (a, b))| a == b)
                );
                assert_eq!(native_result(native, &lower), return_with_parameter_false);
                assert_eq!(native_result(native, &upper), return_with_parameter_true);
                assert_ne!(return_with_parameter_false, return_with_parameter_true);
                if case.case == "nested-gate" {
                    assert_eq!(
                        lower,
                        if index == 0 {
                            [false, true]
                        } else {
                            [true, false]
                        }
                    );
                    assert_eq!(upper, [true, true]);
                }
            }
            NativeBooleanParameterDisposition::SameReturnAcrossPairedInputs => {
                assert!(!changed.contains(&entry.parameter.as_str()));
            }
        }
    }
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R08-001`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R08
#[test]
fn admitted_boolean_return_matches_frozen_native_tables() {
    let fixtures: Value = serde_json::from_slice(CASES).unwrap();
    let cases: Vec<Fixture> = serde_json::from_value(fixtures["cases"].clone()).unwrap();
    assert_eq!(cases.len(), 17);
    for case in cases {
        let outcome = replay(&case);
        let NativeBodyOutcome::Lowered(body) = outcome else {
            let NativeBodyOutcome::Unavailable(reason) = outcome else {
                unreachable!();
            };
            assert_eq!(reason.code(), case.model);
            continue;
        };
        let observed = inspect_native_boolean_sensitivity(&body);
        assert_eq!(observed, inspect_native_boolean_sensitivity(&body));
        if case.model == "complete" {
            compare_table(&case, observed);
            continue;
        }
        let reason = match case.model.as_str() {
            "INCOMPLETE_VALUATION" => NativeBooleanSensitivityReason::IncompleteValuation,
            "UNSUPPORTED_SCALAR_SCOPE" => NativeBooleanSensitivityReason::UnsupportedScalarScope,
            "PARAMETER_COUNT" => NativeBooleanSensitivityReason::ParameterCount,
            _ => panic!("unexpected lowered fixture {}: {}", case.case, case.model),
        };
        assert_eq!(
            observed,
            NativeBooleanSensitivity::Unavailable {
                occurrence_ref: body.binding().into(),
                reason
            }
        );
        assert!(
            serde_json::to_value(observed)
                .unwrap()
                .get("parameters")
                .is_none()
        );
    }
}

fn location(source: &str, start: usize, end: usize) -> Value {
    let preceding = &source[..start];
    let line = preceding.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let col = preceding
        .rfind('\n')
        .map_or(start + 1, |previous| start - previous);
    json!({"path":PATH,"start_byte":start,"end_byte":end,"start_line":line,"start_byte_column":col})
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R08-002`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R08
#[test]
fn structurally_admitted_residual_branch_never_yields_a_partial_comparison() {
    let source = "def selected(flag):\n    if flag:\n        return True\n";
    let symbol = source.find("selected").unwrap();
    let parameter = source.find("flag").unwrap();
    let conditional = source.find("if flag").unwrap();
    let returned = source.find("return True").unwrap();
    let reply = json!({
        "status":"LOWERABLE",
        "symbol":{"name":"selected","span":location(source,symbol,symbol+"selected".len()),
                  "declaration_span":location(source,0,source.len()-1)},
        "parameters":[{"name":"flag","scalar":"BOOL","span":location(source,parameter,parameter+4)}],
        "locals":[],"result_scalar":"BOOL",
        "body":[{"kind":"if","condition":{"kind":"binding","name":"flag"},
                 "span":location(source,conditional,source.len()-1),
                 "then_branch":[{"kind":"return","value":{"kind":"boolean","value":true},
                                  "span":location(source,returned,source.len()-1)}],"else_branch":[]}]
    });
    let input = NativeBodyInput {
        language: NativeBodyLanguage::Python,
        evaluation: &EvaluationKey::new(REF, REF, REF),
        exchange_ref: REF,
        producer_ref: REF,
        source_path: PATH,
        source_ref: &digest(source.as_bytes()),
        source: source.as_bytes(),
        python_bool_parameters: &["flag"],
    };
    let NativeBodyOutcome::Lowered(body) =
        input.admit(&serde_json::to_vec(&reply).unwrap()).unwrap()
    else {
        panic!("the structural test must reach the finite interpreter");
    };
    assert!(infer_native_scalar_output(&body).is_none());
    assert_eq!(
        inspect_native_boolean_sensitivity(&body),
        NativeBooleanSensitivity::Unavailable {
            occurrence_ref: body.binding().into(),
            reason: NativeBooleanSensitivityReason::IncompleteValuation,
        }
    );
}
