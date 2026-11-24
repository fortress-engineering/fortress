//! Exact source and evaluation controls for native declaration links.

use super::{NativeCallableLimitation, NativeCallableOutcome, VerifiedCallableLink};
use crate::program_semantics::native_body::{
    NativeBodyInput, NativeBodyLanguage, NativeBodyOutcome,
};
use crate::project::EvaluationKey;
use serde_json::json;
use sha2::{Digest, Sha256};

const SOURCE: &str = "def selected():\n    return True\n";
const PATH: &str = "subject.py";
const PIN: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CHANGED: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn literal_reply() -> Vec<u8> {
    let end = SOURCE.trim_end().len();
    let value = SOURCE.find("return").unwrap();
    let span = |start, end, line, column| {
        json!({"path":PATH,"start_byte":start,"end_byte":end,
               "start_line":line,"start_byte_column":column})
    };
    serde_json::to_vec(&json!({
        "status":"LOWERABLE",
        "symbol":{
            "name":"selected",
            "span":span(4, 12, 1, 5),
            "declaration_span":span(0, end, 1, 1),
        },
        "parameters":[],"result_scalar":"BOOL","locals":[],
        "body":[{"kind":"return","span":span(value, end, 2, 5),
            "value":{"kind":"boolean","value":true}}],
    }))
    .unwrap()
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R11-005`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R11
#[test]
fn native_callable_requires_the_retained_exact_declaration_and_evaluation() {
    let source_ref = format!("sha256:{:x}", Sha256::digest(SOURCE.as_bytes()));
    let evaluation = EvaluationKey::new(PIN, PIN, PIN);
    let input = NativeBodyInput {
        language: NativeBodyLanguage::Python,
        evaluation: &evaluation,
        exchange_ref: PIN,
        producer_ref: PIN,
        source_path: PATH,
        source_ref: &source_ref,
        source: SOURCE.as_bytes(),
        python_bool_parameters: &[],
    };
    let reply = literal_reply();
    let lower = || {
        let NativeBodyOutcome::Lowered(body) = input.admit(&reply).unwrap() else {
            panic!("the literal body must lower");
        };
        body
    };
    let exact = VerifiedCallableLink {
        language: NativeBodyLanguage::Python,
        namespace: "subject",
        function: "selected",
        source_path: PATH,
        source_ref: &source_ref,
        origin_ref: PIN,
        exchange_ref: PIN,
    };
    let refuses = |binding: VerifiedCallableLink<'_>, selected: EvaluationKey| {
        assert!(matches!(
            binding.attach(selected, lower()),
            NativeCallableOutcome::Unavailable(NativeCallableLimitation::OccurrenceUnresolved)
        ));
    };
    for changed in [
        VerifiedCallableLink {
            function: "different",
            ..exact
        },
        VerifiedCallableLink {
            source_path: "different.py",
            ..exact
        },
        VerifiedCallableLink {
            source_ref: CHANGED,
            ..exact
        },
        VerifiedCallableLink {
            language: NativeBodyLanguage::Go,
            ..exact
        },
    ] {
        refuses(changed, evaluation.clone());
    }
    for changed in [
        EvaluationKey::new(CHANGED, PIN, PIN),
        EvaluationKey::new(PIN, CHANGED, PIN),
        EvaluationKey::new(PIN, PIN, CHANGED),
    ] {
        refuses(VerifiedCallableLink { ..exact }, changed);
    }
    let NativeCallableOutcome::Linked(linked) = exact.attach(evaluation.clone(), lower()) else {
        panic!("the independently selected declaration must link");
    };
    assert_eq!(linked.function(), "selected");
    assert_eq!(linked.source_ref(), source_ref);
    assert_eq!(linked.evaluation(), &evaluation);
}
