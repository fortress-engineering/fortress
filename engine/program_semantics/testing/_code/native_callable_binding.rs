//! Exact source and evaluation controls for native declaration links.

use super::{NativeCallableLimitation, NativeCallableOutcome, VerifiedCallableLink};
use crate::program_semantics::native_body::{
    NativeBodyError, NativeBodyInput, NativeBodyLanguage, NativeBodyOutcome, NativeCallBindings,
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

/// `T-AF-PROGRAM-SEMANTICS-0001-R11-006`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R11
#[test]
fn native_calls_reject_mixed_evaluations_exchanges_and_declarations() {
    const CALL_SOURCE: &str =
        "def outer():\n    def helper():\n        return True\n    return helper()\n";
    let file_ref = format!("sha256:{:x}", Sha256::digest(CALL_SOURCE.as_bytes()));
    let evaluation = EvaluationKey::new(PIN, PIN, PIN);
    let input = NativeBodyInput {
        language: NativeBodyLanguage::Python,
        evaluation: &evaluation,
        exchange_ref: PIN,
        producer_ref: PIN,
        source_path: PATH,
        source_ref: &file_ref,
        source: CALL_SOURCE.as_bytes(),
        python_bool_parameters: &[],
    };
    let span = |start: usize, end: usize| {
        let prefix = &CALL_SOURCE[..start];
        let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
        let column = prefix.rsplit('\n').next().unwrap().len() + 1;
        json!({"path":PATH,"start_byte":start,"end_byte":end,
               "start_line":line,"start_byte_column":column})
    };
    let inner_start = CALL_SOURCE.find("def helper").unwrap();
    let inner_end = CALL_SOURCE.find("True").unwrap() + 4;
    let inner = json!({
        "name":"helper","span":span(inner_start + 4, inner_start + 10),
        "declaration_span":span(inner_start,inner_end),
    });
    let outer_end = CALL_SOURCE.trim_end().len();
    let caller_reply = serde_json::to_vec(&json!({
        "status":"LOWERABLE",
        "symbol":{"name":"outer","span":span(4,9),"declaration_span":span(0,outer_end)},
        "parameters":[],"result_scalar":"BOOL","locals":[],
        "body":[{"kind":"return","span":span(CALL_SOURCE.rfind("return").unwrap(),outer_end),
                 "value":{"kind":"call","call":{
                    "span":span(CALL_SOURCE.rfind("helper").unwrap(),outer_end),
                    "target":inner,"arguments":[]
                 }}}],
    }))
    .unwrap();
    let target_reply = serde_json::to_vec(&json!({
        "status":"LOWERABLE","symbol":inner,
        "parameters":[],"result_scalar":"BOOL","locals":[],
        "body":[{"kind":"return","span":span(CALL_SOURCE.find("return").unwrap(),inner_end),
                 "value":{"kind":"boolean","value":true}}],
    }))
    .unwrap();
    let lower = |scope: &NativeBodyInput<'_>, reply: &[u8]| {
        let NativeBodyOutcome::Lowered(body) = scope.admit_bound_calls(reply).unwrap() else {
            panic!("the exact Boolean fixtures must lower");
        };
        body
    };
    let caller = lower(&input, &caller_reply);
    let helper = lower(&input, &target_reply);
    let [site] = caller.bound_calls() else {
        panic!("the declared source has one call");
    };

    let rejects = |changed: &NativeBodyInput<'_>| {
        let incompatible = lower(changed, &target_reply);
        let mut bindings = NativeCallBindings::default();
        assert_eq!(
            bindings.insert(&caller, site, Some(&incompatible)),
            Err(NativeBodyError::InvalidResponse)
        );
        assert!(bindings.target(&caller, site).is_none());
    };
    for changed in [
        EvaluationKey::new(CHANGED, PIN, PIN),
        EvaluationKey::new(PIN, CHANGED, PIN),
        EvaluationKey::new(PIN, PIN, CHANGED),
    ] {
        rejects(&NativeBodyInput {
            evaluation: &changed,
            ..input
        });
    }
    rejects(&NativeBodyInput {
        exchange_ref: CHANGED,
        ..input
    });
    rejects(&NativeBodyInput {
        producer_ref: CHANGED,
        ..input
    });

    let mut bindings = NativeCallBindings::default();
    assert_eq!(
        bindings.insert(&caller, site, Some(&caller)),
        Err(NativeBodyError::InvalidResponse)
    );
    bindings.insert(&caller, site, Some(&helper)).unwrap();
    assert_eq!(
        bindings.insert(&caller, site, None),
        Err(NativeBodyError::InvalidResponse)
    );
    assert_eq!(
        bindings.target(&caller, site).unwrap().binding(),
        helper.binding()
    );
    assert!(bindings.target(&helper, site).is_none());
}
