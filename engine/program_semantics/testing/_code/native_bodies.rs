//! Independent boundary controls for shared scalar body admission.

use fortress_core::program_semantics::native_body::{
    NativeBodyError, NativeBodyInput, NativeBodyLanguage, NativeBodyOutcome, NativeScalar,
};
use fortress_core::program_semantics::{ProgramExpression, ProgramStatement};
use fortress_core::project::EvaluationKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const REF: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ALTERNATE: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Fixture<'a> {
    language: NativeBodyLanguage,
    path: &'a str,
    text: &'a str,
    expected_parameters: &'a [&'a str],
    evaluation: EvaluationKey,
    digest: String,
}

impl<'a> Fixture<'a> {
    fn new(
        language: NativeBodyLanguage,
        path: &'a str,
        text: &'a str,
        expected_parameters: &'a [&'a str],
    ) -> Self {
        Self {
            language,
            path,
            text,
            expected_parameters,
            evaluation: EvaluationKey::new(REF, REF, REF),
            digest: format!("sha256:{:x}", Sha256::digest(text)),
        }
    }

    fn input(&self) -> NativeBodyInput<'_> {
        NativeBodyInput {
            language: self.language,
            evaluation: &self.evaluation,
            exchange_ref: REF,
            producer_ref: REF,
            source_path: self.path,
            source_ref: &self.digest,
            source: self.text.as_bytes(),
            python_bool_parameters: self.expected_parameters,
        }
    }

    fn span(&self, snippet: &str, after: usize) -> Value {
        let start = after
            + self.text[after..]
                .find(snippet)
                .expect("exact fixture span");
        let preceding = &self.text.as_bytes()[..start];
        let line = self.text[..start].split('\n').count();
        let line_start = preceding
            .iter()
            .rposition(|&byte| byte == b'\n')
            .map_or(0, |i| i + 1);
        json!({
            "path": self.path,
            "start_byte": start,
            "end_byte": start + snippet.len(),
            "start_line": line,
            "start_byte_column": start - line_start + 1
        })
    }

    fn admit(&self, payload: &Value) -> Result<NativeBodyOutcome, NativeBodyError> {
        self.input()
            .admit(&serde_json::to_vec(payload).expect("fixture JSON"))
    }
}

fn go() -> (Fixture<'static>, Value) {
    let function =
        "func Box(v bool) int64 {\r\n  if !v {\r\n    return -9\r\n  }\r\n  return 7\r\n}";
    let text = "package p\r\n// π exact coordinates\r\nfunc Box(v bool) int64 {\r\n  if !v {\r\n    return -9\r\n  }\r\n  return 7\r\n}";
    let fixture = Fixture::new(NativeBodyLanguage::Go, "src/probe.go", text, &[]);
    let declarations = fixture.span(function, 0);
    let start = text.len() - function.len();
    let payload = json!({
        "status":"LOWERABLE",
        "symbol":{"name":"Box","span":fixture.span("Box", start),"declaration_span":declarations},
        "parameters":[{"name":"v","scalar":"BOOL","span":fixture.span("v", start)}],
        "result_scalar":"SIGNED_I64",
        "locals":[],
        "body":[
            {
                "kind":"if",
                "span":fixture.span("if !v {\r\n    return -9\r\n  }", start),
                "condition":{"kind":"unary","operator":"!","value":{"kind":"binding","name":"v"}},
                "then_branch":[{
                    "kind":"return", "span":fixture.span("return -9", start),
                    "value":{"kind":"integer","value":"-9"}
                }],
                "else_branch":[]
            },
            {
                "kind":"return", "span": fixture.span("return 7", start),
                "value":{"kind":"integer","value":"7"}
            }
        ]
    });
    (fixture, payload)
}

fn python() -> (Fixture<'static>, Value) {
    let fixture = Fixture::new(
        NativeBodyLanguage::Python,
        "src/probe.py",
        "def invert(a):\n    local = not a\n    return local\n",
        &["a"],
    );
    let payload = json!({
        "status":"LOWERABLE",
        "symbol":{
            "name":"invert","span":fixture.span("invert", 0),
            "declaration_span": fixture.span("def invert(a):\n    local = not a\n    return local", 0)
        },
        "parameters":[{"name":"a","scalar":"BOOL","span":fixture.span("a", 0)}],
        "result_scalar":"BOOL",
        "locals":[{"name":"local","scalar":"BOOL","span":fixture.span("local", 0)}],
        "body":[
            {
                "kind":"let","span":fixture.span("local = not a", 0),
                "pattern":{"kind":"binding","name":"local"},
                "value":{"kind":"unary","operator":"!","value":{"kind":"binding","name":"a"}}
            },
            {
                "kind":"return","span":fixture.span("return local", 0),
                "value":{"kind":"binding","name":"local"}
            }
        ]
    });
    (fixture, payload)
}

fn lowered(
    value: NativeBodyOutcome,
) -> Box<fortress_core::program_semantics::native_body::NativeScalarBody> {
    match value {
        NativeBodyOutcome::Lowered(value) => value,
        NativeBodyOutcome::Unavailable(_) => panic!("expected the admitted owner body"),
    }
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R11-001`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R11
#[test]
fn distinct_native_premises_use_the_same_owner_body() {
    let (go, go_reply) = go();
    let got = lowered(go.admit(&go_reply).unwrap());
    assert_eq!(got.parameters(), &[("v".into(), NativeScalar::Bool)]);
    assert_eq!(got.result(), NativeScalar::SignedI64);
    assert_eq!(got.body().symbol(), got.binding());

    let [
        ProgramStatement::If {
            then_branch,
            provenance,
            ..
        },
        ProgramStatement::Return { .. },
    ] = got.body().statements()
    else {
        panic!("unexpected Go body shape");
    };
    assert_eq!(provenance.location().line(), 4);
    assert_eq!(provenance.location().column(), 3);
    assert!(matches!(
        then_branch.as_slice(), [ProgramStatement::Return { value: Some(ProgramExpression::Integer { value }), .. }] if value == "-9"
    ));

    let (python, python_reply) = python();
    let found = lowered(python.admit(&python_reply).unwrap());
    assert_eq!(found.parameters(), &[("a".into(), NativeScalar::Bool)]);
    assert_eq!(found.locals(), &[("local".into(), NativeScalar::Bool)]);
    assert_eq!(found.result(), NativeScalar::Bool);
    assert!(matches!(
        found.body().statements(),
        [
            ProgramStatement::Let { .. },
            ProgramStatement::Return { .. }
        ]
    ));
    assert_ne!(got.binding(), found.binding());
    let replay = lowered(python.admit(&python_reply).unwrap());
    assert_eq!(found.binding(), replay.binding());
    assert_eq!(found.body(), replay.body());
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R11-002`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R11
#[test]
fn native_binding_checks_and_occurrence_identity_are_exact() {
    let (fixture, reply) = python();
    let encoded = serde_json::to_vec(&reply).unwrap();
    let baseline = lowered(fixture.input().admit(&encoded).unwrap());
    let change = EvaluationKey::new(REF, ALTERNATE, REF);
    let other_context = NativeBodyInput {
        evaluation: &change,
        ..fixture.input()
    };
    let other_producer = NativeBodyInput {
        producer_ref: ALTERNATE,
        ..fixture.input()
    };
    let other_exchange = NativeBodyInput {
        exchange_ref: ALTERNATE,
        ..fixture.input()
    };
    for input in [other_context, other_producer, other_exchange] {
        assert_ne!(
            baseline.binding(),
            lowered(input.admit(&encoded).unwrap()).binding()
        );
    }
    for input in [
        NativeBodyInput {
            source_ref: ALTERNATE,
            ..fixture.input()
        },
        NativeBodyInput {
            source: b"modified",
            ..fixture.input()
        },
        NativeBodyInput {
            source_path: "../probe.py",
            ..fixture.input()
        },
    ] {
        assert_eq!(
            input.admit(&encoded).unwrap_err(),
            NativeBodyError::InvalidBinding
        );
    }
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R11-003`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R11
#[test]
fn unsupported_scalar_operations_and_bad_provenance_cannot_lower() {
    let (fixture, original) = go();
    for (pointer, value) in [
        ("/symbol/span/start_byte_column", json!(32)),
        ("/symbol/span/path", json!("another.go")),
        (
            "/body/0/then_branch/0/value/value",
            json!("9223372036854775808"),
        ),
        ("/body/0/then_branch/0/value/value", json!("-0")),
        (
            "/body/0/then_branch/0/value",
            json!({"kind":"call","reference":"other","arguments":[]}),
        ),
        ("/body/0/condition/operator", json!("-")),
        ("/body/0/condition/value/name", json!("absent")),
        ("/body/1/span", fixture.span("package p", 0)),
    ] {
        let mut bad = original.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            fixture.admit(&bad).unwrap_err(),
            NativeBodyError::InvalidResponse,
            "{pointer}"
        );
    }

    let (fixture, python) = python();
    let encoded = serde_json::to_vec(&python).unwrap();
    let no_assumptions = NativeBodyInput {
        python_bool_parameters: &[],
        ..fixture.input()
    };
    assert_eq!(
        no_assumptions.admit(&encoded).unwrap_err(),
        NativeBodyError::InvalidResponse
    );
    let mut signed = python;
    signed["parameters"][0]["scalar"] = json!("SIGNED_I64");
    assert_eq!(
        fixture.admit(&signed).unwrap_err(),
        NativeBodyError::InvalidResponse
    );
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R11-004`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R11
#[test]
fn unavailable_results_are_not_empty_success_or_partial_bodies() {
    let (fixture, reply) = python();
    let mut unavailable = json!({
        "status":"UNAVAILABLE","symbol":reply["symbol"],"parameters":[],"locals":[],"body":[],
        "diagnostic":{"code":"NATIVE_UNSUPPORTED","span":fixture.span("not a", 0)}
    });
    let NativeBodyOutcome::Unavailable(result) = fixture.admit(&unavailable).unwrap() else {
        panic!("an unavailable report cannot lower");
    };
    assert_eq!(result.code(), "NATIVE_UNSUPPORTED");
    assert_eq!(result.location().unwrap().line(), 2);

    unavailable["body"] = reply["body"].clone();
    assert_eq!(
        fixture.admit(&unavailable).unwrap_err(),
        NativeBodyError::InvalidResponse
    );
    let duplicate = br#"{"status":"UNAVAILABLE","status":"LOWERABLE"}"#;
    assert_eq!(
        fixture.input().admit(duplicate).unwrap_err(),
        NativeBodyError::InvalidResponse
    );
    let oversized = vec![b' '; 128 * 1024 + 1];
    assert_eq!(
        fixture.input().admit(&oversized).unwrap_err(),
        NativeBodyError::ResourceLimit
    );
}
