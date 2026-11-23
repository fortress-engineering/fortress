//! Exact lexical boundary controls with independently specified source and facts.

use fortress_core::observation::SourceView;
use fortress_core::project::EvaluationKey;
use fortress_core::source_architecture::python_lexical::{
    PythonGrammar, PythonLexicalError, PythonLexicalMode, PythonLexicalObservation,
    PythonLexicalOutcome, PythonLexicalProducer, PythonLexicalRequest,
};
use serde_json::{Value, json};

const SOURCE: &str = "def position(fn):\r\n    π = 1; return fn(π)\r\n";
const PATH: &str = "pkg/source.py";

fn identity(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn evaluation(context: char) -> EvaluationKey {
    EvaluationKey::new(identity('a'), identity(context), identity('c'))
}

fn producer() -> PythonLexicalProducer {
    PythonLexicalProducer::new(PythonGrammar::Cpython313, identity('d'), identity('e'))
        .expect("fixture producer pins")
}

fn view(source: &[u8]) -> SourceView {
    SourceView::from_bytes([(PATH, source.to_vec())]).expect("fixture source view")
}

fn request(view: &SourceView, mode: PythonLexicalMode) -> PythonLexicalRequest {
    PythonLexicalRequest::for_source(view, &evaluation('b'), PATH, mode, producer())
        .expect("fixture lexical request")
}

fn report(request: &PythonLexicalRequest, byte_count: usize) -> Value {
    json!({
        "schema": "fortress-research/python-lexical-response/1",
        "id": request.id(),
        "source_ref": request.source_ref(),
        "byte_count": byte_count,
        "runtime_ref": request.runtime_ref(),
        "worker_ref": request.worker_ref(),
        "mode": "LEXICAL",
        "outcome": "LEXICAL",
        "stages": {
            "SYNTAX": {"status": "COMPLETE"},
            "LEXICAL_SCOPE": {"status": "COMPLETE"},
            "MODULE_VALIDITY": {"status": "COMPLETE"}
        },
        "observations": {
            "imports": [],
            "scopes": [
                {"id": "s0", "parent": null, "kind": "Module", "name": "top", "span": null,
                 "bindings": [{"name": "position", "flags": ["assigned", "global", "local", "namespace"]}]},
                {"id": "s1", "parent": "s0", "kind": "FunctionDef", "name": "position", "span": [1, 0, 2, 25],
                 "bindings": [{"name": "fn", "flags": ["local", "parameter", "referenced"]},
                              {"name": "π", "flags": ["assigned", "local", "referenced"]}]}
            ],
            "constructs": [
                {"scope": "s1", "kind": "NameStore", "spelling": "π", "span": [2, 4, 2, 6]},
                {"scope": "s1", "kind": "Call", "spelling": "Name:fn", "target": "UNRESOLVED", "span": [2, 19, 2, 25]}
            ],
            "limitations": []
        },
        "target_execution": "NOT_RUN",
        "runtime_limitations": ["IMPORT_TARGETS", "RUNTIME_CALL_TARGETS", "EFFECTS", "EXECUTION"]
    })
}

fn admit(
    request: &PythonLexicalRequest,
    view: &SourceView,
    value: &Value,
) -> Result<PythonLexicalObservation, PythonLexicalError> {
    PythonLexicalObservation::admit(
        request,
        view,
        &evaluation('b'),
        &serde_json::to_vec(value).expect("fixture serializes"),
    )
}

fn not_run() -> Value {
    json!({ "status": "NOT_RUN" })
}

/// T-AF-SOURCE-ARCHITECTURE-0001-R05-001
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R05
#[test]
fn lexical_observation_keeps_exact_utf8_and_runtime_uncertainty() {
    let view = view(SOURCE.as_bytes());
    let request = request(&view, PythonLexicalMode::Lexical);
    let value = report(&request, SOURCE.len());
    let actual = admit(&request, &view, &value).expect("independently stated lexical facts");
    let expected = actual.to_canonical_json().expect("deterministic sidecar");
    assert_eq!(actual.outcome(), PythonLexicalOutcome::Lexical);
    assert_eq!(
        expected,
        admit(&request, &view, &value)
            .expect("same exact observation")
            .to_canonical_json()
            .expect("deterministic bytes")
    );
    let document: Value = serde_json::from_slice(&expected).expect("sidecar JSON");
    assert_eq!(document["request"]["source_view_ref"], view.digest());
    assert_eq!(
        document["request"]["evaluation_ref"],
        evaluation('b').digest()
    );
    assert_eq!(document["request"]["source_path"], PATH);
    assert_eq!(
        document["report"]["observations"]["constructs"][1]["span"],
        json!([2, 19, 2, 25])
    );
    assert_eq!(
        document["report"]["observations"]["constructs"][1]["target"],
        "UNRESOLVED"
    );
    assert_eq!(document["report"]["target_execution"], "NOT_RUN");
}

/// T-AF-SOURCE-ARCHITECTURE-0001-R05-002
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R05
#[test]
fn lexical_report_cannot_move_across_views_contexts_or_producers() {
    let original = view(SOURCE.as_bytes());
    let pinned = request(&original, PythonLexicalMode::Lexical);
    let value = report(&pinned, SOURCE.len());
    let moved_view = SourceView::from_bytes([
        (PATH, SOURCE.as_bytes().to_vec()),
        ("pkg/another_source.py", b"x = 1\n".to_vec()),
    ])
    .expect("different exact inventory with same subject bytes");
    assert!(matches!(
        admit(&pinned, &moved_view, &value),
        Err(PythonLexicalError::StaleInput)
    ));
    assert!(matches!(
        PythonLexicalObservation::admit(
            &pinned,
            &original,
            &evaluation('f'),
            &serde_json::to_vec(&value).expect("fixture serializes"),
        ),
        Err(PythonLexicalError::StaleInput)
    ));
    for field in ["source_ref", "id", "runtime_ref", "worker_ref"] {
        let mut changed = value.clone();
        changed[field] = json!(identity('0'));
        assert!(
            matches!(
                admit(&pinned, &original, &changed),
                Err(PythonLexicalError::InvalidBinding)
            ),
            "{field}"
        );
    }
    let other = PythonLexicalRequest::for_source(
        &original,
        &evaluation('f'),
        PATH,
        PythonLexicalMode::Lexical,
        producer(),
    )
    .expect("changed context is a separate request");
    assert_ne!(other.id(), pinned.id());
}

/// T-AF-SOURCE-ARCHITECTURE-0001-R05-003
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R05
#[test]
fn lexical_mode_separates_contextual_invalidity_from_syntax_admission() {
    // A missing nonlocal binding is grammatically valid and rejected at scope.
    let source = b"def example():\n    nonlocal missing\n";
    let original = view(source);
    let syntax = request(&original, PythonLexicalMode::Syntax);
    let lexical = request(&original, PythonLexicalMode::Lexical);
    let mut syntax_only = report(&syntax, source.len());
    syntax_only["mode"] = json!("SYNTAX");
    syntax_only["outcome"] = json!("SYNTAX_ONLY");
    syntax_only["reason"] = json!("LEXICAL_AND_MODULE_VALIDITY_NOT_ADMITTED");
    syntax_only["observations"] = Value::Null;
    syntax_only["stages"]["LEXICAL_SCOPE"] = not_run();
    syntax_only["stages"]["MODULE_VALIDITY"] = not_run();
    assert_eq!(
        admit(&syntax, &original, &syntax_only)
            .expect("syntax-only")
            .outcome(),
        PythonLexicalOutcome::SyntaxOnly
    );
    let mut invalid = report(&lexical, source.len());
    invalid["outcome"] = json!("INVALID_SOURCE");
    invalid["observations"] = Value::Null;
    invalid["stages"]["LEXICAL_SCOPE"] =
        json!({ "status": "INVALID", "reason": "SyntaxError", "line": 2 });
    invalid["stages"]["MODULE_VALIDITY"] = not_run();
    assert_eq!(
        admit(&lexical, &original, &invalid)
            .expect("scoped invalidity")
            .outcome(),
        PythonLexicalOutcome::InvalidSource
    );
    invalid["stages"]["MODULE_VALIDITY"] = json!({ "status": "COMPLETE" });
    assert!(matches!(
        admit(&lexical, &original, &invalid),
        Err(PythonLexicalError::InvalidReport)
    ));
}

/// T-AF-SOURCE-ARCHITECTURE-0001-R05-004
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R05
#[test]
fn partial_unsupported_and_unavailable_preserve_distinct_limits() {
    let source = b"x = lambda y: y\n";
    let original = view(source);
    let pinned = request(&original, PythonLexicalMode::Lexical);
    let mut partial = report(&pinned, source.len());
    partial["outcome"] = json!("PARTIAL");
    partial["observations"] = json!({
        "scopes": [{"id": "s0", "parent": null, "kind": "Module", "name": "top",
                    "span": null, "bindings": [{"name": "x", "flags": ["assigned", "global", "local"]}]}],
        "imports": [],
        "constructs": [{"scope": "s0", "kind": "NameStore", "spelling": "x", "span": [1, 0, 1, 1]}],
        "limitations": [{"scope": "s0", "code": "UNMODELED_SCOPE_FORM", "kind": "Lambda",
                         "span": [1, 4, 1, 15]}]
    });
    assert_eq!(
        admit(&pinned, &original, &partial)
            .expect("partial")
            .outcome(),
        PythonLexicalOutcome::Partial
    );
    partial["outcome"] = json!("LEXICAL");
    assert!(matches!(
        admit(&pinned, &original, &partial),
        Err(PythonLexicalError::InvalidReport)
    ));

    let encoded_source = b"\xef\xbb\xbfx = 1\n";
    let encoded = view(encoded_source);
    let encoded_pin = request(&encoded, PythonLexicalMode::Lexical);
    let mut unsupported = report(&encoded_pin, encoded_source.len());
    unsupported["outcome"] = json!("UNSUPPORTED");
    unsupported["reason"] = json!("UNSUPPORTED_UTF8_BOM");
    unsupported["observations"] = Value::Null;
    unsupported["stages"] = json!({
        "SYNTAX": not_run(),
        "LEXICAL_SCOPE": not_run(),
        "MODULE_VALIDITY": not_run()
    });
    assert_eq!(
        admit(&encoded_pin, &encoded, &unsupported)
            .expect("unsupported")
            .outcome(),
        PythonLexicalOutcome::Unsupported
    );
    let mut unavailable = report(&pinned, source.len());
    unavailable["outcome"] = json!("UNAVAILABLE");
    unavailable["reason"] = json!("TOKEN_OR_NESTING_LIMIT");
    unavailable["stages"] = unsupported["stages"].clone();
    unavailable["observations"] = Value::Null;
    assert_eq!(
        admit(&pinned, &original, &unavailable)
            .expect("unavailable")
            .outcome(),
        PythonLexicalOutcome::Unavailable
    );

    let mut custody_failure = unavailable.clone();
    custody_failure["reason"] = json!("RUNTIME_BINDING_MISMATCH");
    assert!(admit(&pinned, &original, &custody_failure).is_ok());
    let all_complete = report(&pinned, source.len())["stages"].clone();
    custody_failure["stages"] = all_complete.clone();
    assert!(matches!(
        admit(&pinned, &original, &custody_failure),
        Err(PythonLexicalError::InvalidReport)
    ));

    let mut output_failure = unavailable;
    output_failure["reason"] = json!("OUTPUT_LIMIT");
    assert!(matches!(
        admit(&pinned, &original, &output_failure),
        Err(PythonLexicalError::InvalidReport)
    ));
    output_failure["stages"] = all_complete;
    assert_eq!(
        admit(&pinned, &original, &output_failure)
            .expect("unavailable output after lexical phases")
            .outcome(),
        PythonLexicalOutcome::Unavailable
    );
}

fn assert_bounded_json_admission(request: &PythonLexicalRequest, view: &SourceView) {
    // Each reply is well-formed, with a size far below the overall byte cap.
    // Excessive structure must be refused before a typed decoder allocates it.
    let over_depth = format!("{}null{}", "[".repeat(9), "]".repeat(9));
    let over_nodes = format!("[{}0]", "0,".repeat(180_000));
    let over_token = format!("\"{}\"", "a".repeat(3 * 4096 + 1));
    for (label, reply) in [
        ("depth", over_depth),
        ("nodes", over_nodes),
        ("token", over_token),
    ] {
        assert!(reply.len() < 1024 * 1024);
        assert!(
            matches!(
                PythonLexicalObservation::admit(request, view, &evaluation('b'), reply.as_bytes()),
                Err(PythonLexicalError::ResourceLimit)
            ),
            "{label}"
        );
    }
}

/// T-AF-SOURCE-ARCHITECTURE-0001-R05-005
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R05
#[test]
fn malformed_source_and_untrusted_worker_shape_fail_closed() {
    let original = view(SOURCE.as_bytes());
    let pinned = request(&original, PythonLexicalMode::Lexical);
    let valid = report(&pinned, SOURCE.len());
    for (scope, key, value) in [
        (
            "report",
            "schema",
            json!("fortress-research/python-lexical-response/2"),
        ),
        ("report", "target_execution", json!("RAN")),
        ("report", "runtime_limitations", json!([])),
        ("construct", "span", json!([2, 5, 2, 25])),
        ("construct", "target", json!("RESOLVED")),
        ("construct", "scope", json!("s99")),
        ("scope", "parent", json!("s1")),
        ("scope", "kind", json!("Module")),
    ] {
        let mut changed = valid.clone();
        match scope {
            "report" => changed[key] = value,
            "construct" => changed["observations"]["constructs"][1][key] = value,
            _ => changed["observations"]["scopes"][1][key] = value,
        }
        assert!(
            admit(&pinned, &original, &changed).is_err(),
            "{scope} {key}"
        );
    }
    let mut forged = valid.clone();
    forged["certification"] = json!("PASS");
    assert!(admit(&pinned, &original, &forged).is_err());
    let encoded = serde_json::to_string(&valid).expect("fixture JSON");
    let duplicate = format!(r#"{{"mode":"LEXICAL",{}"#, &encoded[1..]);
    assert!(
        PythonLexicalObservation::admit(&pinned, &original, &evaluation('b'), duplicate.as_bytes())
            .is_err()
    );
    assert!(matches!(
        PythonLexicalObservation::admit(
            &pinned,
            &original,
            &evaluation('b'),
            &vec![b' '; 1024 * 1024 + 1]
        ),
        Err(PythonLexicalError::ResourceLimit)
    ));

    assert_bounded_json_admission(&pinned, &original);

    let invalid_source = b"\xff";
    let invalid_view = view(invalid_source);
    let invalid_pin = request(&invalid_view, PythonLexicalMode::Lexical);
    let mut invalid = report(&invalid_pin, invalid_source.len());
    let false_lexical = admit(&invalid_pin, &invalid_view, &invalid);
    assert!(matches!(
        false_lexical,
        Err(PythonLexicalError::InvalidReport)
    ));
    invalid["outcome"] = json!("INVALID_SOURCE");
    invalid["observations"] = Value::Null;
    invalid["stages"] = json!({
        "SYNTAX": { "status": "INVALID", "reason": "INVALID_UTF8" },
        "LEXICAL_SCOPE": not_run(),
        "MODULE_VALIDITY": not_run(),
    });
    assert_eq!(
        admit(&invalid_pin, &invalid_view, &invalid)
            .expect("invalid UTF-8")
            .outcome(),
        PythonLexicalOutcome::InvalidSource
    );
}

/// T-AF-SOURCE-ARCHITECTURE-0001-R05-006
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R05
#[test]
fn lexical_selection_uses_existing_portable_source_scope() {
    let observed = SourceView::from_bytes([
        ("pkg/source.py", b"x = 1\n".to_vec()),
        ("pkg/types.pyi", b"x: int\n".to_vec()),
        ("__Fortress/control.py", b"x = 2\n".to_vec()),
        ("pkg/huge.py", vec![b' '; 128 * 1024 + 1]),
    ])
    .expect("immutable fixture");
    let select = |path| {
        PythonLexicalRequest::for_source(
            &observed,
            &evaluation('b'),
            path,
            PythonLexicalMode::Lexical,
            producer(),
        )
    };
    for path in [
        "pkg/types.pyi",
        "__Fortress/control.py",
        "../outside.py",
        "pkg\\source.py",
    ] {
        assert!(
            matches!(select(path), Err(PythonLexicalError::UnsupportedSource)),
            "{path}"
        );
    }
    assert!(matches!(
        select("pkg/missing.py"),
        Err(PythonLexicalError::MissingSource)
    ));
    assert!(matches!(
        select("pkg/huge.py"),
        Err(PythonLexicalError::ResourceLimit)
    ));
    assert!(matches!(
        PythonLexicalProducer::new(
            PythonGrammar::Cpython313,
            "unvalidated-issuer",
            identity('e')
        ),
        Err(PythonLexicalError::InvalidBinding)
    ));
}
