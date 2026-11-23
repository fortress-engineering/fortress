//! Frozen `CPython` `FileFinder` outcomes and exact root-admission controls.

use fortress_core::observation::SourceView;
use fortress_core::project::EvaluationKey;
use fortress_core::source_architecture::python_lexical::python_static_imports::{
    PythonImportRoots, PythonStaticImportError, PythonStaticImportObservation,
};
use fortress_core::source_architecture::python_lexical::{
    PythonGrammar, PythonLexicalMode, PythonLexicalObservation, PythonLexicalProducer,
    PythonLexicalRequest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FROZEN: &[u8] = include_bytes!("../_data/python_import_reference_v1.json");
const FROZEN_REF: &str = "sha256:90dbaaf6489a999ffa53aedb64c82014463764d22b83ab826cb5b4c1ac38d742";
const DEFAULT_ORIGIN: &str = "A/control_subject.py";

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn identity(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn evaluation(binding: char) -> EvaluationKey {
    EvaluationKey::new(identity('a'), identity('b'), identity(binding))
}

fn configuration(view: &SourceView, key: &EvaluationKey, roots: &Value) -> Value {
    json!({
        "schema": "fortress:python:static-import-roots:1",
        "source_view_ref": view.digest(),
        "evaluation_ref": key.digest(),
        "inventory": "COMPLETE_SOURCE_ONLY",
        "roots": roots,
    })
}

fn admit_roots(record: &Value) -> Result<PythonImportRoots, PythonStaticImportError> {
    let encoded = serde_json_canonicalizer::to_vec(record).expect("root configuration serializes");
    PythonImportRoots::admit(&encoded, &digest(&encoded))
}

fn imports(statement: &str) -> Vec<Value> {
    let span = json!([1, 0, 1, statement.len()]);
    let common = |form: &str, level: Value, module: Value, names: Value| {
        json!({"scope":"s0","form":form,"level":level,"module":module,"names":names,
               "target":"UNRESOLVED","span":span})
    };
    if let Some(imports) = statement.strip_prefix("import ") {
        if imports.contains("..") {
            return Vec::new();
        }
        let names = imports
            .split(", ")
            .map(|part| {
                let (name, alias) = part
                    .split_once(" as ")
                    .map_or((part, None), |(name, alias)| (name, Some(alias)));
                json!([name, alias])
            })
            .collect::<Vec<_>>();
        return vec![common("import", Value::Null, Value::Null, json!(names))];
    }
    if let Some(declaration) = statement.strip_prefix("from ") {
        let (module, member) = declaration
            .split_once(" import ")
            .expect("frozen from form");
        let suffix = module.trim_start_matches('.');
        return vec![common(
            "from",
            json!(module.len() - suffix.len()),
            json!((!suffix.is_empty()).then_some(suffix)),
            json!([[member, null]]),
        )];
    }
    Vec::new()
}

fn lexical(
    view: &SourceView,
    key: &EvaluationKey,
    origin: &str,
    statement: &str,
    invalid: bool,
) -> PythonLexicalObservation {
    let producer =
        PythonLexicalProducer::new(PythonGrammar::Cpython313, identity('d'), identity('e'))
            .expect("deterministic lexical fixture producer");
    let request =
        PythonLexicalRequest::for_source(view, key, origin, PythonLexicalMode::Lexical, producer)
            .expect("exact fixture request");
    let mut report = json!({
        "schema":"fortress-research/python-lexical-response/1",
        "id":request.id(),"source_ref":request.source_ref(),
        "byte_count":view.bytes(origin).expect("fixture origin").len(),
        "runtime_ref":request.runtime_ref(),"worker_ref":request.worker_ref(),
        "mode":"LEXICAL","outcome":"LEXICAL",
        "stages":{"SYNTAX":{"status":"COMPLETE"},"LEXICAL_SCOPE":{"status":"COMPLETE"},"MODULE_VALIDITY":{"status":"COMPLETE"}},
        "observations":{"imports":imports(statement),
    "scopes":[{"id":"s0","parent":null,"kind":"Module","name":"top","span":null,"bindings":[]}],
    "constructs":[],"limitations":[]},
        "target_execution":"NOT_RUN","runtime_limitations":["IMPORT_TARGETS","RUNTIME_CALL_TARGETS","EFFECTS","EXECUTION"],
    });
    if invalid {
        report["outcome"] = json!("INVALID_SOURCE");
        report["observations"] = Value::Null;
        report["stages"] = json!({
            "SYNTAX":{"status":"INVALID","reason":"SyntaxError","line":1},
            "LEXICAL_SCOPE":{"status":"NOT_RUN"},"MODULE_VALIDITY":{"status":"NOT_RUN"}
        });
    }
    PythonLexicalObservation::admit(
        &request,
        view,
        key,
        &serde_json::to_vec(&report).expect("report encoding"),
    )
    .expect("typed fixture lexical admission")
}

fn view_with(files: &[(&str, &[u8])]) -> SourceView {
    SourceView::from_bytes(
        [
            (DEFAULT_ORIGIN, b"import chosen\n".as_slice()),
            ("A/chosen.py", b"x=1\n".as_slice()),
        ]
        .into_iter()
        .chain(files.iter().copied())
        .map(|(path, bytes)| (path, bytes.to_vec())),
    )
    .expect("exact test view")
}

fn scoped_outcome(
    input: &Value,
    view: &SourceView,
    key: &EvaluationKey,
    lexical: &PythonLexicalObservation,
) -> Result<PythonStaticImportObservation, PythonStaticImportError> {
    let mut registration = configuration(view, key, &input["roots"]);
    if input["ordered"] == false {
        registration["roots"] = json!({"order":"UNAVAILABLE"});
    }
    if input["complete"] == false {
        registration["inventory"] = json!("INCOMPLETE");
    }
    let roots = admit_roots(&registration)?;
    PythonStaticImportObservation::evaluate(lexical, view, key, &roots)
}

fn check_frozen_result(
    expected: &Value,
    actual: Result<PythonStaticImportObservation, PythonStaticImportError>,
    view: &SourceView,
    key: &EvaluationKey,
) {
    use PythonStaticImportError as Error;
    let state = expected["state"].as_str().expect("frozen result state");
    let observation = match state {
        "ROOT_UNAVAILABLE" => {
            assert!(matches!(actual, Err(Error::RootUnavailable)));
            return;
        }
        "ROOT_ORDER_UNAVAILABLE" => {
            assert!(matches!(actual, Err(Error::Encoding(_))));
            return;
        }
        "ROOTS_OVERLAP" => {
            assert!(matches!(actual, Err(Error::AmbiguousRoots)));
            return;
        }
        "INVALID_ROOT_PATH" => {
            assert!(matches!(actual, Err(Error::InvalidRootPath)));
            return;
        }
        "SOURCE_INVENTORY_INCOMPLETE" => {
            assert!(matches!(actual, Err(Error::IncompleteInventory)));
            return;
        }
        "UNSUPPORTED_ROOT_CONTENT" => {
            assert!(matches!(actual, Err(Error::UnsupportedRootContent)));
            return;
        }
        "INVALID_STATEMENT" => {
            assert!(matches!(actual, Err(Error::LexicalUnavailable)));
            return;
        }
        _ => actual.expect("static sidecar at frozen inputs"),
    };
    if state == "DYNAMIC_UNRESOLVED" {
        assert!(
            observation.imports().is_empty(),
            "dynamic call was synthesized as an import"
        );
        return;
    }
    let bytes = observation
        .to_canonical_json()
        .expect("bounded canonical report");
    let actual: Value = serde_json::from_slice(&bytes).expect("encoded observation");
    assert_eq!(actual["lexical_request"]["source_view_ref"], view.digest());
    assert_eq!(actual["lexical_request"]["evaluation_ref"], key.digest());
    assert_eq!(
        actual["directory_coverage"],
        "IMPLIED_BY_ADMITTED_SOURCE_FILES"
    );
    let row = &actual["imports"][0];
    assert_eq!(row["runtime_resolution"], expected["runtime"]);
    let expected_member = expected["members"].as_str().expect("frozen member status");
    if expected_member == "NONE" {
        assert_eq!(row["member_resolution"], "NO_MEMBER");
    } else {
        assert_eq!(row["member_resolution"], expected_member);
    }
    let target = &row["static_targets"][0];
    assert_eq!(target["state"], state);
    assert_eq!(target["module"], expected["absolute"]);
    if state == "FILE_STATIC" {
        let path = expected["paths"][0].as_str().expect("frozen target path");
        assert_eq!(target["path"], path);
        assert_eq!(
            target["source_ref"],
            digest(view.bytes(path).expect("exact target bytes"))
        );
    }
    if state == "NAMESPACE_STATIC" {
        assert_eq!(target["portions"], expected["paths"]);
    }
}

/// T-AF-SOURCE-ARCHITECTURE-0001-R06-001
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R06
#[test]
fn static_import_resolution_matches_frozen_cpython_cases() {
    assert_eq!(digest(FROZEN), FROZEN_REF);
    let protocol: Value = serde_json::from_slice(FROZEN).expect("frozen cases decode");
    let fixture = protocol["fixture"]
        .as_object()
        .expect("frozen fixture files");
    let cases = protocol["cases"].as_array().expect("frozen cases");
    assert_eq!(cases.len(), 32);
    for case in cases {
        let statement = case["statement"].as_str().expect("frozen statement");
        let origin = case["origin"].as_str().unwrap_or(DEFAULT_ORIGIN);
        let files = fixture
            .iter()
            .filter(|(path, _)| path.as_str() != origin)
            .map(|(path, content)| {
                (
                    path.as_str(),
                    content.as_str().expect("exact source").as_bytes().to_vec(),
                )
            })
            .chain(std::iter::once((
                origin,
                format!("{statement}\n").into_bytes(),
            )));
        let view = SourceView::from_bytes(files).expect("exact immutable fixture");
        let key = evaluation('c');
        let facts = lexical(
            &view,
            &key,
            origin,
            statement,
            case["expected"]["state"] == "INVALID_STATEMENT",
        );
        check_frozen_result(
            &case["expected"],
            scoped_outcome(case, &view, &key, &facts),
            &view,
            &key,
        );
    }
}

/// T-AF-SOURCE-ARCHITECTURE-0001-R06-002
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R06
#[test]
fn exact_roots_reject_malformed_trust_and_drift() {
    use PythonStaticImportError as Error;
    let view = view_with(&[]);
    let key = evaluation('c');
    let registered = configuration(&view, &key, &json!(["A"]));
    let exact =
        serde_json_canonicalizer::to_vec(&registered).expect("pins canonical configuration");
    let pin = digest(&exact);
    let roots = PythonImportRoots::admit(&exact, &pin).expect("trusted fixture scope");
    let pretty = serde_json::to_vec_pretty(&registered).expect("format variation");
    assert_eq!(
        PythonImportRoots::admit(&pretty, &pin).expect("same JCS scope"),
        roots
    );
    assert_eq!(roots.configuration_ref(), pin);
    assert!(matches!(
        PythonImportRoots::admit(&exact, &identity('f')),
        Err(Error::InvalidBinding)
    ));
    assert!(matches!(
        PythonImportRoots::admit(br#"{"roots":[],"roots":[]}"#, &pin),
        Err(Error::Encoding(_))
    ));
    assert!(matches!(
        PythonImportRoots::admit(&vec![b' '; 8193], &pin),
        Err(Error::ResourceLimit)
    ));
    let mut unknown = registered;
    unknown["approve"] = json!(true);
    assert!(matches!(admit_roots(&unknown), Err(Error::Encoding(_))));
    for path in ["../A", "A\\children", "__fortress", ".git", "C:/A"] {
        assert!(matches!(
            admit_roots(&configuration(&view, &key, &json!([path]))),
            Err(Error::InvalidRootPath)
        ));
    }
    let facts = lexical(&view, &key, DEFAULT_ORIGIN, "import chosen", false);
    let changed = view_with(&[("A/new.py", b"x=2\n")]);
    assert!(matches!(
        PythonStaticImportObservation::evaluate(&facts, &changed, &key, &roots),
        Err(Error::StaleInput)
    ));
    assert!(matches!(
        PythonStaticImportObservation::evaluate(&facts, &view, &evaluation('f'), &roots),
        Err(Error::StaleInput)
    ));
    let rebound = admit_roots(&configuration(&changed, &key, &json!(["A"]))).expect("current pin");
    assert!(matches!(
        PythonStaticImportObservation::evaluate(&facts, &changed, &key, &rebound),
        Err(Error::StaleInput)
    ));
    let result = || {
        PythonStaticImportObservation::evaluate(&facts, &view, &key, &roots)
            .expect("exact observation")
            .to_canonical_json()
            .expect("canonical report")
    };
    assert_eq!(result(), result());
}

/// T-AF-SOURCE-ARCHITECTURE-0001-R06-003
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R06
#[test]
fn partial_or_conflicting_source_inventories_never_produce_static_success() {
    use PythonStaticImportError as Error;
    let key = evaluation('c');
    let unsupported_view = view_with(&[("A/chosen.pyd", b"not an executable")]);
    let alias_view = view_with(&[("A/CHOSEN.py", b"competing case spelling")]);
    let impossible_view = view_with(&[("A", b"physical root cannot also be a file")]);
    let assess = |view: &SourceView| {
        let facts = lexical(view, &key, DEFAULT_ORIGIN, "import chosen", false);
        let roots = admit_roots(&configuration(view, &key, &json!(["A"]))).expect("exact scope");
        PythonStaticImportObservation::evaluate(&facts, view, &key, &roots)
    };
    assert!(matches!(
        assess(&unsupported_view),
        Err(Error::UnsupportedRootContent)
    ));
    assert!(matches!(
        assess(&alias_view),
        Err(Error::AmbiguousInventory)
    ));
    assert!(matches!(
        assess(&impossible_view),
        Err(Error::AmbiguousInventory)
    ));
    let oversize = SourceView::from_bytes(
        std::iter::once((DEFAULT_ORIGIN.to_owned(), b"import chosen\n".to_vec()))
            .chain((0..4096).map(|index| (format!("A/module_{index}.py"), Vec::new()))),
    )
    .expect("immutable source scope over resolver's file limit");
    assert!(matches!(assess(&oversize), Err(Error::ResourceLimit)));
}
