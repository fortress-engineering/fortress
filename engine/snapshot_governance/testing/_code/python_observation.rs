//! Actual-state controls for independently hosted Python lexical observations.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::control_layout::{ControlLayout, EVIDENCE_ROOT};
use fortress_core::observation::{
    ObservationPolicy, SourceManifest, SourceView, observe_repository,
};
use fortress_core::portable::digest;
use fortress_core::python_observation::{
    PythonGrammar, PythonLexicalError, PythonLexicalMode, PythonLexicalOutcome,
    PythonLexicalProducer, PythonLexicalRequest, PythonObservationError, observe_python_lexical,
};
use serde_json::json;

use fortress_core::python_observation::{
    PythonImportScope, PythonScalarError, PythonScalarProducer, PythonScalarSubject,
    PythonStaticImportError, PythonStaticImportLimitation, PythonStaticImportOutcome,
    observe_python_scalar, observe_python_static_imports,
};

const PATH: &str = "_code/source.py";
const SOURCE: &[u8] = b"value: int = 7\r\n";
const OTHER: &[u8] = b"original ancillary input\n";
const CONTEXT: &str = "sha256:f19e50baa1d1fd5a6df2123b2973d458d3806567b133d3192b5b2587b5e1376f";

mod test_declarations {
    use super::*;
    use fortress_core::python_observation::observe_python_tests;
    use serde_json::Value;

    const NATIVE: &[u8] = include_bytes!("../_data/python_test_fixture_v1.json");
    const SCHEMA: &str = include_str!("../../_data/python_test_schema_v1.json");

    fn native_fixture(name: &str) -> (Fixture, Value, PythonLexicalProducer) {
        let fixture = Fixture::new(name);
        let record: Value = serde_json::from_slice(NATIVE).unwrap();
        for (path, source) in record["files"].as_object().unwrap() {
            assert!(fortress_core::observation::is_canonical_relative_path(path));
            let path = fixture.root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source.as_str().unwrap()).unwrap();
        }
        let representative = &record["replies"]["tests/test_basic.py"];
        let producer = PythonLexicalProducer::new(
            PythonGrammar::Cpython313,
            representative["runtime_ref"].as_str().unwrap().to_owned(),
            representative["worker_ref"].as_str().unwrap().to_owned(),
        )
        .unwrap();
        (fixture, record, producer)
    }

    fn reply(record: &Value, request: &PythonLexicalRequest, source: &[u8]) -> Value {
        let source_ref = digest(source);
        assert_eq!(request.source_ref(), source_ref);
        let mut response = record["replies"]
            .as_object()
            .unwrap()
            .values()
            .find(|row| row["source_ref"] == source_ref)
            .expect("retained compiler reply for exact file")
            .clone();
        response["id"] = json!(request.id());
        response
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-012`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
    #[test]
    fn python_test_roots_retain_exact_declaration_and_unknown_discovery() {
        let (fixture, record, producer) = native_fixture("python-tests-exact");
        fs::write(
            fixture.root.join("pytest.ini"),
            "[pytest]\npython_files=spec_*.py\n",
        )
        .unwrap();
        fs::write(
            fixture.root.join("tests/conftest.py"),
            "# observed hook file\n",
        )
        .unwrap();
        let evaluate = |roots: &[&str]| {
            let observed =
                observe_python_tests(&fixture.root, roots, &producer, |request, bytes| {
                    Ok(serde_json::to_vec(&reply(&record, request, bytes)).unwrap())
                })
                .unwrap();
            serde_json::to_value(observed).unwrap()
        };
        let document = evaluate(&["tests", "missing"]);
        assert_eq!(document, evaluate(&["missing", "tests"]));
        jsonschema::draft202012::validate(&serde_json::from_str(SCHEMA).unwrap(), &document)
            .expect("strict standalone derived schema");
        assert_eq!(document["runner_collection"], "UNESTABLISHED");
        assert_eq!(document["roots"][0]["state"], "SOURCE_UNESTABLISHED");
        assert_eq!(document["roots"][1]["naming_matches"], 3);
        assert_eq!(document["discovery_markers"][0]["path"], "pytest.ini");
        assert_eq!(
            document["discovery_markers"][1]["path"],
            "tests/conftest.py"
        );
        let files = document["files"].as_array().unwrap();
        assert_eq!(files.len(), 3);
        assert_eq!(files[0]["path"], "tests/extra_test.py");
        assert_eq!(files[1]["path"], "tests/test_basic.py");
        assert_eq!(files[1]["declarations"][1]["name"], "testable");
        assert_eq!(files[1]["declarations"][2]["kind"], "ASYNC_FUNCTION");
        assert_eq!(files[1]["declarations"][2]["span"][0], 6);
        assert_eq!(
            files[2]["declarations"][0]["placement"],
            "CONDITIONAL_MODULE_SCOPE"
        );
        assert_eq!(files[2]["declarations"][1]["name"], "test_disabled");
        assert_eq!(files[2]["barriers"].as_array().unwrap().len(), 4);
        assert!(document.get("coverage").is_none() && document.get("execution").is_none());

        let mut false_collection = document;
        false_collection["runner_collection"] = json!("PASSED");
        assert!(
            jsonschema::draft202012::validate(
                &serde_json::from_str(SCHEMA).unwrap(),
                &false_collection
            )
            .is_err()
        );
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-013`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
    #[test]
    fn python_test_scope_rejects_unavailable_shapes_before_dispatch() {
        let fixture = Fixture::new("python-tests-limits");
        for roots in [
            &[][..],
            &["../tests"][..],
            &[".", "tests"][..],
            &["TESTS/child", "tests"][..],
            &["note.txt"][..],
        ] {
            let invalid = observe_python_tests(&fixture.root, roots, &pin(), |_, _| {
                panic!("invalid roots must prevent dispatch");
            });
            assert!(
                matches!(invalid, Err(PythonObservationError::InvalidTestRoots)),
                "{roots:?}"
            );
        }
        fs::create_dir(fixture.root.join("tests")).unwrap();
        for index in 0..17 {
            fs::write(
                fixture.root.join(format!("tests/test_{index}.py")),
                "def test_something():\n    pass\n",
            )
            .unwrap();
        }
        let exceeded = observe_python_tests(&fixture.root, &["tests"], &pin(), |_, _| {
            panic!("oversized declaration inventory must prevent dispatch");
        });
        assert!(matches!(
            exceeded,
            Err(PythonObservationError::TestScopeLimit)
        ));
        let missing = observe_python_tests(&fixture.root, &["future"], &pin(), |_, _| {
            panic!("unobserved root must not invoke the lexical worker");
        })
        .unwrap();
        assert_eq!(
            serde_json::to_value(missing).unwrap()["roots"][0]["state"],
            "SOURCE_UNESTABLISHED"
        );
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-014`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
    #[test]
    fn python_test_projection_refuses_forged_execution_and_changed_source() {
        let (fixture, record, producer) = native_fixture("python-tests-stale");
        let forged =
            observe_python_tests(&fixture.root, &["tests"], &producer, |request, bytes| {
                let mut response = reply(&record, request, bytes);
                response["target_execution"] = json!("PASS");
                Ok(serde_json::to_vec(&response).unwrap())
            });
        assert!(matches!(forged, Err(PythonObservationError::Lexical(_))));
        let stale = observe_python_tests(&fixture.root, &["tests"], &producer, |request, bytes| {
            let response = reply(&record, request, bytes);
            fs::write(
                fixture.root.join("outside/test_outside.py"),
                "# changed ancillary source\n",
            )
            .unwrap();
            Ok(serde_json::to_vec(&response).unwrap())
        });
        assert!(matches!(stale, Err(PythonObservationError::SourceChanged)));
    }
}

mod regions {
    use super::*;
    use fortress_core::filing::LayoutExtension;
    use fortress_core::native_regions::{
        NativeRegionAvailability, NativeRegionError, NativeRegionInput,
        project_native_source_regions,
    };
    use fortress_core::source_architecture::{RegionCoverage, SemanticRegion};

    const NATIVE: &[u8] = include_bytes!("../_data/python_region_fixture_v1.json");
    const LAYOUT: &[u8] =
        include_bytes!("../../../project_model/testing/_data/layout_extension_example_v1.json");
    const LEXICAL_SOURCE: &str =
        "# café\r\nimport outside\r\nasync def convert(value):\r\n    return value\r\n";
    const LEXICAL_PATH: &str = "src/convert.py";

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-008`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
    #[test]
    fn python_layout_role_and_lexical_regions_remain_distinct() {
        let fixture = Fixture::new("py-native-regions");
        fs::create_dir(fixture.root.join("src")).unwrap();
        fs::write(fixture.root.join(LEXICAL_PATH), LEXICAL_SOURCE).unwrap();
        fs::write(
            fixture.root.join("pyproject.toml"),
            "[project]\nname = 'region-test'\n",
        )
        .unwrap();
        let response: serde_json::Value = serde_json::from_slice(NATIVE).unwrap();
        let native_pin = PythonLexicalProducer::new(
            PythonGrammar::Cpython313,
            response["runtime_ref"].as_str().unwrap().to_owned(),
            response["worker_ref"].as_str().unwrap().to_owned(),
        )
        .unwrap();
        let admitted = observe_python_lexical(
            &fixture.root,
            LEXICAL_PATH,
            PythonLexicalMode::Lexical,
            &native_pin,
            |request, selected| {
                assert_eq!(selected, LEXICAL_SOURCE.as_bytes());
                // Keep exact compiler facts and producer pins, and bind the
                // independent native replay to this caller's exact request.
                let mut replay = response;
                replay["id"] = json!(request.id());
                Ok(serde_json::to_vec(&replay).unwrap())
            },
        )
        .unwrap();
        let profile = LayoutExtension::from_pinned_bytes(LAYOUT, &digest(LAYOUT)).unwrap();
        let project = |path| {
            project_native_source_regions(
                &fixture.root,
                path,
                NativeRegionInput::Python(&admitted),
                std::slice::from_ref(&profile),
            )
        };
        let result = project(LEXICAL_PATH).unwrap();
        assert_eq!(result.availability(), NativeRegionAvailability::Observed);
        for region in result.regions() {
            let expected = if region.region() == SemanticRegion::Declarations {
                RegionCoverage::Observed
            } else {
                RegionCoverage::Unsupported
            };
            assert_eq!(region.coverage(), expected);
        }
        let document = serde_json::to_value(&result).unwrap();
        let schema =
            fortress_core::source_architecture::native_regions::native_source_region_schema();
        jsonschema::draft202012::validate(&serde_json::from_str(schema).unwrap(), &document)
            .expect(
                "source-bound region view and analysis-only layout satisfy the registered schema",
            );
        assert_eq!(document["layout"]["authority"], "ANALYSIS_ONLY");
        assert_eq!(document["layout"]["entry"]["state"], "CLASSIFIED");
        assert_eq!(document["layout"]["entry"]["role"], "SOURCE");
        assert_eq!(
            document["layout"]["selected_profile"]["digest"],
            digest(LAYOUT)
        );
        assert_eq!(document["regions"][1]["coverage"], "UNSUPPORTED");
        let evidence = &document["regions"][1]["evidence"][0];
        assert_eq!(evidence["start_line"], 2);
        assert_eq!(
            evidence["source_reference"],
            format!(
                "{}#/report/observations/imports/0",
                document["native_receipt_ref"].as_str().unwrap(),
            )
        );
        assert!(document.get("ownership").is_none());
        assert!(matches!(
            project(PATH),
            Err(NativeRegionError::SubjectMismatch)
        ));
        fs::remove_file(fixture.root.join("pyproject.toml")).unwrap();
        assert!(matches!(
            project(LEXICAL_PATH),
            Err(NativeRegionError::StaleReceipt)
        ));
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-009`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
    #[test]
    fn python_syntax_only_does_not_establish_other_regions() {
        let fixture = Fixture::new("py-syntax-regions");
        let admitted = observe_python_lexical(
            &fixture.root,
            PATH,
            PythonLexicalMode::Syntax,
            &pin(),
            syntax_reply,
        )
        .unwrap();
        let result = project_native_source_regions(
            &fixture.root,
            PATH,
            NativeRegionInput::Python(&admitted),
            &[],
        )
        .unwrap();
        assert_eq!(result.availability(), NativeRegionAvailability::SyntaxOnly);
        assert!(
            result
                .regions()
                .iter()
                .all(|region| region.coverage() == RegionCoverage::Unsupported)
        );
        assert!(serde_json::to_value(result).unwrap()["layout"].is_null());
    }
}

struct Fixture {
    container: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let parent = std::env::temp_dir().canonicalize().expect("temporary root");
        let container = parent.join(format!(
            "fortress-python-native-{}-{name}",
            std::process::id()
        ));
        fs::create_dir(&container).expect("create owned fixture root");
        let root = container.join("project");
        Self::write_tree(&root);
        Self { container, root }
    }

    fn write_tree(root: &Path) {
        fs::create_dir(root).expect("create owned project");
        fs::create_dir(root.join("_code")).expect("create Code directory");
        fs::write(root.join(PATH), SOURCE).expect("write frozen source fixture");
        fs::write(root.join("note.txt"), OTHER).expect("write ancillary fixture");
    }

    fn configure(&self, content: &[u8]) {
        let control = self.root.join("__fortress");
        fs::create_dir_all(&control).expect("create owned control directory");
        fs::write(control.join(".fsconfig"), content).expect("write fixture authority");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let path = self
            .container
            .canonicalize()
            .expect("owned fixture resolves");
        assert_eq!(path, self.container);
        fs::remove_dir_all(path).expect("remove only owned fixture container");
    }
}

fn pin() -> PythonLexicalProducer {
    PythonLexicalProducer::new(
        PythonGrammar::Cpython313,
        format!("sha256:{}", "a".repeat(64)),
        format!("sha256:{}", "b".repeat(64)),
    )
    .expect("fixed fixture pins")
}

fn syntax_reply(
    request: &PythonLexicalRequest,
    selected: &[u8],
) -> Result<Vec<u8>, PythonObservationError> {
    assert_eq!(selected, SOURCE);
    assert_eq!(request.source_ref(), digest(SOURCE));
    let value = json!({
        "schema": "fortress-research/python-lexical-response/1",
        "id": request.id(),
        "source_ref": request.source_ref(),
        "byte_count": selected.len(),
        "runtime_ref": request.runtime_ref(),
        "worker_ref": request.worker_ref(),
        "mode": "SYNTAX",
        "outcome": "SYNTAX_ONLY",
        "reason": "LEXICAL_AND_MODULE_VALIDITY_NOT_ADMITTED",
        "stages": {
            "SYNTAX": {"status": "COMPLETE"},
            "LEXICAL_SCOPE": {"status": "NOT_RUN"},
            "MODULE_VALIDITY": {"status": "NOT_RUN"}
        },
        "observations": null,
        "target_execution": "NOT_RUN",
        "runtime_limitations": ["IMPORT_TARGETS", "RUNTIME_CALL_TARGETS", "EFFECTS", "EXECUTION"]
    });
    serde_json::to_vec(&value).map_err(|error| PythonLexicalError::Encoding(error).into())
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn exact_original_source_and_selected_authority_bind_python_observation() {
    let fixture = Fixture::new("actual");
    let result = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        syntax_reply,
    )
    .expect("read-only exact original observation");
    assert_eq!(
        result.observation().outcome(),
        PythonLexicalOutcome::SyntaxOnly
    );
    assert_eq!(result.evaluation_key().program_context_digest(), CONTEXT);
    let policy = ObservationPolicy::new(
        [".git", EVIDENCE_ROOT]
            .into_iter()
            .chain(ControlLayout::standard().migration_record_roots()),
    )
    .unwrap();
    let observed = observe_repository(&fixture.root, &policy).unwrap();
    let expected_manifest = SourceManifest::from_observation(&observed, &policy).unwrap();
    assert_eq!(
        result.evaluation_key().source_manifest_digest(),
        expected_manifest.entries_digest()
    );
    let expected_view =
        SourceView::from_bytes([(PATH, SOURCE.to_vec()), ("note.txt", OTHER.to_vec())]).unwrap();
    let retained: serde_json::Value =
        serde_json::from_slice(&result.observation().to_canonical_json().unwrap()).unwrap();
    assert_eq!(
        retained["request"]["source_view_ref"],
        expected_view.digest()
    );
    assert_eq!(
        retained["request"]["evaluation_ref"],
        result.evaluation_key().digest()
    );
    assert_eq!(retained["report"]["target_execution"], "NOT_RUN");
    let absent_authority = result.evaluation_key().authority_binding_digest();
    assert!(absent_authority.starts_with("sha256:"));

    let current_config = br#"{"$schema":"urn:fortress:schema:v3:project-configuration","schema_version":3,"observation_exclusions":[],"logical_modules":[]}"#;
    fixture.configure(current_config);
    fs::write(
        fixture.root.join("contract.json"),
        br#"{
  "$schema": "urn:fortress:schema:v2:module-contract",
  "schema_version": 2,
  "id": "PF-PYTHON-FIXTURE",
  "display_name": "Python lexical fixture",
  "ecosystem": {
    "repository_grammar": 1,
    "standard": {
      "id": "STD-FORTRESS-ENGINEERING",
      "edition": "1.0.0-draft.2"
    }
  },
  "provides": [],
  "requires": [],
  "relationships": [],
  "constraints": [],
  "guarantees": [],
  "features": [],
  "behavior": []
}
"#,
    )
    .unwrap();
    let declared = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        syntax_reply,
    )
    .expect("selected declared original authority");
    assert_eq!(declared.evaluation_key().program_context_digest(), CONTEXT);
    assert_ne!(
        declared.evaluation_key().authority_binding_digest(),
        absent_authority
    );
    assert_ne!(
        declared.evaluation_key().source_manifest_digest(),
        expected_manifest.entries_digest()
    );
    assert_eq!(fs::read(fixture.root.join(PATH)).unwrap(), SOURCE);
    assert_eq!(fs::read(fixture.root.join("note.txt")).unwrap(), OTHER);
    assert_eq!(
        fs::read(fixture.root.join("__fortress/.fsconfig")).unwrap(),
        current_config
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn changes_outside_the_selected_file_prevent_python_publication() {
    let fixture = Fixture::new("whole-view");
    let result = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        |request, bytes| {
            let original = syntax_reply(request, bytes)?;
            fs::write(fixture.root.join("note.txt"), "changed ancillary input\n").unwrap();
            Ok(original)
        },
    );
    assert!(matches!(result, Err(PythonObservationError::SourceChanged)));
    let result = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        |request, bytes| {
            let original = syntax_reply(request, bytes)?;
            fixture.configure(b"new attempted authority");
            Ok(original)
        },
    );
    assert!(matches!(result, Err(PythonObservationError::SourceChanged)));
    assert_eq!(fs::read(fixture.root.join(PATH)).unwrap(), SOURCE);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn replacement_directory_with_equal_bytes_prevents_python_publication() {
    let fixture = Fixture::new("directory");
    let result = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        |request, bytes| {
            let original = syntax_reply(request, bytes)?;
            fs::rename(&fixture.root, fixture.container.join("retained-original")).unwrap();
            Fixture::write_tree(&fixture.root);
            Ok(original)
        },
    );
    assert!(matches!(result, Err(PythonObservationError::SourceChanged)));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn invalid_and_excluded_original_authority_prevent_python_dispatch() {
    let fixture = Fixture::new("authority");
    for rejected in [
        b"not valid project JSON".as_slice(),
        br#"{"$schema":"urn:fortress:schema:v3:project-configuration","schema_version":3,"observation_exclusions":["note.txt"],"logical_modules":[]}"#,
    ] {
        fixture.configure(rejected);
        let result = observe_python_lexical(
            &fixture.root,
            PATH,
            PythonLexicalMode::Syntax,
            &pin(),
            |_, _| panic!("unavailable original authority must refuse worker dispatch"),
        );
        assert!(matches!(result, Err(PythonObservationError::SourceUnavailable(_))));
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn candidate_bound_python_reply_cannot_be_used_for_actual_source() {
    let fixture = Fixture::new("candidate");
    let original = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        syntax_reply,
    )
    .unwrap();
    let proposed = SourceView::from_bytes([
        (PATH, SOURCE.to_vec()),
        ("note.txt", b"hypothetical ancillary replacement\n".to_vec()),
    ])
    .unwrap();
    let candidate = PythonLexicalRequest::for_source(
        &proposed,
        original.evaluation_key(),
        PATH,
        PythonLexicalMode::Syntax,
        pin(),
    )
    .unwrap();
    let result = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        |actual, bytes| {
            assert_ne!(actual.id(), candidate.id());
            syntax_reply(&candidate, bytes)
        },
    );
    assert!(matches!(
        result,
        Err(PythonObservationError::Lexical(
            PythonLexicalError::InvalidBinding
        ))
    ));
    assert_eq!(fs::read(fixture.root.join("note.txt")).unwrap(), OTHER);
}

const SCALAR_SOURCE: &[u8] = b"def subject(gate):\n    return not gate\n";

fn scalar_fixture(name: &str) -> (Fixture, PythonScalarSubject, PythonScalarProducer) {
    let fixture = Fixture::new(name);
    fs::write(fixture.root.join(PATH), SCALAR_SOURCE).expect("write exact scalar fixture");
    let subject = PythonScalarSubject {
        source_path: PATH.into(),
        source_ref: digest(SCALAR_SOURCE),
        function: "subject".into(),
        exact_bool_parameters: vec!["gate".into()],
    };
    let producer = PythonScalarProducer::new(
        format!("sha256:{}", "d".repeat(64)),
        format!("sha256:{}", "e".repeat(64)),
        format!("sha256:{}", "f".repeat(64)),
    )
    .expect("fixed scalar producer pins");
    (fixture, subject, producer)
}

fn scalar_reply(payload: &[u8]) -> Result<Vec<u8>, PythonObservationError> {
    let request: serde_json::Value =
        serde_json::from_slice(payload).expect("exact worker frame parses");
    let first_line = |start: usize, end: usize| {
        json!({
            "path":PATH,"start_byte":start,"end_byte":end,
            "start_line":1,"start_byte_column":start+1,
        })
    };
    let value = json!({
        "schema":"fortress:python:scalar-response:1",
        "id":request["id"],"byte_count":SCALAR_SOURCE.len(),
        "source_path":PATH,"source_ref":digest(SCALAR_SOURCE),"function":"subject",
        "parameter_domains":["BOOL"],"worker_ref":request["worker_ref"],
        "bootstrap_ref":request["bootstrap_ref"],"runtime_ref":request["runtime_ref"],
        "target_execution":"NOT_RUN","status":"LOWERABLE",
        "symbol":{"name":"subject","span":first_line(4,11),"declaration_span":first_line(0,38)},
        "parameters":[{"name":"gate","scalar":"BOOL","span":first_line(12,16)}],
        "locals":[],"result_scalar":"BOOL","diagnostic":null,
        "body":[{"kind":"return",
            "span":{"path":PATH,"start_byte":23,"end_byte":38,"start_line":2,"start_byte_column":5},
            "value":{"kind":"unary","operator":"!","value":{"kind":"binding","name":"gate"}}}],
    });
    serde_json::to_vec(&value).map_err(|error| PythonScalarError::Json(error).into())
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R30-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R30
#[test]
fn exact_python_scalar_body_carries_an_upper_bound_under_independent_assumptions() {
    use fortress_core::program_semantics::native_body::NativeBodyOutcome;
    use fortress_core::semantic_analysis::SemanticDomain;

    let (fixture, subject, producer) = scalar_fixture("scalar-actual");
    let result = observe_python_scalar(&fixture.root, &subject, &producer, |request| {
        scalar_reply(&request)
    })
    .expect("bounded original-source native observation");
    assert!(matches!(result.outcome(), NativeBodyOutcome::Lowered(_)));
    assert!(matches!(
        result.inferred_output(),
        Some(SemanticDomain::Boolean { values, .. }) if values == &[false, true]
    ));
    assert_eq!(result.request().source_ref(), digest(SCALAR_SOURCE));
    assert_eq!(
        fs::read(fixture.root.join(PATH)).expect("unchanged source"),
        SCALAR_SOURCE
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R30-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R30
#[test]
fn stale_subject_pin_and_physical_drift_refuse_scalar_publication() {
    let (fixture, mut subject, producer) = scalar_fixture("scalar-refusal");
    subject.source_ref = digest(b"different independently selected bytes");
    let wrong = observe_python_scalar(&fixture.root, &subject, &producer, |_| {
        panic!("a stale subject pin must refuse before process dispatch")
    });
    assert!(matches!(
        wrong,
        Err(PythonObservationError::SubjectIdentityMismatch)
    ));
    subject.source_ref = digest(SCALAR_SOURCE);
    let changed = observe_python_scalar(&fixture.root, &subject, &producer, |request| {
        fs::write(
            fixture.root.join("note.txt"),
            b"scope changed during launch",
        )
        .expect("fixture changes");
        scalar_reply(&request)
    });
    assert!(matches!(
        changed,
        Err(PythonObservationError::SourceChanged)
    ));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R30-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R30
#[test]
fn python_scalar_flow_keeps_exact_input_and_refuses_physical_drift() {
    use fortress_core::python_observation::{NativeBodyOutcome, observe_python_scalar_flow};

    let (fixture, subject, producer) = scalar_fixture("scalar-flow");
    let evaluate = || {
        observe_python_scalar_flow(&fixture.root, &subject, &producer, |request| {
            scalar_reply(&request)
        })
    };
    let (native, observed) = evaluate().unwrap();
    let NativeBodyOutcome::Lowered(body) = native.outcome() else {
        panic!("the frozen Boolean function lowers");
    };
    let report = serde_json::to_value(&observed).unwrap();
    let edges = report["facts"]["explicit_data_edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0]["producer"]["name"], "gate");
    assert_eq!(edges[0]["consumer"]["role"], "return");
    assert_eq!(edges[0]["line"], 2);
    assert_eq!(edges[0]["column"], 5);
    assert_eq!(report["occurrence_ref"], body.binding());
    assert_eq!(report["facts"]["condition_inputs"], json!([]));
    assert_eq!(report["control_influence_coverage"], "UNSUPPORTED");
    assert_eq!(report["classification_authority"], "UNKNOWN");
    assert_eq!(
        observed.to_canonical_json().unwrap(),
        evaluate().unwrap().1.to_canonical_json().unwrap()
    );
    let drift = observe_python_scalar_flow(&fixture.root, &subject, &producer, |request| {
        fs::write(
            fixture.root.join("note.txt"),
            "changed while native worker returns",
        )
        .unwrap();
        scalar_reply(&request)
    });
    assert!(matches!(drift, Err(PythonObservationError::SourceChanged)));
}

const IMPORT_SOURCE: &[u8] = b"import chosen\r\n";

fn import_scope(roots: &[&str], inventory: &str) -> (Vec<u8>, String) {
    let selection = json!({
        "$schema":"urn:fortress:host:v1:python-static-import-scope",
        "schema_version":1,
        "inventory":inventory,
        "roots":roots,
    });
    let bytes = serde_json_canonicalizer::to_vec(&selection).expect("fixture scope canonicalizes");
    let pin = digest(&bytes);
    (bytes, pin)
}

fn import_fixture(name: &str) -> Fixture {
    let fixture = Fixture::new(name);
    fs::write(fixture.root.join(PATH), IMPORT_SOURCE).expect("write exact Python import source");
    fs::write(fixture.root.join("_code/chosen.py"), b"VALUE = 3\n").expect("write first source");
    fs::create_dir(fixture.root.join("vendor")).expect("second root creates");
    fs::write(fixture.root.join("vendor/chosen.py"), b"VALUE = 9\n").expect("write second source");
    fixture
}

fn import_reply(
    request: &PythonLexicalRequest,
    selected: &[u8],
) -> Result<Vec<u8>, PythonObservationError> {
    assert_eq!(selected, IMPORT_SOURCE);
    let report = json!({
        "schema":"fortress-research/python-lexical-response/1",
        "id":request.id(),"mode":"LEXICAL","source_ref":request.source_ref(),
        "byte_count":selected.len(),"runtime_ref":request.runtime_ref(),"worker_ref":request.worker_ref(),
        "outcome":"LEXICAL",
        "stages":{"SYNTAX":{"status":"COMPLETE"},"LEXICAL_SCOPE":{"status":"COMPLETE"},
                  "MODULE_VALIDITY":{"status":"COMPLETE"}},
        "observations":{"imports":[{"scope":"s0","form":"import","level":null,"module":null,
                                   "names":[["chosen",null]],"target":"UNRESOLVED","span":[1,0,1,13]}],
                        "scopes":[{"id":"s0","name":"top","parent":null,"span":null,"kind":"Module",
                                   "bindings":[]}],
                        "constructs":[],"limitations":[]},
        "target_execution":"NOT_RUN",
        "runtime_limitations":["IMPORT_TARGETS","RUNTIME_CALL_TARGETS","EFFECTS","EXECUTION"],
    });
    serde_json::to_vec(&report).map_err(|error| PythonLexicalError::Encoding(error).into())
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-006`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn explicit_python_root_order_binds_actual_source_and_typed_origins() {
    use fortress_core::source_architecture::python_lexical::python_static_imports::PythonStaticImportTarget;

    let fixture = import_fixture("static-imports");
    let (first, first_pin) = import_scope(&["_code", "vendor"], "COMPLETE_SOURCE_ONLY");
    let (reversed, reverse_pin) = import_scope(&["vendor", "_code"], "COMPLETE_SOURCE_ONLY");
    assert_ne!(first_pin, reverse_pin);
    assert!(matches!(
        PythonImportScope::admit(&reversed, &first_pin),
        Err(PythonStaticImportError::InvalidBinding)
    ));
    let select = |bytes: &[u8], reference: &str| {
        let scope = PythonImportScope::admit(bytes, reference).expect("trusted fixture scope");
        observe_python_static_imports(&fixture.root, PATH, &pin(), &scope, import_reply)
            .expect("exact native import owner")
    };
    let ordered = select(&first, &first_pin);
    let switched = select(&reversed, &reverse_pin);
    assert_ne!(
        ordered.evaluation_key().program_context_digest(),
        switched.evaluation_key().program_context_digest()
    );
    assert_eq!(
        ordered.evaluation_key().source_manifest_digest(),
        switched.evaluation_key().source_manifest_digest()
    );
    assert_eq!(
        ordered.evaluation_key().authority_binding_digest(),
        switched.evaluation_key().authority_binding_digest()
    );
    for (report, target) in [
        (&ordered, "_code/chosen.py"),
        (&switched, "vendor/chosen.py"),
    ] {
        let PythonStaticImportOutcome::Observed { observation } = report.outcome() else {
            panic!("trusted fixture has a unique static target");
        };
        assert_eq!(observation.source_path(), PATH);
        assert_eq!(observation.source_ref(), digest(IMPORT_SOURCE));
        assert_eq!(
            observation.evaluation_ref(),
            report.evaluation_key().digest()
        );
        assert_eq!(observation.imports()[0].scope(), "s0");
        assert_eq!(observation.imports()[0].source_span(), [1, 0, 1, 13]);
        assert_eq!(
            observation.imports()[0].static_targets(),
            [PythonStaticImportTarget::FileStatic {
                module: "chosen".into(),
                path: target.into(),
                source_ref: digest(
                    &fs::read(fixture.root.join(target)).expect("exact selected bytes")
                )
            }]
        );
    }
    assert_eq!(fs::read(fixture.root.join(PATH)).unwrap(), IMPORT_SOURCE);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-007`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn stale_static_imports_refuse_and_incomplete_scopes_keep_truthful_limits() {
    let fixture = import_fixture("static-import-limits");
    let (incomplete, incomplete_ref) = import_scope(&["_code"], "INCOMPLETE");
    assert!(matches!(
        PythonImportScope::admit(&incomplete, &incomplete_ref),
        Err(PythonStaticImportError::IncompleteInventory)
    ));
    let (selection, selection_ref) = import_scope(&["_code"], "COMPLETE_SOURCE_ONLY");
    let scope = PythonImportScope::admit(&selection, &selection_ref).unwrap();
    let mismatch =
        observe_python_static_imports(&fixture.root, PATH, &pin(), &scope, |request, source| {
            let mut reply: serde_json::Value =
                serde_json::from_slice(&import_reply(request, source)?).unwrap();
            reply["source_ref"] = json!(digest(b"unrelated source"));
            serde_json::to_vec(&reply).map_err(|error| PythonLexicalError::Encoding(error).into())
        });
    assert!(matches!(
        mismatch,
        Err(PythonObservationError::Lexical(
            PythonLexicalError::InvalidBinding
        ))
    ));
    fs::write(
        fixture.root.join("_code/unsafe.pyd"),
        b"not a native module",
    )
    .unwrap();
    let blocked =
        observe_python_static_imports(&fixture.root, PATH, &pin(), &scope, import_reply).unwrap();
    assert_eq!(blocked.lexical().outcome(), PythonLexicalOutcome::Lexical);
    assert!(matches!(
        blocked.outcome(),
        PythonStaticImportOutcome::Unavailable {
            reason: PythonStaticImportLimitation::UnsupportedRootContent
        }
    ));
    let changed =
        observe_python_static_imports(&fixture.root, PATH, &pin(), &scope, |request, source| {
            let report = import_reply(request, source)?;
            fs::write(
                fixture.root.join("note.txt"),
                b"original scope changed during inspection",
            )
            .unwrap();
            Ok(report)
        });
    assert!(matches!(
        changed,
        Err(PythonObservationError::SourceChanged)
    ));
}

const DEPENDENCY_SOURCE: &str = "café = 1; from chosen import member\r\nimport ns, missing\r\ndynamic = __import__(\"chosen\")\r\n";
const CONSUMER: &str = "AF-PYTHON-CONSUMER-0001";
const PROVIDER: &str = "AF-PYTHON-PROVIDER-0001";

fn write_dependency_contract(path: &Path, document: serde_json::Value) {
    let contract: fortress_core::contract_coherency::ModuleContract =
        serde_json::from_value(document).unwrap();
    fs::write(path, contract.to_canonical_json().unwrap()).unwrap();
}

fn dependency_fixture(name: &str) -> Fixture {
    let fixture = import_fixture(name);
    fs::write(fixture.root.join(PATH), DEPENDENCY_SOURCE.as_bytes()).unwrap();
    fs::create_dir(fixture.root.join("_code/ns")).unwrap();
    fs::write(fixture.root.join("_code/ns/portion.py"), b"VALUE = 1\n").unwrap();
    let root = json!({
        "$schema": "urn:fortress:schema:v2:module-contract", "schema_version": 2,
        "id": "PF-PYTHON-FIXTURE", "display_name": "Python dependency fixture",
        "ecosystem":{"repository_grammar":1,
            "standard":{"id":"STD-FORTRESS-ENGINEERING","edition":"1.0.0-draft.2"}},
        "provides":[],"requires":[],"relationships":[],"constraints":[],
        "guarantees":[],"features":[],"behavior":[]
    });
    write_dependency_contract(&fixture.root.join("contract.json"), root);
    let mut logical = Vec::new();
    for (id, stem, path) in [
        (CONSUMER, "consumer", PATH),
        (PROVIDER, "provider", "_code/chosen.py"),
    ] {
        let contract = format!("_data/logical_modules/{stem}/contract.json");
        let absolute = fixture.root.join(&contract);
        fs::create_dir_all(absolute.parent().unwrap()).unwrap();
        let module = json!({
            "$schema":"urn:fortress:schema:v2:module-contract","schema_version":2,
            "id":id,"display_name":stem,"provides":[],"requires":[],"relationships":[],
            "constraints":[],"guarantees":[],"features":[],"behavior":[]
        });
        write_dependency_contract(&absolute, module);
        logical.push(
            json!({"module":id,"contract":contract,"parent":"PF-PYTHON-FIXTURE",
            "bindings":[{"kind":"file","path":path}]}),
        );
    }
    fixture.configure(
        &serde_json::to_vec(&json!({
            "$schema":"urn:fortress:schema:v3:project-configuration","schema_version":3,
            "observation_exclusions":[],"logical_modules":logical,
        }))
        .unwrap(),
    );
    fixture
}

fn dependency_reply(
    request: &PythonLexicalRequest,
    source: &[u8],
) -> Result<Vec<u8>, PythonObservationError> {
    assert_eq!(source, DEPENDENCY_SOURCE.as_bytes());
    // Native fixture positions are independently asserted against physical bytes.
    let report = json!({
        "schema":"fortress-research/python-lexical-response/1","id":request.id(),
        "mode":"LEXICAL","source_ref":request.source_ref(),"byte_count":source.len(),
        "runtime_ref":request.runtime_ref(),"worker_ref":request.worker_ref(),
        "outcome":"LEXICAL",
        "stages":{"SYNTAX":{"status":"COMPLETE"},"LEXICAL_SCOPE":{"status":"COMPLETE"},
            "MODULE_VALIDITY":{"status":"COMPLETE"}},
        "observations":{
            "imports":[
                {"scope":"s0","form":"from","level":0,"module":"chosen",
                    "names":[["member",null]],"target":"UNRESOLVED","span":[1,11,1,36]},
                {"scope":"s0","form":"import","level":null,"module":null,
                    "names":[["ns",null],["missing",null]],"target":"UNRESOLVED","span":[2,0,2,18]}
            ],
            "scopes":[{"id":"s0","name":"top","parent":null,"span":null,
                "kind":"Module","bindings":[]}],
            "constructs":[],"limitations":[]
        },
        "target_execution":"NOT_RUN",
        "runtime_limitations":["IMPORT_TARGETS","RUNTIME_CALL_TARGETS","EFFECTS","EXECUTION"]
    });
    serde_json::to_vec(&report).map_err(|error| PythonLexicalError::Encoding(error).into())
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-010`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn scoped_python_dependencies_join_only_exact_declared_file_origins() {
    use fortress_core::python_observation::{
        PythonStaticDependencyOutcome, observe_python_static_dependencies,
    };

    let fixture = dependency_fixture("dependency-scope");
    let check = |roots: &[&str]| {
        let (bytes, scope_ref) = import_scope(roots, "COMPLETE_SOURCE_ONLY");
        let scope = PythonImportScope::admit(&bytes, &scope_ref).unwrap();
        let report = observe_python_static_dependencies(
            &fixture.root,
            PATH,
            &pin(),
            &scope,
            dependency_reply,
        )
        .unwrap();
        let PythonStaticDependencyOutcome::Observed {
            projection,
            ownership_diagnostics,
            ..
        } = report.dependencies()
        else {
            panic!("expected scoped native evidence")
        };
        assert!(ownership_diagnostics.is_empty());
        let PythonStaticImportOutcome::Observed { observation } = report.imports().outcome() else {
            panic!("expected original static import observation")
        };
        assert_eq!(
            projection["observation_sha256"],
            digest(&observation.to_canonical_json().unwrap())
        );
        let receipt = serde_json::to_value(&observation.imports()[0]).unwrap();
        assert_eq!(
            receipt["member_resolution"],
            "UNRESOLVED_ATTRIBUTE_OR_SUBMODULE"
        );
        assert_eq!(receipt["runtime_resolution"], "UNRESOLVED");
        projection.clone()
    };
    let forward = check(&["_code", "vendor"]);
    let dependencies = forward["observation"]["module_dependencies"]
        .as_array()
        .unwrap();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0]["source_module"], CONSUMER);
    assert_eq!(dependencies[0]["target_module"], PROVIDER);
    assert_eq!(forward["sites"][0]["occurrence"]["start_byte"], 11);
    assert_eq!(forward["sites"][0]["occurrence"]["end_byte"], 36);
    assert_eq!(
        forward["sites"][0]["target"]["file"]["path"],
        "_code/chosen.py"
    );
    assert_eq!(forward["sites"][1]["occurrence"]["start_byte"], 38);
    assert_eq!(forward["sites"][1]["occurrence"]["end_byte"], 56);
    assert_eq!(
        forward["sites"][1]["target"]["reason"],
        "missing_from_admitted_scope"
    );
    assert_eq!(forward["sites"][2]["target"]["reason"], "namespace_only");
    let reverse = check(&["vendor", "_code"]);
    assert_eq!(
        reverse["sites"][0]["target"]["file"]["path"],
        "vendor/chosen.py"
    );
    assert_eq!(
        reverse["sites"][0]["target"]["ownership"]["state"],
        "ownership_unavailable"
    );
    assert_eq!(reverse["observation"]["module_dependencies"], json!([]));
    assert_eq!(forward, check(&["_code", "vendor"]));
    assert_eq!(
        fs::read(fixture.root.join(PATH)).unwrap(),
        DEPENDENCY_SOURCE.as_bytes()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-011`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn python_dependency_capture_rejects_drift_and_preserves_unavailable_scope() {
    use fortress_core::python_observation::{
        PythonStaticDependencyOutcome, observe_python_static_dependencies,
    };

    let fixture = dependency_fixture("dependency-drift");
    let (bytes, scope_ref) = import_scope(&["_code", "vendor"], "COMPLETE_SOURCE_ONLY");
    let scope = PythonImportScope::admit(&bytes, &scope_ref).unwrap();
    let result = observe_python_static_dependencies(
        &fixture.root,
        PATH,
        &pin(),
        &scope,
        |request, source| {
            let answer = dependency_reply(request, source)?;
            fs::write(fixture.root.join("_code/chosen.py"), b"VALUE = 41\n").unwrap();
            Ok(answer)
        },
    );
    assert!(matches!(result, Err(PythonObservationError::SourceChanged)));
    fs::write(
        fixture.root.join("_code/unsafe.pyd"),
        b"unsupported native source",
    )
    .unwrap();
    let blocked =
        observe_python_static_dependencies(&fixture.root, PATH, &pin(), &scope, dependency_reply)
            .unwrap();
    assert!(matches!(
        blocked.dependencies(),
        PythonStaticDependencyOutcome::Unavailable {
            reason: PythonStaticImportLimitation::UnsupportedRootContent,
        }
    ));
    assert_eq!(
        blocked.imports().lexical().outcome(),
        PythonLexicalOutcome::Lexical
    );
}
