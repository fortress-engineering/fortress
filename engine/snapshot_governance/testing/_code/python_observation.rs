//! Actual-state controls for independently hosted Python lexical observations.

use fortress_core::candidate::{CandidateRequest, CandidateWorkspace, NativeCandidateSelection};
use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
use fortress_core::migration_adapter::CanonicalMigrationAuthority;
use fortress_core::migration_governance::MigrationOperation;
use fortress_core::python_observation::observe_python_candidate_sensitivity;
use fortress_core::state_governance::ComparisonContext;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

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

mod lexical_calls {
    use super::{
        AtomicBool, CandidateRequest, CandidateWorkspace, CanonicalMigrationAuthority,
        ComparisonContext, MigrationOperation, NativeCandidateSelection, NoGrantValidator,
        Ordering, UnmediatedHost,
    };
    use super::{
        Fixture, PythonObservationError, PythonScalarError, PythonScalarProducer,
        PythonScalarSubject, digest, fs, json, observe_python_scalar,
    };
    use fortress_core::python_observation::observe_python_candidate_call_return;
    use fortress_core::python_observation::observe_python_native_call_return;
    use serde_json::Value;

    fn case(
        name: &str,
        label: &str,
    ) -> (Fixture, PythonScalarSubject, PythonScalarProducer, Value) {
        let doc: Value =
            serde_json::from_slice(include_bytes!("../_data/python_call_fixture_v1.json")).unwrap();
        lexical_fixture(&doc[name], label, vec!["v".into()])
    }

    fn lexical_fixture(
        row: &Value,
        label: &str,
        exact_bool_parameters: Vec<String>,
    ) -> (Fixture, PythonScalarSubject, PythonScalarProducer, Value) {
        let report = &row["reply"];
        let data = row["source"].as_str().unwrap();
        assert_eq!(report["source_ref"], digest(data.as_bytes()));
        let fixture = Fixture::new(label);
        fs::write(fixture.root.join("fixture.py"), data).unwrap();
        let producer = PythonScalarProducer::new(
            report["worker_ref"].as_str().unwrap(),
            report["bootstrap_ref"].as_str().unwrap(),
            report["runtime_ref"].as_str().unwrap(),
        )
        .unwrap();
        let subject = PythonScalarSubject {
            source_path: "fixture.py".into(),
            source_ref: digest(data.as_bytes()),
            function: "outer".into(),
            exact_bool_parameters,
        };
        (fixture, subject, producer, report.clone())
    }

    fn bind(request: &[u8], reply: &Value) -> Value {
        let request: Value = serde_json::from_slice(request).unwrap();
        assert_eq!(request["schema"], "fortress:python:lexical-call-request:1");
        for key in [
            "source_path",
            "source_ref",
            "worker_ref",
            "runtime_ref",
            "bootstrap_ref",
        ] {
            assert_eq!(request[key], reply[key], "{key}");
        }
        let mut response = reply.clone();
        response["id"] = request["id"].clone();
        response
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R40-002`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R40
    #[test]
    fn admitted_python_call_does_not_invent_original_module_ownership() {
        use fortress_core::python_observation::observe_python_native_call_module_boundaries;

        for name in ["locally_defined_shadow_free_function", "later_local_rebind"] {
            let (fixture, subject, producer, reply) = case(name, &format!("owned-python-{name}"));
            let inspect = || {
                observe_python_native_call_module_boundaries(
                    &fixture.root,
                    &subject,
                    &producer,
                    |request| Ok(serde_json::to_vec(&bind(&request, &reply)).unwrap()),
                )
                .unwrap()
            };
            let report = inspect();
            assert_eq!(report, inspect());
            assert_eq!(
                report["original_intent"],
                json!({"status":"ORIGINAL_INTENT_UNAVAILABLE"})
            );
            assert_eq!(report["observation"]["source_ref"], subject.source_ref);
            assert_eq!(report["canonical_finding_or_certificate"], "NOT_ISSUED");
            if name == "later_local_rebind" {
                assert_eq!(report["topology"]["reason"], "CALL_TARGET_UNESTABLISHED");
                assert_eq!(report["ownership_sites"], json!([]));
            } else {
                let sites = report["ownership_sites"].as_array().unwrap();
                assert_eq!(sites.len(), 1);
                assert_eq!(sites[0]["relationship"], "DECLARED_OWNER_UNAVAILABLE");
                assert_eq!(sites[0]["caller"], Value::Null);
                assert_eq!(sites[0]["callee"], Value::Null);
            }
        }
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R42-002`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R42
    #[test]
    fn exact_python_boolean_returns_refuse_unknown_operand_values() {
        let doc: Value =
            serde_json::from_slice(include_bytes!("../_data/python_short_circuit_v1.json"))
                .unwrap();
        for (name, row) in doc["cases"].as_object().unwrap() {
            let parameters = serde_json::from_value(row["parameters"].clone()).unwrap();
            let (fixture, subject, producer, receipt) = lexical_fixture(row, name, parameters);
            let result =
                observe_python_native_call_return(&fixture.root, &subject, &producer, |request| {
                    Ok(serde_json::to_vec(&bind(&request, &receipt)).unwrap())
                })
                .unwrap();
            if let Some(reason) = row["expected_limitation"].as_str() {
                assert!(result["evaluation"].is_null(), "{name}");
                assert_eq!(result["diagnostic"]["code"], reason, "{name}");
            } else {
                assert_eq!(result["evaluation"]["status"], "COMPLETE", "{name}");
                assert_eq!(
                    result["evaluation"]["parameters"], row["parameters"],
                    "{name}"
                );
                assert_eq!(
                    result["evaluation"]["returns"], row["expected_returns"],
                    "{name}"
                );
                assert_eq!(result["target_execution"], "NOT_RUN");
            }
            let actual = fs::read_to_string(fixture.root.join("fixture.py")).unwrap();
            assert_eq!(actual, row["source"].as_str().unwrap());
        }
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R39-002`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R39
    #[test]
    fn python_native_call_sensitivity_retains_witnesses_and_refuses_lexical_rebinding() {
        use fortress_core::python_observation::observe_python_native_call_sensitivity;

        for name in ["locally_defined_shadow_free_function", "later_local_rebind"] {
            let (fixture, subject, producer, reply) =
                case(name, &format!("sensitivity-python-{name}"));
            let respond =
                |request: Vec<u8>| Ok(serde_json::to_vec(&bind(&request, &reply)).unwrap());
            let inspect = || {
                observe_python_native_call_sensitivity(&fixture.root, &subject, &producer, respond)
                    .unwrap()
            };
            let report = inspect();
            assert_eq!(report, inspect());
            assert_eq!(report["target_execution"], "NOT_RUN");
            assert_eq!(report["observation"]["source_ref"], subject.source_ref);
            let sensitivity = &report["sensitivity"];
            if name == "later_local_rebind" {
                assert_eq!(
                    sensitivity,
                    &json!({
                        "status":"UNAVAILABLE","occurrence":null,"reason":"CALL_TARGET_UNESTABLISHED"
                    })
                );
                continue;
            }
            let closure =
                observe_python_native_call_return(&fixture.root, &subject, &producer, respond)
                    .unwrap();
            assert_eq!(sensitivity["status"], "COMPLETE");
            assert_eq!(
                sensitivity["occurrence"],
                closure["evaluation"]["occurrence"]
            );
            assert_eq!(
                sensitivity["dependency_occurrences"],
                closure["evaluation"]["dependency_occurrences"]
            );
            assert_eq!(sensitivity["valuation_count"], 2);
            // Independently, inner returns not v under this admitted lexical binding.
            assert_eq!(
                sensitivity["parameters"],
                json!([{"parameter":"v","disposition":{
                    "status":"RETURN_CHANGES","inputs_with_parameter_false":[false],
                    "inputs_with_parameter_true":[true],"return_with_parameter_false":true,
                    "return_with_parameter_true":false
                }}])
            );
        }
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R38-002`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R38
    #[test]
    fn python_static_call_topology_retains_lexical_provenance_and_unavailable_root() {
        use fortress_core::python_observation::observe_python_native_call_topology;

        for name in ["locally_defined_shadow_free_function", "later_local_rebind"] {
            let (fixture, subject, producer, reply) =
                case(name, &format!("topology-python-{name}"));
            let examine = || {
                observe_python_native_call_topology(&fixture.root, &subject, &producer, |request| {
                    Ok(serde_json::to_vec(&bind(&request, &reply)).unwrap())
                })
                .unwrap()
            };
            let report = examine();
            assert_eq!(report, examine());
            assert_eq!(report["runtime_execution"], "NOT_RUN");
            assert_eq!(report["observation"]["source_ref"], subject.source_ref);
            let graph = &report["graph"];
            if name == "later_local_rebind" {
                assert_eq!(
                    graph,
                    &json!({"status":"UNAVAILABLE","root":null,"reason":"CALL_TARGET_UNESTABLISHED"})
                );
            } else {
                assert_eq!(graph["status"], "AVAILABLE");
                let root = graph["root"].as_str().unwrap();
                let site = &graph["sites"][0];
                assert_eq!(graph["sites"].as_array().unwrap().len(), 1);
                assert_eq!(site["caller"], root);
                assert_eq!(site["call"]["target"]["name"], "inner");
                assert_eq!(site["call"]["span"]["path"], subject.source_path);
                let target = site["target_body"].as_str().unwrap();
                assert_ne!(root, target);
                let map = &graph["topology"];
                assert_eq!(map["direct_callees"][root], json!([target]));
                assert_eq!(map["direct_callers"][target], json!([root]));
                assert_eq!(map["transitive_reachability"][root], json!([target]));
                assert_eq!(map["recursive_symbols"], json!([]));
                assert_eq!(map["leaf_symbols"], json!([target]));
                assert_eq!(graph["unavailable_targets"], json!([]));
            }
        }
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R35-001`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R35
    #[test]
    fn python_lexical_calls_compose_selected_cases_and_preserve_uncertainty() {
        for (name, expected) in [
            ("locally_defined_shadow_free_function", None),
            ("ordered_positionals", None),
            ("implicit_continuation_comment", None),
            ("explicit_continuation", None),
            ("later_local_rebind", Some("CALL_TARGET_UNESTABLISHED")),
            (
                "nested_recursive_capture",
                Some("LEXICAL_SCOPE_UNESTABLISHED"),
            ),
            ("decorated_local", Some("FUNCTION_FORM_UNSUPPORTED")),
        ] {
            let (fixture, subject, producer, reply) = case(name, name);
            let observe = || {
                observe_python_native_call_return(&fixture.root, &subject, &producer, |request| {
                    Ok(serde_json::to_vec(&bind(&request, &reply)).unwrap())
                })
                .unwrap()
            };
            let report = observe();
            assert_eq!(report, observe());
            assert_eq!(report["target_execution"], "NOT_RUN");
            assert_eq!(report["scope"], "BOUNDED_LEXICAL_BOOLEAN_CALL_RETURN");
            assert_eq!(report["source_ref"], subject.source_ref);
            if let Some(reason) = expected {
                assert!(report["evaluation"].is_null());
                assert_eq!(report["diagnostic"]["code"], reason);
                assert_eq!(report["calls"], json!([]));
            } else {
                assert!(report["diagnostic"].is_null());
                assert_eq!(report["calls"][0]["target"]["name"], "inner");
                assert_eq!(report["evaluation"]["status"], "COMPLETE");
                assert_eq!(report["evaluation"]["parameters"], json!(["v"]));
                assert_eq!(report["evaluation"]["returns"], json!([true, false]));
                assert_eq!(
                    report["evaluation"]["dependency_occurrences"]
                        .as_array()
                        .unwrap()
                        .len(),
                    1
                );
            }
        }
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R36-002`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R36
    #[test]
    fn python_lexical_call_candidate_keeps_unsupported_and_cancelled_results_distinct() {
        let (fixture, subject, producer, reply) =
            case("later_local_rebind", "retained_python_call");
        let source = fixture.root.join("fixture.py");
        let target = fs::read(&source).unwrap();
        let actual = b"def outer(v):\n    return v\n";
        fs::write(&source, actual).unwrap();
        let mut workspace = CandidateWorkspace::open_cold(&fixture.root).unwrap();
        let request = CandidateRequest {
            schema_version: 1,
            base_source_ref: workspace.base_source_ref().into(),
            context_ref: workspace.context_ref().into(),
            operations: vec![MigrationOperation::ReplaceFile {
                path: "fixture.py".into(),
                preimage: actual.to_vec(),
                postimage: target,
            }],
            comparison_context: ComparisonContext::default(),
        };
        let authority = CanonicalMigrationAuthority {
            policy: None,
            host: &UnmediatedHost,
            validator: &NoGrantValidator,
            evaluation_time: None,
            reviewed_initial_intent_ref: None,
            finding_proposal: None,
            identity_plan: None,
        };
        let cancelled = AtomicBool::new(false);
        let proposal = workspace
            .evaluate("owner", "edit", request, &authority, &cancelled)
            .unwrap();
        let retained = NativeCandidateSelection {
            client: "owner",
            candidate: "edit",
            cancelled: &cancelled,
        };
        let report = observe_python_candidate_call_return(
            &workspace,
            retained,
            &subject,
            &producer,
            |request| Ok(serde_json::to_vec(&bind(&request, &reply)).unwrap()),
        )
        .unwrap();
        let report = serde_json::to_value(report).unwrap();
        assert_eq!(report["schema_version"], 2);
        assert_eq!(report["language"], "python");
        assert_eq!(report["proposal_ref"], proposal.evaluation_ref());
        assert_eq!(report["source_ref"], subject.source_ref);
        assert_eq!(report["actual_state"], false);
        assert_eq!(report["comparison"], "NOT_COMPARED");
        assert!(report["native"]["result"].is_null());
        assert_eq!(report["native"]["limitation"], "CALL_TARGET_UNESTABLISHED");
        let refusal = observe_python_candidate_call_return(
            &workspace,
            retained,
            &subject,
            &producer,
            |request| {
                let report = bind(&request, &reply);
                cancelled.store(true, Ordering::Release);
                Ok(serde_json::to_vec(&report).unwrap())
            },
        )
        .err()
        .unwrap();
        assert_eq!(refusal.code, "CANCELLED");
        assert_eq!(fs::read(&source).unwrap(), actual);
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R41-002`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R41
    #[test]
    fn retained_python_dependency_projection_preserves_unavailable_ownership() {
        use fortress_core::python_observation::observe_python_candidate_call_module_boundaries;

        let (fixture, subject, producer, reply) = case(
            "locally_defined_shadow_free_function",
            "retained_python_owned_call",
        );
        let path = fixture.root.join("fixture.py");
        let target = fs::read(&path).unwrap();
        let original = b"def outer(v):\n    return v\n";
        fs::write(&path, original).unwrap();
        let mut workspace = CandidateWorkspace::open_cold(&fixture.root).unwrap();
        let request = CandidateRequest {
            schema_version: 1,
            base_source_ref: workspace.base_source_ref().into(),
            context_ref: workspace.context_ref().into(),
            operations: vec![MigrationOperation::ReplaceFile {
                path: "fixture.py".into(),
                preimage: original.to_vec(),
                postimage: target,
            }],
            comparison_context: ComparisonContext::default(),
        };
        let authority = CanonicalMigrationAuthority {
            policy: None,
            host: &UnmediatedHost,
            validator: &NoGrantValidator,
            evaluation_time: None,
            reviewed_initial_intent_ref: None,
            finding_proposal: None,
            identity_plan: None,
        };
        let cancelled = AtomicBool::new(false);
        let proposal = workspace
            .evaluate("owner", "edit", request, &authority, &cancelled)
            .unwrap();
        let retained = NativeCandidateSelection {
            client: "owner",
            candidate: "edit",
            cancelled: &cancelled,
        };
        let exchange = |request: Vec<u8>| Ok(serde_json::to_vec(&bind(&request, &reply)).unwrap());
        let output = observe_python_candidate_call_module_boundaries(
            &workspace, retained, &subject, &producer, exchange,
        )
        .unwrap();
        let report = serde_json::to_value(output).unwrap();
        assert_eq!(report["schema_version"], 3);
        assert_eq!(report["proposal_ref"], proposal.evaluation_ref());
        assert_eq!(report["source_ref"], subject.source_ref);
        assert_eq!(report["actual_state"], false);
        let observed = &report["native"]["report"];
        assert_eq!(
            observed["original_intent"],
            json!({"status":"ORIGINAL_INTENT_UNAVAILABLE"})
        );
        assert_eq!(
            observed["ownership_sites"][0]["relationship"],
            "DECLARED_OWNER_UNAVAILABLE"
        );
        assert_eq!(
            observed["source_view_sha256"],
            report["candidate_source_view_ref"]
        );
        assert_ne!(
            report["candidate_source_view_ref"],
            report["original_source_view_ref"]
        );

        let refusal = observe_python_candidate_call_module_boundaries(
            &workspace,
            retained,
            &subject,
            &producer,
            |request| {
                cancelled.store(true, Ordering::Release);
                exchange(request)
            },
        )
        .err()
        .unwrap();
        assert_eq!(refusal.code, "CANCELLED");
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R35-002`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R35
    #[test]
    fn python_lexical_calls_reject_displaced_evidence_and_source_drift() {
        let (fixture, subject, producer, reply) = case(
            "locally_defined_shadow_free_function",
            "lexical-call-rejected",
        );
        for (pointer, replacement) in [
            ("/schema", json!("fortress:python:scalar-response:1")),
            ("/helpers", json!([])),
            ("/body/0/value/call/target/span/path", json!("different.py")),
            ("/body/0/value/call/arguments", json!([])),
            (
                "/source_ref",
                json!("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
            ),
        ] {
            let failure =
                observe_python_native_call_return(&fixture.root, &subject, &producer, |request| {
                    let mut response = bind(&request, &reply);
                    *response.pointer_mut(pointer).unwrap() = replacement;
                    Ok(serde_json::to_vec(&response).unwrap())
                });
            assert!(
                matches!(
                    failure,
                    Err(PythonObservationError::Scalar(
                        PythonScalarError::InvalidResponse | PythonScalarError::Native(_)
                    ))
                ),
                "{pointer}"
            );
        }
        assert!(matches!(
            observe_python_scalar(&fixture.root, &subject, &producer, |request| {
                let selected: Value = serde_json::from_slice(&request).unwrap();
                let mut response = reply.clone();
                response["id"] = selected["id"].clone();
                Ok(serde_json::to_vec(&response).unwrap())
            }),
            Err(PythonObservationError::Scalar(
                PythonScalarError::InvalidResponse
            ))
        ));
        assert!(matches!(
            observe_python_native_call_return(&fixture.root, &subject, &producer, |request| {
                let response = bind(&request, &reply);
                fs::write(
                    fixture.root.join("fixture.py"),
                    b"# changed after observation\n",
                )
                .unwrap();
                Ok(serde_json::to_vec(&response).unwrap())
            }),
            Err(PythonObservationError::SourceChanged)
        ));
    }
}

mod test_declarations {
    use super::*;
    use fortress_core::python_observation::{
        PYTHON_TEST_OBSERVATION_SCHEMA as SCHEMA, observe_python_tests,
    };
    use serde_json::Value;

    const NATIVE: &[u8] = include_bytes!("../_data/python_test_fixture_v1.json");

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
        for path in ["tests/test_upper_suffix.PY", "tests/upper_suffix_test.PY"] {
            fs::write(fixture.root.join(path), "def test_unselected(): pass\n").unwrap();
        }
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
    const LAYOUT_REF: &str =
        "sha256:9515352f9c2d5e6bce1ec5871efce892ac068308baaf6706ed379fe86f52cbef";
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
        let layout = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../engine/project_model/testing/_data/layout_extension_example_v1.json"),
        )
        .expect("qualified external example is present in the exact test checkout");
        let profile = LayoutExtension::from_pinned_bytes(&layout, LAYOUT_REF).unwrap();
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
        assert_eq!(document["layout"]["selected_profile"]["digest"], LAYOUT_REF);
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

mod project_metadata {
    use super::{Fixture, fs, json};
    use fortress_core::portable::{canonical, digest};
    use fortress_core::python_project_observation::{
        PythonProjectObservationError, observe_python_project_metadata,
    };
    use serde_json::Value;

    const MANIFEST: &str = "packages/native lib/pyproject.toml";
    const STATIC: &[u8] =
        b"[project]\r\nname = 'density'\r\nversion = '1.0.0'\r\nrequires-python = '>=3.12'\r\n";
    const DYNAMIC: &[u8] = b"[project]\nname = 'density'\ndynamic = ['version', 'dependencies']\n";
    const BACKEND: &[u8] = b"[build-system]\nrequires = ['test-backend>=1']\nbuild-backend = 'test_backend.core'\nbackend-path = ['../untrusted']\n[project]\nname = 'density'\nversion = '1.0'\n";

    fn write(fixture: &Fixture, relative: &str, bytes: &[u8]) {
        let file = fixture.root.join(relative);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }

    fn observe(fixture: &Fixture) -> Value {
        serde_json::to_value(observe_python_project_metadata(&fixture.root, MANIFEST).unwrap())
            .unwrap()
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R31-001`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R31
    #[test]
    fn python_project_metadata_binds_declarations_and_exact_ordinary_inputs() {
        let fixture = Fixture::new("project-metadata");
        write(&fixture, MANIFEST, STATIC);
        write(
            &fixture,
            "packages/native lib/pylock.toml",
            b"sample lock bytes",
        );
        write(
            &fixture,
            "packages/native lib/uv.lock",
            b"second lock input",
        );
        write(
            &fixture,
            "packages/native lib/.venv/pyvenv.cfg",
            b"home = /not/a/runtime",
        );
        write(&fixture, "other/poetry.lock", b"outside selected scope");
        let origin = observe(&fixture);
        let original_bytes = canonical(&origin).unwrap();
        assert_eq!(original_bytes, canonical(&observe(&fixture)).unwrap());
        assert_eq!(origin["scope"], "STATIC_DECLARATIONS_ONLY");
        assert_eq!(origin["manifest_path"], MANIFEST);
        assert_eq!(origin["manifest_sha256"], digest(STATIC));
        assert_eq!(origin["runtime_selection"], "UNESTABLISHED");
        assert_eq!(
            origin["metadata"],
            json!({"status":"DECLARED","project":{"name":"density","version":"1.0.0",
                "requires_python":">=3.12","dynamic":[]},"build_system":null})
        );
        assert_eq!(
            origin["lock_files"],
            json!([
                {"path":"packages/native lib/pylock.toml","sha256":digest(b"sample lock bytes")},
                {"path":"packages/native lib/uv.lock","sha256":digest(b"second lock input")}
            ])
        );
        assert_eq!(
            origin["environment_marker"],
            json!({"path":"packages/native lib/.venv/pyvenv.cfg","sha256":digest(b"home = /not/a/runtime")})
        );
        assert!(
            !String::from_utf8(original_bytes.clone())
                .unwrap()
                .contains("/not/a/runtime")
        );
        let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let schema: Value = serde_json::from_slice(
            &fs::read(
                repository.join("engine/snapshot_governance/_data/python_metadata_schema_v1.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&origin));
        let mut false_runtime = origin.clone();
        false_runtime["runtime_selection"] = json!("SELECTED");
        assert!(!validator.is_valid(&false_runtime));
        write(
            &fixture,
            "packages/native lib/uv.lock",
            b"changed lock input",
        );
        let changed = observe(&fixture);
        assert_ne!(changed["source_fingerprint"], origin["source_fingerprint"]);
        assert_ne!(changed["source_view_digest"], origin["source_view_digest"]);
        assert_ne!(
            changed["source_manifest_digest"],
            origin["source_manifest_digest"]
        );
        assert_eq!(changed["authority_digest"], origin["authority_digest"]);
        assert_eq!(changed["metadata"], origin["metadata"]);
        write(
            &fixture,
            "packages/native lib/uv.lock",
            b"second lock input",
        );
        assert_eq!(original_bytes, canonical(&observe(&fixture)).unwrap());
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R31-002`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R31
    #[test]
    fn python_project_metadata_leaves_dynamic_and_backend_execution_unestablished() {
        let fixture = Fixture::new("dynamic-metadata");
        write(&fixture, MANIFEST, DYNAMIC);
        assert_eq!(
            observe(&fixture)["metadata"],
            json!({"status":"DECLARED","project":{"name":"density","version":null,
                "requires_python":null,"dynamic":["dependencies","version"]},"build_system":null})
        );
        write(&fixture, MANIFEST, BACKEND);
        let backend_path = "packages/untrusted/test_backend/core.py";
        write(
            &fixture,
            backend_path,
            b"from pathlib import Path\nPath('must-not-execute').touch()\n",
        );
        let report = observe(&fixture);
        assert_eq!(
            report["metadata"]["build_system"],
            json!({"backend":"test_backend.core","backend_path_declared":true})
        );
        assert_eq!(report["runtime_selection"], "UNESTABLISHED");
        assert!(!fixture.root.join("must-not-execute").exists());
        assert!(
            !fixture
                .root
                .join("packages/native lib/must-not-execute")
                .exists()
        );
        assert_eq!(report["manifest_sha256"], digest(BACKEND));
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R31-003`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R31
    #[test]
    fn python_project_metadata_distinguishes_missing_invalid_and_refused_paths() {
        let fixture = Fixture::new("invalid-metadata");
        let missing = observe(&fixture);
        assert_eq!(missing["metadata"], json!({"status":"MISSING"}));
        assert!(missing["manifest_sha256"].is_null());
        for (bytes, reason) in [
            (
                &b"[project]\nname = 'one'\nname = 'two'\n"[..],
                "INVALID_TOML",
            ),
            (
                &b"[project]\ndynamic = ['name','version']\n"[..],
                "INVALID_SELECTED_PROJECT_DECLARATIONS",
            ),
            (
                &b"[project]\nname = 'density'\nversion = '1'\ndynamic = ['version']\n"[..],
                "INVALID_SELECTED_PROJECT_DECLARATIONS",
            ),
            (
                &b"[project]\nname = 'density'\n"[..],
                "INVALID_SELECTED_PROJECT_DECLARATIONS",
            ),
            (
                &b"[build-system]\nrequires = 'untyped backend list'\n"[..],
                "INVALID_SELECTED_BUILD_DECLARATIONS",
            ),
            (&[255u8][..], "INVALID_UTF8"),
        ] {
            write(&fixture, MANIFEST, bytes);
            let actual = observe(&fixture);
            assert_eq!(
                actual["metadata"],
                json!({"status":"INVALID","reason":reason})
            );
            assert_eq!(actual["manifest_sha256"], digest(bytes));
        }
        write(&fixture, MANIFEST, &vec![b' '; (128 << 10) + 1]);
        assert_eq!(
            observe(&fixture)["metadata"],
            json!({"status":"UNAVAILABLE","reason":"RESOURCE_LIMIT"})
        );
        for unsafe_path in [
            "../pyproject.toml",
            "/pyproject.toml",
            "C:/pyproject.toml",
            "pkg\\pyproject.toml",
            "pkg//pyproject.toml",
            "pkg/PYPROJECT.TOML",
            "pkg/spoofed-pyproject.toml",
        ] {
            assert!(
                matches!(
                    observe_python_project_metadata(&fixture.root, unsafe_path),
                    Err(PythonProjectObservationError::InvalidManifestPath)
                ),
                "{unsafe_path}"
            );
        }
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

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R30-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R30
#[test]
fn python_boolean_sensitivity_retains_exact_host_scope_and_refuses_drift() {
    use fortress_core::python_observation::observe_python_scalar_sensitivity;
    let (fixture, subject, producer) = scalar_fixture("scalar-return-sensitivity");
    let inspect = || {
        observe_python_scalar_sensitivity(&fixture.root, &subject, &producer, |request| {
            scalar_reply(&request)
        })
    };
    let (native, result) = inspect().unwrap();
    let fortress_core::python_observation::NativeBodyOutcome::Lowered(body) = native.outcome()
    else {
        panic!("expected exact Boolean source body");
    };
    assert_eq!(fs::read(fixture.root.join(PATH)).unwrap(), SCALAR_SOURCE);
    let result = result.unwrap();
    assert_eq!(inspect().unwrap().1.as_ref(), Some(&result));
    let report = serde_json::to_value(result).unwrap();
    assert_eq!(report["occurrence_ref"], body.binding());
    assert_eq!(report["status"], "COMPLETE");
    assert_eq!(report["valuation_count"], 2);
    assert_eq!(report["parameters"][0]["parameter"], "gate");
    assert_eq!(
        report["parameters"][0]["disposition"],
        json!({
            "status":"RETURN_CHANGES","inputs_with_parameter_false":[false],
            "inputs_with_parameter_true":[true],
            "return_with_parameter_false":true,"return_with_parameter_true":false
        })
    );

    let changed =
        observe_python_scalar_sensitivity(&fixture.root, &subject, &producer, |request| {
            fs::write(fixture.root.join("note.txt"), "drift during exchange").unwrap();
            scalar_reply(&request)
        });
    assert!(matches!(
        changed,
        Err(PythonObservationError::SourceChanged)
    ));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R30-009`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R30
#[test]
fn python_candidate_sensitivity_keeps_candidate_source_and_refuses_interrupted_publication() {
    let (fixture, subject, producer) = scalar_fixture("python-scalar-candidate");
    let actual = b"def subject(gate):\n    return gate\n";
    fs::write(fixture.root.join(PATH), actual).unwrap();
    let mut workspace = CandidateWorkspace::open_cold(&fixture.root).unwrap();
    let request = CandidateRequest {
        schema_version: 1,
        base_source_ref: workspace.base_source_ref().into(),
        context_ref: workspace.context_ref().into(),
        operations: vec![MigrationOperation::ReplaceFile {
            path: PATH.into(),
            preimage: actual.to_vec(),
            postimage: SCALAR_SOURCE.to_vec(),
        }],
        comparison_context: ComparisonContext::default(),
    };
    let authority = CanonicalMigrationAuthority {
        policy: None,
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let cancelled = AtomicBool::new(false);
    let proposal = workspace
        .evaluate("owner", "edit", request, &authority, &cancelled)
        .unwrap();
    let selected = NativeCandidateSelection {
        client: "owner",
        candidate: "edit",
        cancelled: &cancelled,
    };
    let inspect = || {
        observe_python_candidate_sensitivity(&workspace, selected, &subject, &producer, |bytes| {
            scalar_reply(&bytes)
        })
    };
    let report = serde_json::to_value(inspect().unwrap()).unwrap();
    assert_eq!(report, serde_json::to_value(inspect().unwrap()).unwrap());
    assert_eq!(report["status"], "PROPOSED");
    assert_eq!(report["actual_state"], false);
    assert_eq!(report["comparison"], "NOT_COMPARED");
    assert_eq!(report["proposal_ref"], proposal.evaluation_ref());
    assert_eq!(report["source_ref"], digest(SCALAR_SOURCE));
    assert_eq!(report["native"]["sensitivity"]["valuation_count"], 2);
    assert_eq!(
        report["native"]["sensitivity"]["parameters"][0]["disposition"]["return_with_parameter_false"],
        true
    );
    assert_eq!(fs::read(fixture.root.join(PATH)).unwrap(), actual);

    let mut stale = subject.clone();
    stale.source_ref = digest(actual);
    let refusal =
        observe_python_candidate_sensitivity(&workspace, selected, &stale, &producer, |_| {
            panic!("actual preimage cannot stand in for proposed source")
        })
        .err()
        .unwrap();
    assert_eq!(refusal.code, "NATIVE_SUBJECT_MISMATCH");

    let interrupted =
        observe_python_candidate_sensitivity(&workspace, selected, &subject, &producer, |bytes| {
            cancelled.store(true, Ordering::Release);
            scalar_reply(&bytes)
        })
        .err()
        .unwrap();
    assert_eq!(interrupted.code, "CANCELLED");
    cancelled.store(false, Ordering::Release);
    let stale_base =
        observe_python_candidate_sensitivity(&workspace, selected, &subject, &producer, |bytes| {
            fs::write(
                fixture.root.join("note.txt"),
                "external edit during analysis",
            )
            .unwrap();
            scalar_reply(&bytes)
        })
        .err()
        .unwrap();
    assert_eq!(stale_base.code, "STALE_BASE");
    assert_eq!(fs::read(fixture.root.join(PATH)).unwrap(), actual);
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

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-019`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn scoped_python_intent_retains_only_admitted_edges_and_explicit_unavailability() {
    use fortress_core::python_observation::observe_python_static_dependency_intent;

    let fixture = dependency_fixture("python-dependency-intent");
    let (bytes, scope_ref) = import_scope(&["_code", "vendor"], "COMPLETE_SOURCE_ONLY");
    let scope = PythonImportScope::admit(&bytes, &scope_ref).unwrap();
    let inspect = || {
        observe_python_static_dependency_intent(
            &fixture.root,
            PATH,
            &pin(),
            &scope,
            dependency_reply,
        )
        .unwrap()
    };
    let first = inspect();
    let report = first.intent().unwrap();
    assert_eq!(report["status"], "COMPARED");
    assert_eq!(report, inspect().intent().unwrap());
    let records = report["records"].as_array().unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|row| row["state"] == "OBSERVED_UNDECLARED")
            .count(),
        1
    );
    assert!(
        records
            .iter()
            .all(|row| row["state"] != "DECLARED_UNOBSERVED")
    );
    let edge = records
        .iter()
        .find(|row| row["state"] == "OBSERVED_UNDECLARED")
        .unwrap();
    assert_eq!(edge["source_module"], CONSUMER);
    assert_eq!(edge["target_module"], PROVIDER);
    assert_eq!(edge["evidence"][0]["source_path"], PATH);
    fs::write(
        fixture.root.join("_code/unsupported.pyd"),
        b"not Python source",
    )
    .unwrap();
    assert_eq!(
        inspect().intent().unwrap(),
        &json!({"status":"NATIVE_OBSERVATION_UNAVAILABLE"})
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-018`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn scoped_python_dependencies_use_physical_ownership_after_logical_selection() {
    use fortress_core::python_observation::{
        PythonStaticDependencyOutcome, observe_python_static_dependencies,
    };

    let fixture = dependency_fixture("physical-dependency-ownership");
    let provider = fixture.root.join("library");
    fs::create_dir_all(provider.join("_code")).unwrap();
    fs::copy(
        fixture
            .root
            .join("_data/logical_modules/provider/contract.json"),
        provider.join("contract.json"),
    )
    .unwrap();
    let selected = b"member = 7\n";
    fs::write(provider.join("_code/chosen.py"), selected).unwrap();
    fixture.configure(
        &serde_json::to_vec(&json!({
            "$schema":"urn:fortress:schema:v3:project-configuration","schema_version":3,
            "observation_exclusions":[],
            "logical_modules":[{
                "module":CONSUMER,
                "contract":"_data/logical_modules/consumer/contract.json",
                "parent":"PF-PYTHON-FIXTURE",
                "bindings":[{"kind":"file","path":PATH}]
            }],
        }))
        .unwrap(),
    );
    let inspect = |roots: &[&str]| {
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
            panic!("expected scoped dependency observation")
        };
        assert!(ownership_diagnostics.is_empty());
        projection.clone()
    };
    let exact = inspect(&["library/_code", "_code", "vendor"]);
    assert_eq!(
        exact["sites"][0]["target"]["file"]["path"],
        "library/_code/chosen.py"
    );
    assert_eq!(exact["sites"][0]["target"]["ownership"]["module"], PROVIDER);
    assert_eq!(exact["sites"][0]["source_ownership"]["module"], CONSUMER);
    let edges = exact["observation"]["module_dependencies"]
        .as_array()
        .unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0]["source_module"], CONSUMER);
    assert_eq!(edges[0]["target_module"], PROVIDER);
    assert_eq!(exact, inspect(&["library/_code", "_code", "vendor"]));
    let alternate = inspect(&["vendor", "library/_code", "_code"]);
    assert_eq!(
        alternate["sites"][0]["target"]["file"]["path"],
        "vendor/chosen.py"
    );
    assert_eq!(
        alternate["sites"][0]["target"]["ownership"]["state"],
        "ownership_unavailable"
    );
    assert_eq!(alternate["observation"]["module_dependencies"], json!([]));
    assert_eq!(
        fs::read(provider.join("_code/chosen.py")).unwrap(),
        selected
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

mod callable_links {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use fortress_core::native_return_observation::{
        AuthoredNativeReturnComparison, NativeReturnComparisonLimitation,
    };
    use fortress_core::program_semantics::native_callable::{
        NativeCallableLimitation, NativeCallableOutcome,
    };
    use fortress_core::python_observation::{
        PythonCallableSelection, observe_python_authored_native_return,
        observe_python_linked_callable,
    };

    const CONSUMER_RETURN: &str = "authoring/consumer/data/native_function_contracts.json";
    const PROVIDER_RETURN: &str = "authoring/provider/data/native_function_contracts.json";
    // Frozen from the native namespace and symbol named in the independent fixture.
    const PYTHON_SLOT: &str = "python_lexical_callable_slot:v1:sha256:14b23faa20cacf2547dee241035bf6957f7fa2eb449c3e0c9b6539999657210b";

    const UNCHANGED: &[u8] = b"def subject():\n    return True\n";
    const RELOCATED: &[u8] = b"# moved\r\ndef subject():\r\n    return True\r\n";
    const RUNTIME: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn producer() -> PythonScalarProducer {
        PythonScalarProducer::new(RUNTIME, digest(b"worker"), digest(b"bootstrap")).unwrap()
    }

    fn selection(module: &str) -> PythonCallableSelection<'_> {
        PythonCallableSelection {
            module,
            function: "subject",
        }
    }

    fn scope() -> PythonImportScope {
        let (wire, reference) = import_scope(&["_code", "vendor"], "COMPLETE_SOURCE_ONLY");
        PythonImportScope::admit(&wire, &reference).unwrap()
    }

    fn replay_path(value: &mut serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Object(fields) => {
                if let Some(value) = fields.get_mut("path") {
                    *value = json!(path);
                }
                for child in fields.values_mut() {
                    replay_path(child, path);
                }
            }
            serde_json::Value::Array(rows) => {
                for child in rows {
                    replay_path(child, path);
                }
            }
            _ => {}
        }
    }

    fn reply(payload: &[u8]) -> Result<Vec<u8>, PythonObservationError> {
        let request: serde_json::Value = serde_json::from_slice(payload).unwrap();
        let source = STANDARD
            .decode(request["source"].as_str().unwrap())
            .unwrap();
        let reference = digest(&source);
        let fixture: serde_json::Value =
            serde_json::from_slice(include_bytes!("../_data/python_callable_fixture_v1.json"))
                .unwrap();
        let mut report = fixture["checked"]
            .as_object()
            .unwrap()
            .values()
            .find(|row| row["source_ref"] == reference)
            .expect("exact native compiler fixture")
            .clone();
        // Only the host's per-request correlation and selected file labels
        // differ. Scalar facts, physical coordinates and limitations stay frozen.
        for field in [
            "id",
            "source_path",
            "runtime_ref",
            "worker_ref",
            "bootstrap_ref",
        ] {
            report[field] = request[field].clone();
        }
        replay_path(&mut report, request["source_path"].as_str().unwrap());
        serde_json::to_vec(&report).map_err(|error| PythonScalarError::Json(error).into())
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R30-004`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R30
    #[test]
    fn python_callable_keeps_lexical_module_and_body_identity_separate() {
        let fixture = dependency_fixture("python-callable");
        let mut subjects = Vec::new();
        for (path, source) in [
            ("_code/source.py", UNCHANGED),
            ("vendor/source.py", RELOCATED),
        ] {
            fs::write(fixture.root.join(path), source).unwrap();
            let outcome = observe_python_linked_callable(
                &fixture.root,
                selection("source"),
                &scope(),
                &producer(),
                |frame| reply(&frame),
            )
            .unwrap();
            let NativeCallableOutcome::Linked(subject) = outcome else {
                panic!("unique selected source and closed body should link");
            };
            assert_eq!(subject.namespace(), "source");
            assert_eq!(subject.function(), "subject");
            assert_eq!(subject.source_path(), path);
            assert_eq!(subject.source_ref(), digest(source));
            assert!(subject.body().parameters().is_empty());
            let declared = subject.declared_source_owner();
            if path == PATH {
                assert_eq!(declared.unwrap().owner(), CONSUMER);
            } else {
                assert!(declared.is_none());
            }
            assert_ne!(subject.link_ref(), subject.body().binding());
            subjects.push(subject);
            fs::remove_file(fixture.root.join(path)).unwrap();
        }
        assert_eq!(subjects[0].slot_ref(), subjects[1].slot_ref());
        assert_ne!(subjects[0].link_ref(), subjects[1].link_ref());
        assert_ne!(subjects[0].body().binding(), subjects[1].body().binding());
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R30-005`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R30
    #[test]
    fn python_callable_refuses_alternate_origins_and_stale_physical_source() {
        let fixture = import_fixture("python-callable-ambiguity");
        fs::write(fixture.root.join(PATH), UNCHANGED).unwrap();
        let alternate = fixture.root.join("vendor/source.py");
        fs::write(&alternate, RELOCATED).unwrap();
        let result = observe_python_linked_callable(
            &fixture.root,
            selection("source"),
            &scope(),
            &producer(),
            |_| panic!("ambiguous static origin must never dispatch"),
        )
        .unwrap();
        assert!(matches!(
            result,
            NativeCallableOutcome::Unavailable(NativeCallableLimitation::AmbiguousSubject)
        ));
        fs::remove_file(alternate).unwrap();

        fs::create_dir(fixture.root.join("vendor/source")).unwrap();
        fs::write(
            fixture.root.join("vendor/source/portion.py"),
            b"flag = False\n",
        )
        .unwrap();
        let namespace = observe_python_linked_callable(
            &fixture.root,
            selection("source"),
            &scope(),
            &producer(),
            |_| panic!("namespace alternative must never dispatch"),
        )
        .unwrap();
        assert!(matches!(
            namespace,
            NativeCallableOutcome::Unavailable(NativeCallableLimitation::AmbiguousSubject)
        ));

        fs::remove_file(fixture.root.join("vendor/source/portion.py")).unwrap();

        fs::write(
            fixture.root.join(PATH),
            b"def subject():\n    return True\nsubject = None\n",
        )
        .unwrap();
        let rebound = observe_python_linked_callable(
            &fixture.root,
            selection("source"),
            &scope(),
            &producer(),
            |frame| reply(&frame),
        )
        .unwrap();
        assert!(matches!(
            rebound,
            NativeCallableOutcome::Unavailable(NativeCallableLimitation::BodyUnavailable)
        ));
        fs::write(fixture.root.join(PATH), UNCHANGED).unwrap();
        let result = observe_python_linked_callable(
            &fixture.root,
            selection("source"),
            &scope(),
            &producer(),
            |frame| {
                let report = reply(&frame)?;
                fs::write(fixture.root.join("note.txt"), b"late source change").unwrap();
                Ok(report)
            },
        );
        assert!(matches!(result, Err(PythonObservationError::SourceChanged)));
    }

    fn contract_fixture(name: &str) -> Fixture {
        let fixture = dependency_fixture(name);
        fs::write(fixture.root.join(PATH), UNCHANGED).unwrap();

        let original = fixture.root.join("__fortress/.fsconfig");
        let mut project: serde_json::Value =
            serde_json::from_slice(&fs::read(original).unwrap()).unwrap();
        for (entry, path) in project["logical_modules"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .zip(["authoring/consumer", "authoring/provider"])
        {
            fs::create_dir_all(fixture.root.join(path).join("data")).unwrap();
            entry["bindings"]
                .as_array_mut()
                .unwrap()
                .push(json!({"kind":"directory","path":path}));
        }
        fixture.configure(&serde_json::to_vec(&project).unwrap());
        fixture
    }

    fn write_return_contract(fixture: &Fixture, path: &str, required: bool) -> Vec<u8> {
        let mut bytes = serde_json_canonicalizer::to_vec(&json!({
            "$schema":"urn:fortress:schema:v1:native-function-contracts",
            "schema_version":1,
            "functions":[{"subject":PYTHON_SLOT,"required_return":required}],
        }))
        .unwrap();
        bytes.push(b'\n');
        fs::write(fixture.root.join(path), &bytes).unwrap();
        bytes
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R37-002`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R37
    #[test]
    fn python_authored_call_return_preserves_original_authority_and_limits() {
        use fortress_core::python_observation::observe_python_authored_call_return;
        use fortress_core::semantic_analysis::NativeBooleanReturn;

        let frozen: serde_json::Value =
            serde_json::from_slice(include_bytes!("../_data/authored_call_fixture_v1.json"))
                .unwrap();
        for (name, required, foreign) in [
            ("complete", true, false),
            ("complete", false, false),
            ("complete", true, true),
            ("rebound", true, false),
        ] {
            let fixture = contract_fixture(&format!("authored-call-{name}-{required}-{foreign}"));
            let row = &frozen["python"][name];
            let source = row["source"].as_str().unwrap().as_bytes();
            let captured = &row["reply"];
            let producer = PythonScalarProducer::new(
                captured["worker_ref"].as_str().unwrap(),
                captured["bootstrap_ref"].as_str().unwrap(),
                captured["runtime_ref"].as_str().unwrap(),
            )
            .unwrap();
            fs::write(fixture.root.join(PATH), source).unwrap();
            let path = if foreign {
                PROVIDER_RETURN
            } else {
                CONSUMER_RETURN
            };
            let authored = write_return_contract(&fixture, path, required);
            let result = observe_python_authored_call_return(
                &fixture.root,
                selection("source"),
                &scope(),
                &producer,
                |request| {
                    let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
                    assert_eq!(request["source_ref"], digest(source));
                    assert_eq!(request["schema"], "fortress:python:lexical-call-request:1");
                    for field in [
                        "source_path",
                        "source_ref",
                        "runtime_ref",
                        "worker_ref",
                        "bootstrap_ref",
                    ] {
                        assert_eq!(request[field], row["request"][field]);
                    }
                    let mut reply = captured.clone();
                    reply["id"] = request["id"].clone();
                    Ok(serde_json::to_vec(&reply).unwrap())
                },
            )
            .unwrap();
            let evaluation = serde_json::to_value(result.call_evaluation()).unwrap();
            match result.observation.comparison {
                AuthoredNativeReturnComparison::Observed(checked)
                    if name == "complete" && !foreign =>
                {
                    let expected = if required {
                        NativeBooleanReturn::MatchesRequiredValue
                    } else {
                        NativeBooleanReturn::ExcludesRequiredValue
                    };
                    assert_eq!(checked.observed_return, expected);
                    assert_eq!(checked.contract_ref, digest(&authored));
                    assert_eq!(evaluation["returns"], json!([true]));
                    assert_eq!(
                        evaluation["dependency_occurrences"]
                            .as_array()
                            .unwrap()
                            .len(),
                        1
                    );
                }
                AuthoredNativeReturnComparison::Unavailable(
                    NativeReturnComparisonLimitation::ForeignContractOwner,
                ) if foreign => assert_eq!(evaluation["returns"], json!([true])),
                AuthoredNativeReturnComparison::Unavailable(
                    NativeReturnComparisonLimitation::SubjectUnavailable,
                ) if name == "rebound" => assert!(evaluation.is_null()),
                result => panic!("unanticipated authored call result {result:?}"),
            }
            assert_eq!(fs::read(fixture.root.join(PATH)).unwrap(), source);
            assert_eq!(fs::read(fixture.root.join(path)).unwrap(), authored);
        }
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R30-006`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R30
    #[test]
    fn native_return_comparison_uses_exact_original_owner_and_bytes() {
        use fortress_core::semantic_analysis::NativeBooleanReturn;

        let fixture = contract_fixture("native-return-exact");
        let inspect = || {
            observe_python_authored_native_return(
                &fixture.root,
                selection("source"),
                &scope(),
                &producer(),
                |frame| reply(&frame),
            )
            .unwrap()
        };
        assert!(matches!(
            inspect().comparison,
            AuthoredNativeReturnComparison::Unavailable(
                NativeReturnComparisonLimitation::RequirementUnavailable
            )
        ));

        let mut evaluations = Vec::new();
        for (required, expected) in [
            (true, NativeBooleanReturn::MatchesRequiredValue),
            (false, NativeBooleanReturn::ExcludesRequiredValue),
        ] {
            let document = write_return_contract(&fixture, CONSUMER_RETURN, required);
            let result = inspect();
            let NativeCallableOutcome::Linked(subject) = result.subject else {
                panic!("fixture pins one uniquely admitted lexical declaration");
            };
            assert_eq!(subject.slot_ref(), PYTHON_SLOT);
            assert_eq!(subject.source_ref(), digest(UNCHANGED));
            let AuthoredNativeReturnComparison::Observed(observed) = result.comparison else {
                panic!("original territory supplies a single exact requirement");
            };
            assert_eq!(observed.author, CONSUMER);
            assert_eq!(observed.contract_path, CONSUMER_RETURN);
            assert_eq!(observed.contract_ref, digest(&document));
            assert_eq!(observed.required_return, required);
            assert_eq!(observed.observed_return, expected);
            assert_eq!(
                fs::read(fixture.root.join(CONSUMER_RETURN)).unwrap(),
                document
            );
            evaluations.push(subject.evaluation().source_manifest_digest().to_owned());
        }
        assert_ne!(evaluations[0], evaluations[1]);
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R30-007`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R30
    #[test]
    fn native_return_comparison_refuses_foreign_conflicting_and_drifting_authority() {
        use NativeReturnComparisonLimitation as Limit;
        use fortress_core::authority_roles::{ProtectedClass, protected_input_roles};
        use fortress_core::control_layout::ControlLayout;

        let fixture = contract_fixture("native-return-refusal");
        let inspect = || {
            observe_python_authored_native_return(
                &fixture.root,
                selection("source"),
                &scope(),
                &producer(),
                |frame| reply(&frame),
            )
            .unwrap()
        };
        write_return_contract(&fixture, PROVIDER_RETURN, true);
        assert!(matches!(
            inspect().comparison,
            AuthoredNativeReturnComparison::Unavailable(Limit::ForeignContractOwner)
        ));
        write_return_contract(&fixture, CONSUMER_RETURN, true);
        assert!(matches!(
            inspect().comparison,
            AuthoredNativeReturnComparison::Unavailable(Limit::AmbiguousRequirement)
        ));
        fs::write(fixture.root.join(PROVIDER_RETURN), b"{").unwrap();
        assert!(
            protected_input_roles(&ControlLayout::standard(), PROVIDER_RETURN, None)
                .contains(&ProtectedClass::ModuleIntent)
        );
        assert!(matches!(
            inspect().comparison,
            AuthoredNativeReturnComparison::Unavailable(Limit::InvalidContractDocument)
        ));

        fs::remove_file(fixture.root.join(PROVIDER_RETURN)).unwrap();
        let drifted = observe_python_authored_native_return(
            &fixture.root,
            selection("source"),
            &scope(),
            &producer(),
            |frame| {
                write_return_contract(&fixture, CONSUMER_RETURN, false);
                reply(&frame)
            },
        );
        assert!(matches!(
            drifted,
            Err(PythonObservationError::SourceChanged)
        ));
    }
}

mod filesystem {
    use super::*;
    use fortress_core::portable::canonical;
    use fortress_core::python_observation::{
        PYTHON_FILESYSTEM_OBSERVATION_SCHEMA as SCHEMA, PYTHON_FILESYSTEM_POLICY_SCHEMA,
        PythonFilesystemHost, PythonFilesystemProfile, observe_hypothetical_python_filesystem,
        observe_hypothetical_python_filesystem_policy, python_filesystem_origin_manifest,
    };
    use serde_json::Value;

    const RECEIPT: &[u8] = include_bytes!("../_data/python_effect_fixture_v1.json");
    fn origin() -> &'static [u8] {
        let bytes = python_filesystem_origin_manifest(PythonFilesystemProfile::WindowsX64);
        assert_eq!(
            digest(bytes),
            "sha256:d64d760d5aa32736dc505121364f40fbb0c52aef5e400536c80935ac6236db9c"
        );
        bytes
    }

    fn make_fixture(name: &str) -> (Fixture, Value, PythonScalarSubject, PythonImportScope) {
        let fixture = Fixture::new(name);
        let native: Value = serde_json::from_slice(RECEIPT).unwrap();
        let source = native["source"].as_str().unwrap();
        fs::create_dir(fixture.root.join("src")).unwrap();
        fs::write(fixture.root.join("src/effect.py"), source).unwrap();
        let exact = PythonScalarSubject {
            source_path: "src/effect.py".into(),
            source_ref: digest(source.as_bytes()),
            function: "selected".into(),
            exact_bool_parameters: Vec::new(),
        };
        let config = canonical(&json!({
            "$schema": "urn:fortress:host:v1:python-static-import-scope",
            "schema_version": 1,
            "inventory": "COMPLETE_SOURCE_ONLY",
            "roots": ["src"],
        }))
        .unwrap();
        let scope = PythonImportScope::admit(&config, &digest(&config)).unwrap();
        (fixture, native, exact, scope)
    }

    fn selected_producer(native: &Value) -> PythonScalarProducer {
        let frame: Value = serde_json::from_str(native["ready"].as_str().unwrap()).unwrap();
        PythonScalarProducer::new(
            frame["worker_ref"].as_str().unwrap(),
            frame["bootstrap_ref"].as_str().unwrap(),
            frame["runtime_ref"].as_str().unwrap(),
        )
        .unwrap()
    }

    fn replay(native: &Value, request: &[u8], readiness: &[u8]) -> Vec<u8> {
        assert_eq!(readiness, native["ready"].as_str().unwrap().as_bytes());
        let request: Value = serde_json::from_slice(request).unwrap();
        let mut response: Value = serde_json::from_str(native["reply"].as_str().unwrap()).unwrap();
        assert_eq!(request["source_ref"], response["source_ref"]);
        assert_eq!(request["source_path"], response["source_path"]);
        // This deterministic replay varies only the test capture's exact
        // correlation. Production CLI qualification uses unmodified live frames.
        response["id"] = request["id"].clone();
        let mut bytes = canonical(&response).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn host(producer: &PythonScalarProducer) -> PythonFilesystemHost<'_> {
        PythonFilesystemHost {
            producer,
            profile: PythonFilesystemProfile::WindowsX64,
            supervisor_ref: CONTEXT,
        }
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-015`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
    #[test]
    fn hypothetical_python_filesystem_preserves_original_and_refuses_scope_or_origin() {
        let (fixture, native, subject, scope) = make_fixture("effect-conditional");
        let producer = selected_producer(&native);
        let run = || {
            observe_hypothetical_python_filesystem(
                &fixture.root,
                &subject,
                &scope,
                host(&producer),
                |request, ready| Ok(replay(&native, request, ready)),
                || Ok(origin().to_vec()),
            )
        };
        let report = serde_json::to_value(run().unwrap()).unwrap();
        assert_eq!(report, serde_json::to_value(run().unwrap()).unwrap());
        jsonschema::draft202012::validate(&serde_json::from_str(SCHEMA).unwrap(), &report)
            .expect("strict conditional observation schema");
        assert_eq!(report["status"], "CONDITIONAL");
        assert_eq!(report["actual_project_binding"], "UNESTABLISHED");
        assert_eq!(report["runtime_execution"], "NOT_RUN");
        assert_eq!(report["canonical_finding_or_certificate"], "NOT_ISSUED");
        let effect = &report["effect"];
        assert_eq!(effect["site"], json!([63, 104]));
        assert_eq!(effect["upper_bound"], json!({"state":"UNKNOWN"}));
        assert_eq!(
            effect["catalog_disposition"]["effects"],
            json!(["filesystem.write"])
        );
        assert_eq!(effect["installed_origin_sha256"], digest(origin()));
        assert!(!fixture.root.join("sentinel.bin").exists());

        let refused = observe_hypothetical_python_filesystem(
            &fixture.root,
            &subject,
            &scope,
            host(&producer),
            |request, ready| Ok(replay(&native, request, ready)),
            || Ok(b"{}".to_vec()),
        );
        assert!(matches!(
            refused,
            Err(PythonObservationError::HostUnavailable)
        ));

        fs::write(fixture.root.join("src/pathlib.py"), "# local alternative\n").unwrap();
        let local = observe_hypothetical_python_filesystem(
            &fixture.root,
            &subject,
            &scope,
            host(&producer),
            |_, _| panic!("local alternative must veto the source worker"),
            || panic!("local alternative must veto the origin worker"),
        )
        .unwrap();
        let local = serde_json::to_value(local).unwrap();
        assert_eq!(local["status"], "LOCAL_IMPORT_OR_SCOPE_UNRESOLVED");
        assert_eq!(local["effect"], Value::Null);
        assert_eq!(local["installed_origin_ref"], Value::Null);
    }

    const EFFECT_CONTRACT: &str = "_data/logical_modules/effects/contract.json";
    const EFFECT_OWNER: &str = "AF-PYTHON-EFFECTS-0001";

    fn select_effect_owner(fixture: &Fixture) {
        write_dependency_contract(
            &fixture.root.join("contract.json"),
            json!({
                "$schema":"urn:fortress:schema:v2:module-contract", "schema_version":2,
                "id":"PF-PYTHON-EFFECTS", "display_name":"Python effect fixture",
                "ecosystem":{"repository_grammar":1,
                    "standard":{"id":"STD-FORTRESS-ENGINEERING","edition":"1.0.0-draft.2"}},
                "provides":[],"requires":[],"relationships":[],"constraints":[],
                "guarantees":[],"features":[],"behavior":[]
            }),
        );
        fixture.configure(&serde_json::to_vec(&json!({
            "$schema":"urn:fortress:schema:v3:project-configuration", "schema_version":3,
            "observation_exclusions":[],
            "logical_modules":[{"module":EFFECT_OWNER,"contract":EFFECT_CONTRACT,
                "parent":"PF-PYTHON-EFFECTS","bindings":[{"kind":"file","path":"src/effect.py"}]}]
        })).unwrap());
    }

    fn write_effect_contract(fixture: &Fixture, allow_write: Option<bool>) -> String {
        let output = fixture.root.join(EFFECT_CONTRACT);
        fs::create_dir_all(output.parent().unwrap()).unwrap();
        let mut contract = json!({
            "$schema":"urn:fortress:schema:v2:module-contract", "schema_version":2,
            "id":EFFECT_OWNER, "display_name":"Python effect owner",
            "provides":[],"requires":[],"relationships":[],"constraints":[],
            "guarantees":[],"features":[],"behavior":[]
        });
        if let Some(allow) = allow_write {
            contract["$schema"] = json!("urn:fortress:schema:v3:module-contract");
            contract["schema_version"] = json!(3);
            let (effect_allow, effect_deny) = if allow {
                (["filesystem.write"].as_slice(), [].as_slice())
            } else {
                ([].as_slice(), ["filesystem.write"].as_slice())
            };
            let (capability_allow, capability_deny) = if allow {
                ([].as_slice(), ["filesystem"].as_slice())
            } else {
                (["filesystem"].as_slice(), [].as_slice())
            };
            contract["semantic_policy"] = json!({
                "default":"UNDECLARED",
                "capabilities":{"allow":capability_allow, "deny":capability_deny},
                "effects":{"allow":effect_allow, "deny":effect_deny}
            });
        }
        write_dependency_contract(&output, contract);
        digest(&fs::read(output).unwrap())
    }

    fn policy_receipt(
        fixture: &Fixture,
        native: &Value,
        subject: &PythonScalarSubject,
        scope: &PythonImportScope,
    ) -> Value {
        let producer = selected_producer(native);
        let report = observe_hypothetical_python_filesystem_policy(
            &fixture.root,
            subject,
            scope,
            host(&producer),
            |request, ready| Ok(replay(native, request, ready)),
            || Ok(origin().to_vec()),
        )
        .unwrap();
        let document = serde_json::to_value(report).unwrap();
        let schema: Value = serde_json::from_str(PYTHON_FILESYSTEM_POLICY_SCHEMA).unwrap();
        let underlying: Value = serde_json::from_str(SCHEMA).unwrap();
        jsonschema::draft202012::options()
            .with_resource(
                "urn:fortress:derived:v1:python-hypothetical-filesystem",
                jsonschema::Resource::from_contents(underlying).unwrap(),
            )
            .build(&schema)
            .unwrap()
            .validate(&document)
            .expect("strict hypothetical policy schema");
        document
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-016`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
    #[test]
    fn hypothetical_python_filesystem_policy_projects_exact_original_owner_and_precedence() {
        let (fixture, native, subject, scope) = make_fixture("conditional-effect-policy");
        let run = || policy_receipt(&fixture, &native, &subject, &scope);
        let unowned = run();
        assert_eq!(unowned["ownership"], Value::Null);
        assert_eq!(unowned["authored_policy"], Value::Null);

        select_effect_owner(&fixture);
        let absent_digest = write_effect_contract(&fixture, None);
        let absent = run();
        assert_eq!(absent["original_contract_digest"], absent_digest);
        assert_eq!(absent["authored_policy"]["authored_policy"], "ABSENT");
        assert_eq!(
            absent["authored_policy"]["site"]["effects"][0]["disposition"]["status"],
            "NO_AUTHORED_POLICY"
        );
        for (allow, expected) in [(false, "DENY"), (true, "ALLOW")] {
            let contract_digest = write_effect_contract(&fixture, Some(allow));
            let report = run();
            assert_eq!(report["original_contract_digest"], contract_digest);
            assert_eq!(report["original_contract_path"], EFFECT_CONTRACT);
            assert_eq!(report["ownership"]["owner"], EFFECT_OWNER);
            assert_eq!(report["ownership"]["source_path"], subject.source_path);
            assert_eq!(report["runtime_reachability"], "UNKNOWN");
            assert_eq!(report["canonical_conformance"], "NOT_EVALUATED");
            let view = &report["authored_policy"];
            assert_eq!(view["scope"], "HYPOTHETICAL_CLOSED_REFERENCE_ONLY");
            let site = &view["site"];
            assert_eq!(site["start_byte"], 63);
            assert_eq!(site["end_byte"], 104);
            let decision = &site["effects"][0]["disposition"]["decision"];
            assert_eq!(decision["governing_target_kind"], "EFFECT");
            assert_eq!(decision["governing_target"], "filesystem.write");
            assert_eq!(decision["disposition"], expected);
            let old = observe_hypothetical_python_filesystem(
                &fixture.root,
                &subject,
                &scope,
                host(&selected_producer(&native)),
                |request, ready| Ok(replay(&native, request, ready)),
                || Ok(origin().to_vec()),
            )
            .unwrap();
            assert_eq!(
                report["hypothetical_receipt"],
                serde_json::to_value(old).unwrap()
            );
            assert_eq!(report, run());
        }
        assert!(!fixture.root.join("sentinel.bin").exists());
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R29-017`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
    #[test]
    fn hypothetical_python_filesystem_policy_withholds_stale_or_vetoed_operation() {
        let (fixture, native, subject, scope) = make_fixture("conditional-effect-policy-stale");
        select_effect_owner(&fixture);
        write_effect_contract(&fixture, Some(false));
        let producer = selected_producer(&native);
        let drift = observe_hypothetical_python_filesystem_policy(
            &fixture.root,
            &subject,
            &scope,
            host(&producer),
            |request, ready| Ok(replay(&native, request, ready)),
            || {
                write_effect_contract(&fixture, Some(true));
                Ok(origin().to_vec())
            },
        );
        assert!(matches!(drift, Err(PythonObservationError::SourceChanged)));

        let refused = observe_hypothetical_python_filesystem_policy(
            &fixture.root,
            &subject,
            &scope,
            host(&producer),
            |request, ready| Ok(replay(&native, request, ready)),
            || Ok(b"{}".to_vec()),
        );
        assert!(matches!(
            refused,
            Err(PythonObservationError::HostUnavailable)
        ));

        fs::write(
            fixture.root.join("src/pathlib.py"),
            "# original local alternative\n",
        )
        .unwrap();
        let local = observe_hypothetical_python_filesystem_policy(
            &fixture.root,
            &subject,
            &scope,
            host(&producer),
            |_, _| panic!("local alternative must veto the source worker"),
            || panic!("local alternative must veto the origin worker"),
        )
        .unwrap();
        let local = serde_json::to_value(local).unwrap();
        assert_eq!(local["ownership"]["owner"], EFFECT_OWNER);
        assert_eq!(local["authored_policy"], Value::Null);
        assert_eq!(
            local["hypothetical_receipt"]["status"],
            "LOCAL_IMPORT_OR_SCOPE_UNRESOLVED"
        );
        assert_eq!(
            local["hypothetical_receipt"]["actual_project_binding"],
            "UNESTABLISHED"
        );
        assert!(!fixture.root.join("sentinel.bin").exists());
    }
}
