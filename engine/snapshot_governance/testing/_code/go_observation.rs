//! Exact native Go admission and refusal controls.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::go_observation::{
    GoBuildContext, GoBuildTestMode, GoCollectorPin, GoObservationError, GoPackageSelection,
    observe_go_native, observe_go_native_build,
};
use fortress_core::native_regions::{
    NativeRegionAvailability, NativeRegionError, NativeRegionInput, project_native_source_regions,
};
use fortress_core::source_architecture::{RegionCoverage, SemanticRegion};
use serde_json::{Value, json};

mod test_declarations {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use fortress_core::go_observation::observe_go_native_tests;

    const SOURCE: &[u8] = include_bytes!("../_data/go_test_request_v1.json");
    const NATIVE: &[u8] = include_bytes!("../_data/go_test_fixture_v1.json");
    const TEST_PIN: GoCollectorPin<'static> = GoCollectorPin {
        executable_sha256: "sha256:f2e010b50ea3f4c433f455be592a3b8cad34c8bb3027b6237c27ab2e748760a3",
        supervisor_context_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        go_toolchain: "go1.22.12",
    };

    fn test_fixture(name: &str) -> (Fixture, GoPackageSelection<'static>, GoBuildContext) {
        let fixture = Fixture::new(name);
        let request: Value = serde_json::from_slice(SOURCE).unwrap();
        for file in request["files"].as_array().unwrap() {
            let name = file["path"].as_str().unwrap();
            assert!(
                Path::new(name).extension() == Some(std::ffi::OsStr::new("go"))
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_'))
            );
            let bytes = STANDARD
                .decode(file["source_base64"].as_str().unwrap())
                .unwrap();
            let digest = fortress_core::portable::digest(&bytes);
            assert_eq!(file["sha256"], digest);
            fs::write(fixture.root.join(name), bytes).unwrap();
        }
        let selection = GoPackageSelection {
            directory: "",
            package_path: "fixture.local/native",
            go_version: "go1.22",
            target_os: "windows",
            target_arch: "amd64",
        };
        let context = serde_json::from_value(request["build_context"].clone()).unwrap();
        (fixture, selection, context)
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-018`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn exact_closed_test_declarations_preserve_scope_and_native_coordinates() {
        let (fixture, selection, context) = test_fixture("native-tests");
        let result =
            observe_go_native_tests(&fixture.root, selection, context, &TEST_PIN, |request| {
                assert_eq!(request, SOURCE);
                Ok(NATIVE.to_vec())
            })
            .unwrap();
        let doc = serde_json::to_value(result).unwrap();
        jsonschema::draft202012::validate(
            &super::registered_schema("go_test_schema_v1.json"),
            &doc,
        )
        .expect("canonical test declaration schema");
        assert_eq!(
            doc["response_sha256"],
            fortress_core::portable::digest(NATIVE)
        );
        let observation = &doc["observation"];
        assert_eq!(observation["status"], "DECLARATIONS_OBSERVED");
        let declarations = observation["test_declarations"].as_array().unwrap();
        assert_eq!(declarations.len(), 7);
        let renamed = declarations
            .iter()
            .find(|row| row["name"] == "TestRenamed")
            .unwrap();
        assert_eq!(renamed["parameter"]["qualifier"], "trial");
        assert_eq!(renamed["span"]["path"], "external_test.go");
        let unicode = declarations
            .iter()
            .find(|row| row["name"] == "TestÃƒÆ’Ã¢â‚¬Â°")
            .unwrap();
        assert_eq!(unicode["span"]["start_line"], 11);
        assert_eq!(unicode["span"]["start_byte_column"], 6);
        assert_eq!(
            unicode["span"]["end_byte"].as_u64().unwrap()
                - unicode["span"]["start_byte"].as_u64().unwrap(),
            6
        );
        assert!(
            declarations
                .iter()
                .any(|row| row["name"] == "TestMain" && row["kind"] == "TEST")
        );
        let files = observation["selection"].as_array().unwrap();
        let external = files
            .iter()
            .find(|row| row["path"] == "external_test.go")
            .unwrap();
        assert_eq!(external["package_role"], "EXTERNAL_TEST");
        let hidden = files
            .iter()
            .find(|row| row["path"] == "excluded_test.go")
            .unwrap();
        assert_eq!(hidden["disposition"], "EXCLUDED_BY_NAME_OR_CONSTRAINT");
        assert!(observation.get("execution").is_none() && observation.get("coverage").is_none());
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-019`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn forged_test_evidence_and_mismatched_occurrences_are_refused() {
        let (fixture, selection, context) = test_fixture("native-tests-wire");
        let schema: Value = super::registered_schema("go_test_schema_v1.json");
        let raw: Value = serde_json::from_slice(NATIVE).unwrap();
        for (path, replacement) in [
            ("/context_sha256", json!("wrong-build-context")),
            ("/selection/1/sha256", json!("altered-file")),
            ("/selection/1/package_role", json!("INTERNAL_TEST")),
            ("/test_declarations/0/parameter/qualifier", json!("spoofed")),
            (
                "/test_declarations/0/parameter/import_path_span/path",
                json!("prod.go"),
            ),
            ("/test_declarations/0/span/start_byte_column", json!(1)),
            ("/test_declarations/0/parameter", Value::Null),
            ("/test_declarations/0/kind", json!("TEST_MAIN_HOOK")),
            ("/status", json!("PASS")),
        ] {
            let result = observe_go_native_tests(
                &fixture.root,
                selection,
                context.clone(),
                &TEST_PIN,
                |_| {
                    let mut altered = raw.clone();
                    *altered.pointer_mut(path).unwrap() = replacement;
                    let mut wire = serde_json::to_vec(&altered).unwrap();
                    wire.push(b'\n');
                    Ok(wire)
                },
            );
            assert!(
                matches!(result, Err(GoObservationError::InvalidResponse)),
                "{path}"
            );
        }
        let injection =
            observe_go_native_tests(&fixture.root, selection, context.clone(), &TEST_PIN, |_| {
                let mut altered = raw.clone();
                altered["execution"] = json!({"status":"PASS"});
                let mut wire = serde_json::to_vec(&altered).unwrap();
                wire.push(b'\n');
                Ok(wire)
            });
        assert!(matches!(
            injection,
            Err(GoObservationError::InvalidResponse)
        ));
        let original =
            observe_go_native_tests(&fixture.root, selection, context, &TEST_PIN, |_| {
                Ok(NATIVE.to_vec())
            })
            .unwrap();
        let mut doc = serde_json::to_value(original).unwrap();
        doc["observation"]["test_declarations"][0]["parameter"] = Value::Null;
        assert!(jsonschema::draft202012::validate(&schema, &doc).is_err());
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-020`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn test_declaration_observation_refuses_production_scope_and_stale_source() {
        let (fixture, selection, context) = test_fixture("native-tests-stale");
        let mut production = context.clone();
        production.test_mode = GoBuildTestMode::ProductionOnly;
        let missing_scope =
            observe_go_native_tests(&fixture.root, selection, production, &TEST_PIN, |_| {
                panic!("missing explicit test declaration scope must prevent dispatch");
            });
        assert!(matches!(
            missing_scope,
            Err(GoObservationError::UnsupportedContext)
        ));
        let changed =
            observe_go_native_tests(&fixture.root, selection, context, &TEST_PIN, |request| {
                assert_eq!(request, SOURCE);
                fs::write(fixture.root.join("tagged_test.go"), "package sample\n").unwrap();
                Ok(NATIVE.to_vec())
            });
        assert!(matches!(changed, Err(GoObservationError::SourceChanged)));
    }
}

const NATIVE: &[u8] = include_bytes!("../_data/go_native_fixture_v1.json");
const API: &str =
    "// cafÃƒÆ’Ã‚Â©\r\npackage bounded\r\nfunc Run(input int) int { return target(input) }\r\n";
const TARGET: &str = "package bounded\nfunc target(input int) int { return input + 1 }\n";
const PIN: GoCollectorPin<'static> = GoCollectorPin {
    executable_sha256: "sha256:a8fa98c0d583a610b230c245357a50151fb8b5e5133fb62ca1b41c49b1e71419",
    supervisor_context_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000001",
    go_toolchain: "go1.22.12",
};

struct Fixture {
    parent: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let parent = std::env::temp_dir().canonicalize().expect("temporary root");
        let root = parent.join(format!("fortress-go-{}-{name}", std::process::id()));
        fs::create_dir(&root).expect("owned fixture");
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/api.go"), API).unwrap();
        fs::write(root.join("src/target.go"), TARGET).unwrap();
        Self { parent, root }
    }

    fn select() -> GoPackageSelection<'static> {
        GoPackageSelection {
            directory: "src",
            package_path: "fixture.local/bounded",
            go_version: "go1.22",
            target_os: "windows",
            target_arch: "amd64",
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let path = self.root.canonicalize().expect("owned fixture resolves");
        assert_eq!(path.parent(), Some(self.parent.as_path()));
        assert_eq!(path.file_name(), self.root.file_name());
        fs::remove_dir_all(path).expect("remove owned fixture");
    }
}

fn registered_schema(name: &str) -> Value {
    registered_schema_path(&format!("engine/program_semantics/_data/{name}"))
}

fn registered_schema_path(relative: &str) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = serde_json::from_slice(
        &fs::read(root.join("engine/standard_registry/_data/schema_manifest.json"))
            .expect("registered schemas are available in the test repository"),
    )
    .expect("registered schema manifest");
    assert!(
        manifest["schemas"]
            .as_array()
            .expect("registered paths")
            .iter()
            .any(|path| path == relative)
    );
    serde_json::from_slice(&fs::read(root.join(relative)).expect("registered Go schema"))
        .expect("Go schema JSON")
}

fn run_frozen(request: &[u8]) -> Vec<u8> {
    assert_eq!(
        fortress_core::portable::digest(request),
        "sha256:325bdc8d9cc501476361187d24e11808ddfb8811acf45a3b5b88ed0c63dc912b"
    );
    NATIVE.to_vec()
}

mod bodies {
    use super::*;
    use fortress_core::go_observation::observe_go_native_body;

    const SOURCE: &str = concat!(
        "// cafÃƒÆ’Ã‚Â©\r\npackage fixture\r\n",
        "func Keep(b bool) bool { if b {} ; return !b }\r\n",
        "func ÃƒÆ’Ã¢â‚¬Â°tude(b bool) bool { return b }\r\n",
        "func _(b bool) bool { return b }\r\n",
        "func Named(cafÃƒÆ’Ã‚Â© bool) bool { return cafÃƒÆ’Ã‚Â© }\r\n",
        "func Local(b bool) bool { cÃƒÆ’Ã‚Â´tÃƒÆ’Ã‚Â© := b; return cÃƒÆ’Ã‚Â´tÃƒÆ’Ã‚Â© }\r\n",
        "func Blank(_ bool) bool { return true }\r\n",
        "func Unnamed(bool) bool { return true }\r\n",
        "func Deep(b bool) bool { if b { if b { if b { if b { if b { if b { if b { if b { if b { if b { if b {} } } } } } } } } } } ; return b }\r\n",
        "func init() {}\r\nfunc init() {}\r\n",
    );
    const RAW: &[u8] = include_bytes!("../_data/go_body_fixture_v1.json");
    const DOMAIN_RAW: &[u8] = include_bytes!("../_data/go_domain_fixture_v1.json");
    const DOMAIN_SOURCE: &str = concat!(
        "package main\r\n\r\n",
        "func MinLiteral() int64 { return -9223372036854775808 }\r\n",
        "func MaxLiteral() int64 { return 9223372036854775807 }\r\n",
        "func Copy(value int64) int64 { return value }\r\n",
        "func Endpoints(flag bool) int64 { if flag { return -9223372036854775808 }; return 9223372036854775807 }\r\n",
        "func Constant() bool { return true }\r\n",
        "func Add(value int64) int64 { return value + 1 }\r\n",
    );
    const MIN_I64: &str = "-9223372036854775808";
    const MAX_I64: &str = "9223372036854775807";

    fn setup(case: &str) -> (Fixture, GoPackageSelection<'static>) {
        let fixture = Fixture::new(case);
        fs::write(fixture.root.join("fixture.go"), SOURCE).unwrap();
        (
            fixture,
            GoPackageSelection {
                directory: "",
                package_path: "fixture.local/firstorder",
                go_version: "go1.22",
                target_os: "linux",
                target_arch: "amd64",
            },
        )
    }

    fn replay(request: &[u8]) -> Vec<u8> {
        assert_eq!(
            fortress_core::portable::digest(request),
            "sha256:00e8f3be63df46a4161881be6704d07f8035a602e651b0f08890adbd56972cb8"
        );
        RAW.to_vec()
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-009`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn exact_scalar_body_retains_location_scope_and_limitations() {
        let (fixture, selection) = setup("body-exact");
        let evaluate = || {
            serde_json::to_value(
                observe_go_native_body(&fixture.root, selection, &PIN, |request| {
                    Ok(replay(request))
                })
                .expect("valid native receipt"),
            )
            .unwrap()
        };
        let result = evaluate();
        assert_eq!(result, evaluate());
        assert_eq!(result["status"], "OBSERVED_BODIES");
        assert_eq!(
            result["provenance"]["authority_sha256"],
            result["evaluation_key"]["authority_binding_digest"]
        );
        assert_eq!(
            result["response_sha256"],
            "sha256:cd4df8aab85fa3b12b63cd2fe861053b81adeb6558fa47b56baaa10b36a306bc"
        );
        let rows = result["functions"].as_array().unwrap();
        assert_eq!(rows.len(), 10);
        let first = &rows[0];
        assert_eq!(first["status"], "LOWERED");
        assert_eq!(first["symbol"]["name"], "Keep");
        assert_eq!(first["body"]["provenance"]["location"]["line"], 3);
        assert_eq!(first["body"]["provenance"]["location"]["column"], 6);
        assert_eq!(first["parameters"], json!([["b", "BOOL"]]));
        assert_eq!(first["body"]["statements"][0]["then_branch"], json!([]));
        assert_eq!(first["body"]["statements"][1]["value"]["operator"], "!");
        assert_eq!(rows[1]["status"], "UNAVAILABLE");
        assert_eq!(rows[1]["code"], "IDENTIFIER_OUTSIDE_ASCII_SCOPE");
        assert!(rows[1]["symbol"].is_null());
        assert!(rows[1].get("body").is_none());
        assert_eq!(rows[7]["code"], "GO_SCALAR_BODY_LIMIT");
        assert_eq!(rows[8]["symbol"]["name"], rows[9]["symbol"]["name"]);
        assert_ne!(rows[8]["span"], rows[9]["span"]);
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-021`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn flow_for_exact_go_occurrence_keeps_return_and_condition_separate() {
        use fortress_core::go_observation::observe_go_native_body_flow;
        let (fixture, selection) = setup("body-flow");
        let original = observe_go_native_body(&fixture.root, selection, &PIN, |request| {
            Ok(replay(request))
        })
        .unwrap();
        let original = serde_json::to_value(original).unwrap();
        let binding = original["functions"][0]["binding"].as_str().unwrap();
        let inspect = |binding| {
            observe_go_native_body_flow(&fixture.root, selection, &PIN, binding, |request| {
                Ok(replay(request))
            })
        };
        let (retained, observed) = inspect(binding).unwrap();
        assert_eq!(serde_json::to_value(retained).unwrap(), original);
        let observed = observed.unwrap();
        assert_eq!(observed.explicit_edge_count(), Some(1));
        let body = serde_json::to_value(&observed).unwrap();
        assert_eq!(body["occurrence_ref"], binding);
        assert_eq!(
            body["facts"]["explicit_data_edges"][0]["producer"]["name"],
            "b"
        );
        assert_eq!(
            body["facts"]["explicit_data_edges"][0]["consumer"]["role"],
            "return"
        );
        assert_eq!(
            body["facts"]["condition_inputs"][0]["sources"][0]["name"],
            "b"
        );
        assert_eq!(body["control_influence_coverage"], "UNSUPPORTED");
        assert_eq!(body["classification_authority"], "UNKNOWN");
        let stale = format!("native_body_occurrence:v1:sha256:{}", "0".repeat(64));
        assert!(inspect(&stale).unwrap().1.is_none());
        let malformed =
            observe_go_native_body_flow(&fixture.root, selection, &PIN, "invalid", |_| {
                panic!("invalid selection refuses before dispatch")
            });
        assert!(matches!(
            malformed,
            Err(GoObservationError::InvalidTrustedBinding)
        ));
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-010`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn malformed_or_unbound_scalar_body_receipts_are_refused() {
        let (fixture, selection) = setup("body-wire");
        for (path, replacement) in [
            ("/source_inventory/0/path", json!("other.go")),
            ("/request_sha256", json!("wrong-exchange")),
            ("/schema_version", json!(2)),
            ("/producer", json!("fortress.go-observations@0.1.1")),
            ("/status", json!("UNSUPPORTED")),
            ("/functions/0/symbol/span/start_byte_column", json!(7)),
            ("/functions/1/diagnostic/code", json!("PASS")),
        ] {
            let outcome = observe_go_native_body(&fixture.root, selection, &PIN, |request| {
                let mut receipt: Value = serde_json::from_slice(&replay(request)).unwrap();
                *receipt.pointer_mut(path).unwrap() = replacement;
                let mut output = serde_json::to_vec(&receipt).unwrap();
                output.push(b'\n');
                Ok(output)
            });
            assert!(matches!(outcome, Err(GoObservationError::InvalidResponse)));
        }
        let duplicate = observe_go_native_body(&fixture.root, selection, &PIN, |request| {
            let mut receipt: Value = serde_json::from_slice(&replay(request)).unwrap();
            let first = receipt["functions"][0].clone();
            receipt["functions"].as_array_mut().unwrap().push(first);
            let mut output = serde_json::to_vec(&receipt).unwrap();
            output.push(b'\n');
            Ok(output)
        });
        assert!(matches!(
            duplicate,
            Err(GoObservationError::InvalidResponse)
        ));
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-011`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn changed_original_source_prevents_scalar_body_publication() {
        let (fixture, selection) = setup("body-drift");
        let changed = observe_go_native_body(&fixture.root, selection, &PIN, |request| {
            let output = replay(request);
            fs::write(fixture.root.join("fixture.go"), SOURCE.replace("!b", "b")).unwrap();
            Ok(output)
        });
        assert!(matches!(changed, Err(GoObservationError::SourceChanged)));
    }

    fn domain_source(name: &str) -> (Fixture, GoPackageSelection<'static>) {
        let (fixture, selection) = setup(name);
        fs::write(fixture.root.join("fixture.go"), DOMAIN_SOURCE).unwrap();
        (fixture, selection)
    }

    fn derived_domains(fixture: &Fixture, selection: GoPackageSelection<'_>) -> Value {
        let result = observe_go_native_body(&fixture.root, selection, &PIN, |request| {
            assert_eq!(
                fortress_core::portable::digest(request),
                "sha256:3b9aed28fff9c31cbbff0175861c4b945f0627d5b0e1de97974e42d33741fa08"
            );
            Ok(DOMAIN_RAW.to_vec())
        })
        .expect("exact native domain fixture");
        serde_json::to_value(result).unwrap()
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-014`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn exact_go_domain_endpoints_survive_canonical_json() {
        let (fixture, selection) = domain_source("body-domains");
        let document = derived_domains(&fixture, selection);
        let schema: Value = super::registered_schema("go_body_schema_v1.json");
        jsonschema::draft202012::validate(&schema, &document).expect("fully registered result");
        let canonical = serde_json_canonicalizer::to_vec(&document).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&canonical).unwrap(),
            document
        );
        let functions = document["functions"].as_array().unwrap();
        let domains = document["value_domains"].as_array().unwrap();
        assert_eq!(functions.len(), 6);
        assert_eq!(domains.len(), functions.len());
        for (index, intervals) in [
            (0, json!([{"min": MIN_I64, "max": MIN_I64}])),
            (1, json!([{"min": MAX_I64, "max": MAX_I64}])),
            (2, json!([{"min": MIN_I64, "max": MAX_I64}])),
            (
                3,
                json!([{"min": MIN_I64, "max": MIN_I64}, {"min": MAX_I64, "max": MAX_I64}]),
            ),
        ] {
            assert_eq!(domains[index]["status"], "INFERRED");
            assert_eq!(domains[index]["function_index"], index);
            assert_eq!(domains[index]["binding"], functions[index]["binding"]);
            assert_eq!(domains[index]["domain"]["kind"], "integer");
            assert_eq!(
                domains[index]["domain"]["type_id"],
                "native_scalar:go:int64"
            );
            assert_eq!(domains[index]["domain"]["intervals"], intervals);
            assert_eq!(domains[index]["domain"]["excluded"], json!([]));
        }
        assert_eq!(domains[4]["binding"], functions[4]["binding"]);
        assert_eq!(
            domains[4]["domain"],
            json!({
                "kind": "boolean", "type_id": "native_scalar:bool", "values": [true]
            })
        );
        assert_eq!(
            functions[5]["code"],
            "RUNTIME_INTEGER_ARITHMETIC_UNAVAILABLE"
        );
        assert_eq!(
            domains[5],
            json!({
                "status": "UNAVAILABLE", "binding": null, "function_index": 5, "reason": "BODY_UNAVAILABLE"
            })
        );
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-015`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn scalar_result_schema_and_wire_fail_closed() {
        let (fixture, selection) = domain_source("body-domain-wire");
        let original = derived_domains(&fixture, selection);
        let schema: Value = super::registered_schema("go_body_schema_v1.json");
        for (path, replacement) in [
            ("/value_domains/2/domain/intervals/0/min", json!(-1)),
            (
                "/value_domains/2/domain/intervals/0/min",
                json!("-9223372036854775809"),
            ),
            (
                "/value_domains/2/domain/intervals/0/max",
                json!("9223372036854775808"),
            ),
            ("/value_domains/2/domain/intervals/0/max", json!("01")),
            ("/value_domains/2/domain/intervals/0/max", json!("-0")),
            ("/value_domains/2/domain/intervals/0/max", json!("5\n")),
            ("/value_domains/2/domain/excluded", json!([2])),
            ("/value_domains/5/status", json!("INFERRED")),
            (
                "/functions/0/body/statements/0/value",
                json!({"kind":"call"}),
            ),
            ("/status", json!("UNSUPPORTED")),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(path).unwrap() = replacement;
            assert!(
                jsonschema::draft202012::validate(&schema, &invalid).is_err(),
                "{path}"
            );
        }
        let injected = observe_go_native_body(&fixture.root, selection, &PIN, |_| {
            let mut forged: Value = serde_json::from_slice(DOMAIN_RAW).unwrap();
            forged["value_domains"] = original["value_domains"].clone();
            let mut output = serde_json::to_vec(&forged).unwrap();
            output.push(b'\n');
            Ok(output)
        });
        assert!(matches!(injected, Err(GoObservationError::InvalidResponse)));
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-012`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
#[test]
fn go_native_regions_reuse_exact_declarations_without_ownership_or_absence() {
    let fixture = Fixture::new("go-regions");
    let receipt = observe_go_native(&fixture.root, Fixture::select(), &PIN, |request| {
        Ok(run_frozen(request))
    })
    .unwrap();
    let report = project_native_source_regions(
        &fixture.root,
        "src/api.go",
        NativeRegionInput::Go(&receipt),
        &[],
    )
    .unwrap();
    assert_eq!(report.availability(), NativeRegionAvailability::Observed);
    for region in report.regions() {
        let expected = match region.region() {
            SemanticRegion::Declarations | SemanticRegion::Implementation => {
                RegionCoverage::Observed
            }
            _ => RegionCoverage::Unsupported,
        };
        assert_eq!(region.coverage(), expected, "{:?}", region.region());
    }
    let document = serde_json::to_value(&report).unwrap();
    let schema = fortress_core::source_architecture::native_regions::native_source_region_schema();
    jsonschema::draft202012::validate(&serde_json::from_str(schema).unwrap(), &document)
        .expect("source-bound Go region view satisfies the registered schema");
    let original = serde_json_canonicalizer::to_vec(&receipt).unwrap();
    assert_eq!(
        document["native_receipt_ref"],
        fortress_core::portable::digest(&original)
    );
    assert_eq!(
        document["source_ref"],
        fortress_core::portable::digest(API.as_bytes())
    );
    assert_eq!(document["regions"][2]["evidence"][0]["start_line"], 3);
    assert_eq!(
        document["regions"][2]["evidence"][0]["source_reference"],
        format!(
            "{}#/observation/declarations/0",
            document["native_receipt_ref"].as_str().unwrap(),
        )
    );
    assert!(document["layout"].is_null());
    assert!(document.get("ownership").is_none());
    let repeated = project_native_source_regions(
        &fixture.root,
        "src/api.go",
        NativeRegionInput::Go(&receipt),
        &[],
    )
    .unwrap();
    assert_eq!(
        serde_json_canonicalizer::to_vec(&report).unwrap(),
        serde_json_canonicalizer::to_vec(&repeated).unwrap()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-013`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
#[test]
fn go_native_regions_refuse_stale_ancillary_source_and_missing_subject() {
    let fixture = Fixture::new("go-region-stale");
    fs::write(fixture.root.join("notes.txt"), "original").unwrap();
    let receipt = observe_go_native(&fixture.root, Fixture::select(), &PIN, |request| {
        Ok(run_frozen(request))
    })
    .unwrap();
    let project = |path| {
        project_native_source_regions(&fixture.root, path, NativeRegionInput::Go(&receipt), &[])
    };
    assert!(matches!(
        project("notes.txt"),
        Err(NativeRegionError::SubjectMismatch)
    ));
    assert!(matches!(
        project("../api.go"),
        Err(NativeRegionError::InvalidPath)
    ));
    fs::write(
        fixture.root.join("notes.txt"),
        "changed outside the closed package",
    )
    .unwrap();
    assert!(matches!(
        project("src/api.go"),
        Err(NativeRegionError::StaleReceipt)
    ));
    fs::remove_file(fixture.root.join("src/api.go")).unwrap();
    assert!(matches!(
        project("src/api.go"),
        Err(NativeRegionError::MissingSource)
    ));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
#[test]
fn exact_native_observation_retains_authority_and_source_occurrence() {
    let fixture = Fixture::new("exact");
    let result = observe_go_native(&fixture.root, Fixture::select(), &PIN, |request| {
        Ok(run_frozen(request))
    })
    .expect("exact native response");
    let json = serde_json::to_value(result).unwrap();
    jsonschema::draft202012::validate(&registered_schema("go_observation_schema_v1.json"), &json)
        .expect("go projection matches registered wire");
    assert_eq!(json["observation"]["status"], "OBSERVED");
    assert_eq!(json["provenance"]["actual"], true);
    assert!(
        json["provenance"]["authority_sha256"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    let call = &json["observation"]["calls"][0];
    assert_eq!(call["resolution"], "DIRECT_FUNCTION");
    assert_eq!(call["span"]["start_byte"], 60);
    assert_eq!(call["span"]["start_byte_column"], 34);
    assert_eq!(call["declaration"]["path"], "src/target.go");
    assert_eq!(call["declaration"]["start_byte"], 21);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
#[test]
fn stale_source_and_unselected_go_context_fail_closed() {
    let fixture = Fixture::new("drift");
    let stale = observe_go_native(&fixture.root, Fixture::select(), &PIN, |request| {
        let original = run_frozen(request);
        fs::write(
            fixture.root.join("src/target.go"),
            TARGET.replace("+ 1", "+ 2"),
        )
        .unwrap();
        Ok(original)
    });
    assert!(matches!(stale, Err(GoObservationError::SourceChanged)));
    let uppercase = fixture.root.join("src/mixed.GO");
    fs::write(&uppercase, "package bounded\n").unwrap();
    let unsupported = observe_go_native(&fixture.root, Fixture::select(), &PIN, |_| {
        panic!("uppercase source extension must prevent closed source dispatch")
    });
    assert!(matches!(
        unsupported,
        Err(GoObservationError::UnsupportedContext)
    ));
    fs::remove_file(uppercase).unwrap();
    fs::write(
        fixture.root.join("go.mod"),
        "module fixture.local\n\ngo 1.22\n",
    )
    .unwrap();
    let unsupported = observe_go_native(&fixture.root, Fixture::select(), &PIN, |_| {
        panic!("ancestor Go module authority must prevent closed source dispatch")
    });
    assert!(matches!(
        unsupported,
        Err(GoObservationError::UnsupportedContext)
    ));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
#[test]
fn mismatched_native_spans_and_observation_status_are_rejected() {
    let fixture = Fixture::new("wire");
    for (pointer, value) in [
        ("/calls/0/span/start_byte_column", json!(35)),
        ("/calls/0/declaration/start_byte", json!(22)),
        ("/status", json!("PASS")),
        ("/status", json!("UNSUPPORTED")),
    ] {
        let rejected = observe_go_native(&fixture.root, Fixture::select(), &PIN, |request| {
            let mut native: Value = serde_json::from_slice(&run_frozen(request)).unwrap();
            *native.pointer_mut(pointer).unwrap() = value;
            let mut bytes = serde_json::to_vec(&native).unwrap();
            bytes.push(b'\n');
            Ok(bytes)
        });
        assert!(matches!(rejected, Err(GoObservationError::InvalidResponse)));
    }
}

const BUILD_RESPONSE: &[u8] = include_bytes!("../_data/go_build_fixture_v2.json");
const BUILD_PIN: GoCollectorPin<'static> = GoCollectorPin {
    executable_sha256: "sha256:a9e2ead7baa899dea5fa399c168d6cd17fd9e431bc765462f056509a91788cec",
    supervisor_context_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000002",
    go_toolchain: "go1.22.12",
};

fn build_fixture(name: &str) -> Fixture {
    let fixture = Fixture::new(name);
    fs::remove_file(fixture.root.join("src/target.go")).unwrap();
    for (file, source) in [
        (
            "api.go",
            "package fixture\nfunc Run(n int) int { return target(n) }\n",
        ),
        ("api_linux_test.go", "package fixture\nfunc Tested() {}\n"),
        (
            "core_linux.go",
            "package fixture\nfunc target(n int) int { return n + 1 }\n",
        ),
        ("core_windows.go", "package fixture\nfunc WINDOWS(\n"),
    ] {
        fs::write(fixture.root.join("src").join(file), source).unwrap();
    }
    fixture
}

fn select_build() -> (GoPackageSelection<'static>, GoBuildContext) {
    (
        GoPackageSelection {
            directory: "src",
            package_path: "fixture.local/selected",
            go_version: "go1.22",
            target_os: "linux",
            target_arch: "amd64",
        },
        GoBuildContext {
            compiler: "gc".into(),
            release_minor: 22,
            cgo_enabled: false,
            test_mode: GoBuildTestMode::ProductionOnly,
            custom_tags: Vec::new(),
            tool_tags: vec!["amd64.v1".into()],
        },
    )
}

fn replay_build(request: &[u8]) -> Vec<u8> {
    assert_eq!(
        fortress_core::portable::digest(request),
        "sha256:843a1488e427d47ec0664703d1cf749a62758ac7749b1d960b7e58e14c6eb0e5"
    );
    BUILD_RESPONSE.to_vec()
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
#[test]
fn build_selection_binds_exact_selected_and_excluded_go_source() {
    let fixture = build_fixture("build-selection");
    let (selection, context) = select_build();
    let observation =
        observe_go_native_build(&fixture.root, selection, context, &BUILD_PIN, |request| {
            Ok(replay_build(request))
        })
        .expect("native build selection with exact frozen result");
    let observed = serde_json::to_value(observation).unwrap();
    jsonschema::draft202012::validate(
        &registered_schema("go_observation_schema_v2.json"),
        &observed,
    )
    .expect("Go build selection matches its registered output schema");
    assert_eq!(observed["schema_version"], 2);
    assert_eq!(observed["provenance"]["actual"], true);
    assert_eq!(observed["observation"]["status"], "OBSERVED");
    assert_eq!(
        observed["selection"][1]["disposition"],
        "PRODUCTION_TEST_EXCLUDED"
    );
    assert_eq!(
        observed["selection"][3]["disposition"],
        "EXCLUDED_BY_NAME_OR_CONSTRAINT"
    );
    assert_eq!(
        observed["observation"]["calls"][0]["declaration"]["path"],
        "src/core_linux.go"
    );
    let frozen: Value = serde_json::from_slice(BUILD_RESPONSE).unwrap();
    assert_eq!(observed["selection"], frozen["selection"]);
    assert_eq!(observed["build_context"], frozen["build_context"]);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
#[test]
fn go_build_rejects_context_and_inventory_overclaims_and_excluded_source_drift() {
    let fixture = build_fixture("build-refusals");
    for (member, replacement) in [
        ("/build_context/release_minor", json!(21)),
        (
            "/selection/0/sha256",
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
        ),
        ("/selection/1/native_match", json!(false)),
        (
            "/selection/2/disposition",
            json!("EXCLUDED_BY_NAME_OR_CONSTRAINT"),
        ),
        ("/calls/0/span/path", json!("src/core_windows.go")),
        ("/selection/3/path", json!("src/unavailable.go")),
    ] {
        let (selection, context) = select_build();
        let result =
            observe_go_native_build(&fixture.root, selection, context, &BUILD_PIN, |request| {
                let mut value: Value = serde_json::from_slice(&replay_build(request)).unwrap();
                *value.pointer_mut(member).unwrap() = replacement;
                let mut forged = serde_json::to_vec(&value).unwrap();
                forged.push(b'\n');
                Ok(forged)
            });
        assert!(matches!(result, Err(GoObservationError::InvalidResponse)));
    }

    let (selection, mut context) = select_build();
    context.cgo_enabled = true;
    let blocked = observe_go_native_build(&fixture.root, selection, context, &BUILD_PIN, |_| {
        panic!("unsupported cgo must not dispatch a native request")
    });
    assert!(matches!(
        blocked,
        Err(GoObservationError::UnsupportedContext)
    ));

    let (selection, context) = select_build();
    let changed =
        observe_go_native_build(&fixture.root, selection, context, &BUILD_PIN, |request| {
            let output = replay_build(request);
            fs::write(
                fixture.root.join("src/core_windows.go"),
                "package fixture\n",
            )
            .unwrap();
            Ok(output)
        });
    assert!(matches!(changed, Err(GoObservationError::SourceChanged)));
}

// Frozen native module controls reuse the independent Go reference source and replies.
mod module_controls {
    use super::*;
    use fortress_core::go_observation::{
        GoModuleSelection, observe_go_module_dependencies, observe_go_native_module,
    };

    const MOD: &[u8] = b"module example.test/fortresslocal\n\ngo 1.22\n";
    const APP: &[u8] = b"package app\nimport q \"example.test/fortresslocal/base\"\nfunc Use() int { return q.Number() }\n";
    const LIBRARY: &[u8] = b"package shared\n\ntype Token int\nfunc Number() int { return 1 }\n";
    const MISSING: &[u8] = b"package app\nimport _ \"example.test/fortresslocal/wrong\"\n";
    const OBSERVED: &[u8] = include_bytes!("../_data/go_observed_fixture_v3.json");
    const UNAVAILABLE: &[u8] = include_bytes!("../_data/go_missing_fixture_v3.json");

    fn selection() -> GoModuleSelection<'static> {
        GoModuleSelection {
            directory: "",
            module_path: "example.test/fortresslocal",
            entry_path: "example.test/fortresslocal/app",
            target_os: "linux",
            target_arch: "amd64",
            comparison: None,
        }
    }

    fn context() -> GoBuildContext {
        GoBuildContext {
            compiler: "gc".into(),
            release_minor: 22,
            cgo_enabled: false,
            test_mode: GoBuildTestMode::RequireSeparateTestContext,
            custom_tags: vec![],
            tool_tags: vec!["amd64.v1".into()],
        }
    }

    fn project(name: &str) -> Fixture {
        let fixture = Fixture::new(name);
        fs::remove_file(fixture.root.join("src/api.go")).unwrap();
        fs::remove_file(fixture.root.join("src/target.go")).unwrap();
        for (directory, filename, bytes) in [("app", "app.go", APP), ("base", "base.go", LIBRARY)] {
            fs::create_dir(fixture.root.join(directory)).unwrap();
            fs::write(fixture.root.join(directory).join(filename), bytes).unwrap();
        }
        fs::write(fixture.root.join("go.mod"), MOD).unwrap();
        fixture
    }

    fn frozen(req: &[u8], response: &[u8]) -> Vec<u8> {
        assert_eq!(
            fortress_core::portable::digest(req),
            serde_json::from_slice::<Value>(response).unwrap()["request_sha256"]
                .as_str()
                .unwrap(),
        );
        response.to_vec()
    }

    fn authored_module(id: &str, project: bool) -> String {
        let ecosystem = if project {
            r#"  "ecosystem": {
    "repository_grammar": 1,
    "standard": {
      "id": "STD-FORTRESS-ENGINEERING",
      "edition": "1.0.0-draft.2"
    }
  },
"#
        } else {
            ""
        };
        r#"{
  "$schema": "urn:fortress:schema:v2:module-contract",
  "schema_version": 2,
  "id": "MODULE_ID",
  "display_name": "MODULE_ID",
ROOT_ECOSYSTEM  "provides": [],
  "requires": [],
  "relationships": [],
  "constraints": [],
  "guarantees": [],
  "features": [],
  "behavior": []
}
"#
        .replace("MODULE_ID", id)
        .replace("ROOT_ECOSYSTEM", ecosystem)
    }

    fn declare_owners(fixture: &Fixture) {
        let owner = "PF-GO-INSPECTION";
        fs::write(
            fixture.root.join("contract.json"),
            authored_module(owner, true),
        )
        .unwrap();
        fs::create_dir(fixture.root.join("__fortress")).unwrap();
        let mut modules = Vec::new();
        for (directory, id) in [("app", "AF-GO-APP-0001"), ("base", "AF-GO-BASE-0001")] {
            let path = format!("_data/logical_modules/{directory}/contract.json");
            let file = fixture.root.join(&path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, authored_module(id, false)).unwrap();
            modules.push(json!({
                "module": id,
                "contract": path,
                "parent": owner,
                "bindings": [{"path":directory,"kind":"directory"}],
            }));
        }
        fs::write(
            fixture.root.join("__fortress/.fsconfig"),
            serde_json::to_vec(&json!({
                "$schema":"urn:fortress:schema:v3:project-configuration",
                "schema_version":3,
                "observation_exclusions":[],
                "logical_modules":modules,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn dependency_validator() -> jsonschema::Validator {
        let schema = super::registered_schema_path(
            "engine/snapshot_governance/_data/go_dependency_schema_v1.json",
        );
        let resources = [
            super::registered_schema_path(
                "engine/implementation_observation/_data/native_dependency_schema_v1.json",
            ),
            registered_schema("go_observation_schema_v3.json"),
        ]
        .into_iter()
        .map(|value| {
            (
                value["$id"].as_str().unwrap().to_owned(),
                jsonschema::Resource::from_contents(value).unwrap(),
            )
        });
        jsonschema::draft202012::options()
            .with_resources(resources)
            .build(&schema)
            .unwrap()
    }

    fn inspect(fixture: &Fixture, raw: &[u8]) -> Vec<u8> {
        observe_go_module_dependencies(
            &fixture.root,
            selection(),
            context(),
            &BUILD_PIN,
            |request| Ok(frozen(request, raw)),
        )
        .unwrap()
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-016`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn go_dependencies_attach_exact_authored_direction_without_changed_worker_input() {
        let fixture = project("go-dependency-authority");
        declare_owners(&fixture);
        let bytes = inspect(&fixture, OBSERVED);
        assert_eq!(inspect(&fixture, OBSERVED), bytes);
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        let validator = dependency_validator();
        validator.validate(&report).unwrap();
        let mut falsely_decisive = report.clone();
        falsely_decisive["scope"] = json!("CERTIFIED");
        assert!(!validator.is_valid(&falsely_decisive));
        assert_eq!(report["scope"], "SCOPED_SOURCE_OBSERVATION");
        assert_eq!(report["ownership_diagnostics"], json!([]));
        let dependencies = &report["dependencies"];
        assert_eq!(dependencies["language"], "go");
        let sites = dependencies["sites"].as_array().unwrap();
        assert_eq!(sites.len(), 1);
        let site = &sites[0];
        assert_eq!(site["occurrence"]["file"]["path"], "app/app.go");
        assert_eq!(
            site["occurrence"]["file"]["sha256"],
            fortress_core::portable::digest(APP)
        );
        assert_eq!(site["occurrence"]["start_byte"], 21);
        assert_eq!(site["occurrence"]["end_byte"], 54);
        assert_eq!(site["target"]["files"][0]["path"], "base/base.go");
        assert_eq!(site["source_ownership"]["module"], "AF-GO-APP-0001");
        assert_eq!(site["target"]["ownership"]["module"], "AF-GO-BASE-0001");
        let edges = &dependencies["observation"]["module_dependencies"];
        assert_eq!(
            edges,
            &json!([{
                "source_module":"AF-GO-APP-0001",
                "target_module":"AF-GO-BASE-0001",
                "evidence":[{
                    "source_path":"app/app.go",
                    "source_module":"AF-GO-APP-0001",
                    "reference":"example.test/fortresslocal/base",
                    "location":{"line":2,"column":10},
                    "resolved_target":"AF-GO-BASE-0001"
                }]
            }])
        );
        assert_eq!(fs::read(fixture.root.join("app/app.go")).unwrap(), APP);
        assert_eq!(
            fs::read(fixture.root.join("base/base.go")).unwrap(),
            LIBRARY
        );
        let native = observe_go_native_module(
            &fixture.root,
            selection(),
            context(),
            &BUILD_PIN,
            |request| Ok(frozen(request, OBSERVED)),
        )
        .unwrap();
        assert_eq!(
            report["native_receipt"],
            serde_json::to_value(native).unwrap()
        );
        fs::write(
            fixture.root.join("_data/logical_modules/app/other.txt"),
            b"an unrelated data input",
        )
        .unwrap();
        let unsupported = observe_go_module_dependencies(
            &fixture.root,
            selection(),
            context(),
            &BUILD_PIN,
            |_| panic!("unrecognized input cannot start the worker"),
        );
        assert!(matches!(
            unsupported,
            Err(GoObservationError::UnsupportedContext)
        ));
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-017`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn go_dependencies_retain_unowned_source_refusal_and_original_source_drift() {
        let fixture = project("go-dependency-limits");
        let report: Value = serde_json::from_slice(&inspect(&fixture, OBSERVED)).unwrap();
        assert_eq!(report["dependencies"]["sites"].as_array().unwrap().len(), 1);
        assert_eq!(
            report["dependencies"]["observation"]["module_dependencies"],
            json!([])
        );

        let failure = observe_go_module_dependencies(
            &fixture.root,
            selection(),
            context(),
            &BUILD_PIN,
            |request| {
                fs::write(fixture.root.join("README.md"), "changed during observation").unwrap();
                Ok(frozen(request, OBSERVED))
            },
        );
        assert!(matches!(failure, Err(GoObservationError::SourceChanged)));

        fs::write(fixture.root.join("app/app.go"), MISSING).unwrap();
        let refused: Value = serde_json::from_slice(&inspect(&fixture, UNAVAILABLE)).unwrap();
        let validator = dependency_validator();
        validator.validate(&refused).unwrap();
        assert!(refused["dependencies"].is_null());
        let mut missing_worker_output = refused.clone();
        missing_worker_output["dependencies"] = report["dependencies"].clone();
        assert!(!validator.is_valid(&missing_worker_output));
        assert_eq!(
            refused["native_receipt"]["observation"]["diagnostic"]["code"],
            "MISSING_LOCAL_PACKAGE"
        );
    }
    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-006`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn native_module_exact_import_and_unavailable_package() {
        let fixture = project("module-source");
        for (source, response, expected) in [
            (APP, OBSERVED, "OBSERVED"),
            (MISSING, UNAVAILABLE, "UNSUPPORTED"),
        ] {
            fs::write(fixture.root.join("app/app.go"), source).unwrap();
            let result = observe_go_native_module(
                &fixture.root,
                selection(),
                context(),
                &BUILD_PIN,
                |request| Ok(frozen(request, response)),
            )
            .unwrap();
            let rendered = serde_json::to_value(result).unwrap();
            jsonschema::draft202012::validate(
                &super::registered_schema("go_observation_schema_v3.json"),
                &rendered,
            )
            .unwrap();
            assert_eq!(rendered["provenance"]["actual"], true);
            let observation = &rendered["observation"];
            assert_eq!(observation["status"], expected);
            if expected == "OBSERVED" {
                let app = &observation["observed_packages"][0];
                assert_eq!(
                    app["imports"][0]["target_package"],
                    "example.test/fortresslocal/base"
                );
                assert_eq!(app["imports"][0]["alias"], "q");
                assert_eq!(app["calls"][0]["declaration"]["path"], "base/base.go");
                assert_eq!(
                    app["calls"][0]["declaration_package"],
                    "example.test/fortresslocal/base"
                );
                assert_eq!(
                    observation["observed_packages"][1]["package_name"],
                    "shared"
                );
            } else {
                assert_eq!(observation["diagnostic"]["code"], "MISSING_LOCAL_PACKAGE");
                assert_eq!(observation["observed_packages"], json!([]));
            }
        }
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-007`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn native_module_refuses_wrong_scope_and_changed_source() {
        let fixture = project("module-drift");
        let drift = observe_go_native_module(
            &fixture.root,
            selection(),
            context(),
            &BUILD_PIN,
            |request| {
                fs::write(fixture.root.join("base/base.go"), b"package shared\n").unwrap();
                Ok(frozen(request, OBSERVED))
            },
        );
        assert!(matches!(drift, Err(GoObservationError::SourceChanged)));
        fs::write(fixture.root.join("base/base.go"), LIBRARY).unwrap();

        for (path, content) in [
            ("go.work", b"go 1.22\n".as_slice()),
            ("base/go.mod", MOD),
            (
                "base/native.syso",
                b"not an ordinaryGo build input".as_slice(),
            ),
        ] {
            let path = fixture.root.join(path);
            fs::write(&path, content).unwrap();
            let refusal =
                observe_go_native_module(&fixture.root, selection(), context(), &BUILD_PIN, |_| {
                    panic!("incomplete ordinary module cannot start the worker")
                });
            assert!(matches!(
                refusal,
                Err(GoObservationError::UnsupportedContext)
            ));
            fs::remove_file(path).unwrap();
        }
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-008`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn native_module_refuses_malformed_stale_and_partial_replies() {
        let fixture = project("module-wire");
        for (pointer, replacement) in [
            ("/status", json!("UNKNOWN")),
            ("/context_sha256", json!("bogus")),
            ("/module/definition/sha256", json!("bogus")),
            (
                "/observed_packages/0/imports/0/target_package",
                json!("example.test/fortresslocal/app"),
            ),
            ("/observed_packages/0/imports/0/span/start_line", json!(1)),
            (
                "/observed_packages/0/calls/0/declaration_package",
                json!("example.test/fortresslocal/app"),
            ),
            ("/observed_packages/0/imports", json!([])),
            ("/selection", json!([])),
        ] {
            let result = observe_go_native_module(
                &fixture.root,
                selection(),
                context(),
                &BUILD_PIN,
                |request| {
                    let mut body: Value =
                        serde_json::from_slice(&frozen(request, OBSERVED)).unwrap();
                    *body.pointer_mut(pointer).unwrap() = replacement;
                    let mut bytes = serde_json::to_vec(&body).unwrap();
                    bytes.push(b'\n');
                    Ok(bytes)
                },
            );
            assert!(
                matches!(result, Err(GoObservationError::InvalidResponse)),
                "{pointer}"
            );
        }
    }
}

mod callable_links {
    use super::*;
    use fortress_core::go_observation::{
        GoCallableHost, GoCallableSelection, GoModuleSelection, observe_go_linked_callable,
    };
    use fortress_core::program_semantics::native_callable::{
        NativeCallableLimitation, NativeCallableOutcome,
    };

    const FROZEN: &[u8] = include_bytes!("../_data/go_callable_fixture_v1.json");

    fn selection(function: &str) -> GoCallableSelection<'_> {
        GoCallableSelection {
            module: GoModuleSelection {
                directory: "subject",
                module_path: "example.test/fortresscallable",
                entry_path: "example.test/fortresscallable/app",
                target_os: "linux",
                target_arch: "amd64",
                comparison: None,
            },
            function,
        }
    }

    fn context() -> GoBuildContext {
        GoBuildContext {
            compiler: "gc".into(),
            release_minor: 22,
            cgo_enabled: false,
            test_mode: GoBuildTestMode::RequireSeparateTestContext,
            custom_tags: vec![],
            tool_tags: vec!["amd64.v1".into()],
        }
    }

    fn pin<'a>(receipt: &'a Value, name: &str) -> GoCollectorPin<'a> {
        GoCollectorPin {
            executable_sha256: receipt["worker_refs"][name].as_str().unwrap(),
            supervisor_context_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000001",
            go_toolchain: "go1.22.12",
        }
    }

    fn stage(fixture: &Fixture, record: &Value, row: &Value) {
        let path = fixture.root.join(row["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, row["source"].as_str().unwrap()).unwrap();
        fs::write(
            fixture.root.join("subject/go.mod"),
            record["definition"].as_str().unwrap(),
        )
        .unwrap();
    }

    fn reply(row: &Value, request: &[u8], role: &str) -> Vec<u8> {
        assert_eq!(
            row[format!("{role}_request_ref")],
            fortress_core::portable::digest(request),
            "exact v3 and scalar worker requests",
        );
        row[format!("{role}_reply")]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-022`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn go_callable_links_retained_native_module_and_body_from_the_same_selected_input() {
        let record: Value = serde_json::from_slice(FROZEN).unwrap();
        let fixture = Fixture::new("callable-link");
        let module = pin(&record, "module");
        let body = pin(&record, "body");
        let host = GoCallableHost {
            module: &module,
            body: &body,
        };
        let mut links = Vec::new();
        for row in record["cases"].as_array().unwrap() {
            stage(&fixture, &record, row);
            let result = observe_go_linked_callable(
                &fixture.root,
                selection("Keep"),
                context(),
                host,
                |request| Ok(reply(row, request, "module")),
                |request| Ok(reply(row, request, "body")),
            )
            .unwrap();
            let NativeCallableOutcome::Linked(linked) = result else {
                panic!("correlated proven compiler occurrence did not link");
            };
            assert_eq!(linked.function(), "Keep");
            assert_eq!(linked.namespace(), record["package"].as_str().unwrap());
            assert_eq!(linked.source_path(), row["path"].as_str().unwrap());
            assert_eq!(
                linked.source_ref(),
                fortress_core::portable::digest(row["source"].as_str().unwrap().as_bytes())
            );
            assert_eq!(linked.body().parameters().len(), 1);
            assert!(linked.declared_source_owner().is_none());
            assert!(linked.slot_ref().starts_with("go_callable_slot:v1:sha256:"));
            assert_ne!(linked.link_ref(), linked.body().binding());
            links.push(linked);
            fs::remove_file(fixture.root.join(row["path"].as_str().unwrap())).unwrap();
        }
        assert_eq!(links[0].slot_ref(), links[1].slot_ref());
        assert_ne!(links[0].link_ref(), links[1].link_ref());
        assert_ne!(links[0].body().binding(), links[1].body().binding());
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-023`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn go_callable_rejects_other_exchanges_and_reobserves_original_source() {
        let record: Value = serde_json::from_slice(FROZEN).unwrap();
        let fixture = Fixture::new("callable-stale");
        let module = pin(&record, "module");
        let body = pin(&record, "body");
        let host = GoCallableHost {
            module: &module,
            body: &body,
        };
        let first = &record["cases"][0];
        stage(&fixture, &record, first);

        let missing = observe_go_linked_callable(
            &fixture.root,
            selection("Other"),
            context(),
            host,
            |request| Ok(reply(first, request, "module")),
            |_| panic!("an unavailable subject must not start the body worker"),
        )
        .unwrap();
        assert!(matches!(
            missing,
            NativeCallableOutcome::Unavailable(NativeCallableLimitation::MissingSubject)
        ));

        let stale = observe_go_linked_callable(
            &fixture.root,
            selection("Keep"),
            context(),
            host,
            |request| Ok(reply(first, request, "module")),
            |_| {
                Ok(record["cases"][1]["body_reply"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .to_vec())
            },
        );
        assert!(matches!(stale, Err(GoObservationError::InvalidResponse)));

        let drift = observe_go_linked_callable(
            &fixture.root,
            selection("Keep"),
            context(),
            host,
            |request| Ok(reply(first, request, "module")),
            |request| {
                fs::write(
                    fixture.root.join(first["path"].as_str().unwrap()),
                    b"package app\n",
                )
                .unwrap();
                Ok(reply(first, request, "body"))
            },
        );
        assert!(matches!(drift, Err(GoObservationError::SourceChanged)));
    }

    fn configure_authored_go_owner(fixture: &Fixture, source_path: &str) {
        use fortress_core::contract_coherency::ModuleContract;

        let write_contract = |path: &str, id: &str, root: bool| {
            let mut document = json!({
                "$schema":"urn:fortress:schema:v2:module-contract",
                "schema_version":2,"id":id,"display_name":id,
                "provides":[],"requires":[],"relationships":[],"constraints":[],
                "guarantees":[],"features":[],"behavior":[],
            });
            if root {
                document["ecosystem"] = json!({
                    "repository_grammar":1,
                    "standard":{"id":"STD-FORTRESS-ENGINEERING","edition":"1.0.0-draft.2"},
                });
            }
            let typed: ModuleContract = serde_json::from_value(document).unwrap();
            let absolute = fixture.root.join(path);
            fs::create_dir_all(absolute.parent().unwrap()).unwrap();
            fs::write(absolute, typed.to_canonical_json().unwrap()).unwrap();
        };
        write_contract("contract.json", "PF-GO-CALLABLE", true);
        write_contract(
            "_data/logical_modules/app/contract.json",
            "AF-GO-CALLABLE-0001",
            false,
        );
        fs::create_dir_all(fixture.root.join("__fortress")).unwrap();
        fs::create_dir_all(fixture.root.join("authoring/app/data")).unwrap();
        fs::write(
            fixture.root.join("__fortress/.fsconfig"),
            serde_json::to_vec(&json!({
                "$schema":"urn:fortress:schema:v3:project-configuration",
                "schema_version":3,"observation_exclusions":[],
                "logical_modules":[{"module":"AF-GO-CALLABLE-0001","parent":"PF-GO-CALLABLE",
                    "contract":"_data/logical_modules/app/contract.json",
                    "bindings":[{"kind":"directory","path":"authoring/app"},
                                {"kind":"file","path":source_path}]}],
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-024`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn go_authored_native_return_compares_exact_original_bool_requirement() {
        use fortress_core::go_observation::observe_go_authored_native_return;
        use fortress_core::native_return_observation::AuthoredNativeReturnComparison;
        use fortress_core::portable::digest;
        use fortress_core::semantic_analysis::NativeBooleanReturn;

        const CONTRACT_PATH: &str = "authoring/app/data/native_function_contracts.json";
        const SLOT: &str = "go_callable_slot:v1:sha256:f13fd3e3d4a7a753633dd369bd15b7338bc48823fbba46c47718015230fc5540";

        let fixture = Fixture::new("go-authored-native-bool");
        let record: Value =
            serde_json::from_slice(include_bytes!("../_data/go_authored_return_v1.json")).unwrap();
        let case = &record["cases"][0];
        let source_path = case["path"].as_str().unwrap();
        stage(&fixture, &record, case);
        configure_authored_go_owner(&fixture, source_path);
        let module = pin(&record, "module");
        let body = pin(&record, "body");
        let host = GoCallableHost {
            module: &module,
            body: &body,
        };
        let mut manifests = Vec::new();
        for (required, expected) in [
            (true, NativeBooleanReturn::MatchesRequiredValue),
            (false, NativeBooleanReturn::ExcludesRequiredValue),
        ] {
            let mut authored = serde_json_canonicalizer::to_vec(&json!({
                "$schema":"urn:fortress:schema:v1:native-function-contracts",
                "schema_version":1,"functions":[{"subject":SLOT,"required_return":required}],
            }))
            .unwrap();
            authored.push(b'\n');
            let contract = fixture.root.join(CONTRACT_PATH);
            fs::write(&contract, &authored).unwrap();

            let result = observe_go_authored_native_return(
                &fixture.root,
                selection("Keep"),
                context(),
                host,
                |request| Ok(reply(case, request, "module")),
                |request| Ok(reply(case, request, "body")),
            )
            .unwrap();
            let NativeCallableOutcome::Linked(subject) = result.subject else {
                panic!("the compiler-proven Boolean declaration must link");
            };
            assert_eq!(subject.slot_ref(), SLOT);
            assert_eq!(subject.source_path(), source_path);
            assert!(subject.body().parameters().is_empty());
            assert_eq!(
                subject.source_ref(),
                digest(case["source"].as_str().unwrap().as_bytes())
            );
            let AuthoredNativeReturnComparison::Observed(compared) = result.comparison else {
                panic!("one original Module owns the declaration and exact authored requirement");
            };
            assert_eq!(compared.author, "AF-GO-CALLABLE-0001");
            assert_eq!(compared.contract_path, CONTRACT_PATH);
            assert_eq!(compared.contract_ref, digest(&authored));
            assert_eq!(compared.required_return, required);
            assert_eq!(compared.observed_return, expected);
            assert_eq!(fs::read(contract).unwrap(), authored);
            assert_eq!(
                fs::read(fixture.root.join(source_path)).unwrap(),
                case["source"].as_str().unwrap().as_bytes()
            );
            manifests.push(subject.evaluation().source_manifest_digest().to_owned());
        }
        assert_ne!(manifests[0], manifests[1]);
    }
}

mod filesystem {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use fortress_core::go_observation::{
        GoFilesystemHost, GoFilesystemLibraryPin, observe_go_filesystem_effects,
    };

    const WORKER: GoCollectorPin<'static> = GoCollectorPin {
        executable_sha256: "sha256:16afcaf7f5791425b2eeeff8c3c86b297e71b50156cf83ab86953a475e1f8bf5",
        supervisor_context_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        go_toolchain: "go1.22.12",
    };
    const LIBRARY: GoFilesystemLibraryPin<'static> = GoFilesystemLibraryPin {
        package_source_ref: "sha256:8f61ebb242bc4c60ebcaf6a96015ff67d0ac84d3441da63bd6c185eda13fc226",
        export_set_ref: "sha256:4ff2871ac521be941d7da0eaef51d1a90a6e30a504774a8b043a03943e1798bc",
    };
    const SELECTED: GoPackageSelection<'static> = GoPackageSelection {
        directory: "",
        package_path: "fixture.local/effects",
        go_version: "go1.22",
        target_os: "windows",
        target_arch: "amd64",
    };
    const DIRECT_INPUT: &[u8] = include_bytes!("../_data/go_direct_request_v1.json");
    const DIRECT_REPLY: &[u8] = include_bytes!("../_data/go_fs_direct_v1.json");

    fn filesystem_fixture(name: &str, request: &[u8]) -> (Fixture, Vec<u8>) {
        let fixture = Fixture::new(name);
        let request: Value = serde_json::from_slice(request).unwrap();
        let file = &request["files"][0];
        assert_eq!(file["path"], "fixture.go");
        let bytes = STANDARD
            .decode(file["source_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(file["sha256"], fortress_core::portable::digest(&bytes));
        fs::write(fixture.root.join("fixture.go"), &bytes).unwrap();
        (fixture, bytes)
    }

    fn replay(name: &str, request: &[u8], reply: &[u8]) -> Value {
        let (fixture, original) = filesystem_fixture(name, request);
        let result = observe_go_filesystem_effects(
            &fixture.root,
            SELECTED,
            GoFilesystemHost {
                collector: &WORKER,
                library: LIBRARY,
            },
            |sent| {
                assert_eq!(sent, request);
                Ok(reply.to_vec())
            },
        )
        .unwrap();
        assert_eq!(fs::read(fixture.root.join("fixture.go")).unwrap(), original);
        let document = serde_json::to_value(result).unwrap();
        jsonschema::draft202012::validate(
            &registered_schema_path("engine/snapshot_governance/_data/go_fs_schema_v1.json"),
            &document,
        )
        .expect("public Go filesystem inspection schema");
        assert_eq!(document["runtime_execution"], "NOT_RUN");
        assert_eq!(document["canonical_finding_or_certificate"], "NOT_ISSUED");
        assert_eq!(
            document["native"]["response_ref"],
            fortress_core::portable::digest(reply)
        );
        // The effect context binds the native exchange plus the installed catalog.
        assert_ne!(
            document["native"]["binding_ref"],
            document["evaluation_key"]["program_context_digest"]
        );
        document
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R28-025`
    /// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R28
    #[test]
    fn exact_go_filesystem_effects_bind_scoped_facts_and_refuse_stale_source() {
        let observed = replay("filesystem-direct", DIRECT_INPUT, DIRECT_REPLY);
        let effects = &observed["effects"];
        assert_eq!(effects["upper_bound"], json!({"state":"UNKNOWN"}));
        assert_eq!(
            effects["binding"]["authority_sha256"],
            observed["evaluation_key"]["authority_binding_digest"]
        );
        assert_eq!(effects["sites"].as_array().unwrap().len(), 1);
        assert_eq!(effects["sites"][0]["start_byte"], 58);
        assert_eq!(effects["sites"][0]["end_byte"], 89);
        let operation = &effects["sites"][0]["disposition"];
        assert_eq!(operation["status"], "modeled_operation");
        assert_eq!(operation["effects"], json!(["filesystem.write"]));

        let shadowed = replay(
            "filesystem-shadowed",
            include_bytes!("../_data/go_shadow_request_v1.json"),
            include_bytes!("../_data/go_fs_shadow_v1.json"),
        );
        assert_eq!(
            shadowed["effects"]["sites"][0]["disposition"],
            json!({"status":"local_or_shadowed"})
        );
        assert_eq!(
            shadowed["effects"]["upper_bound"],
            json!({"state":"UNKNOWN"})
        );

        let unavailable = replay(
            "filesystem-conditional",
            include_bytes!("../_data/go_closed_request_v1.json"),
            include_bytes!("../_data/go_fs_closed_v1.json"),
        );
        assert_eq!(
            unavailable["native"]["disposition"]["reason"],
            "BUILD_CONTEXT_REQUIRED"
        );
        assert_eq!(unavailable["native"]["calls"], json!([]));
        assert_eq!(unavailable["effects"], Value::Null);

        let (fixture, _) = filesystem_fixture("filesystem-export-mismatch", DIRECT_INPUT);
        let unknown_sdk = observe_go_filesystem_effects(
            &fixture.root,
            SELECTED,
            GoFilesystemHost {
                collector: &WORKER,
                library: GoFilesystemLibraryPin {
                    export_set_ref: WORKER.supervisor_context_sha256,
                    ..LIBRARY
                },
            },
            |_| panic!("unqualified SDK must never be dispatched"),
        );
        assert!(matches!(
            unknown_sdk,
            Err(GoObservationError::UnsupportedContext)
        ));

        let (fixture, _) = filesystem_fixture("filesystem-drift", DIRECT_INPUT);
        let stale = observe_go_filesystem_effects(
            &fixture.root,
            SELECTED,
            GoFilesystemHost {
                collector: &WORKER,
                library: LIBRARY,
            },
            |sent| {
                assert_eq!(sent, DIRECT_INPUT);
                fs::write(fixture.root.join("fixture.go"), b"package effects\n").unwrap();
                Ok(DIRECT_REPLY.to_vec())
            },
        );
        assert!(matches!(stale, Err(GoObservationError::SourceChanged)));
    }
}
