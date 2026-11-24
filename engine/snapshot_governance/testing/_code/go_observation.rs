//! Exact native Go admission and refusal controls.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::go_observation::{
    GoBuildContext, GoBuildTestMode, GoCollectorPin, GoObservationError, GoPackageSelection,
    observe_go_native, observe_go_native_build,
};
use serde_json::{Value, json};

const NATIVE: &[u8] = include_bytes!("../_data/go_native_fixture_v1.json");
const API: &str =
    "// café\r\npackage bounded\r\nfunc Run(input int) int { return target(input) }\r\n";
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
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = serde_json::from_slice(
        &fs::read(root.join("engine/standard_registry/_data/schema_manifest.json"))
            .expect("registered schemas are available in the test repository"),
    )
    .expect("registered schema manifest");
    let relative = format!("engine/program_semantics/_data/{name}");
    assert!(
        manifest["schemas"]
            .as_array()
            .expect("registered paths")
            .iter()
            .any(|path| path == relative.as_str())
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
        "// café\r\npackage fixture\r\n",
        "func Keep(b bool) bool { if b {} ; return !b }\r\n",
        "func Étude(b bool) bool { return b }\r\n",
        "func _(b bool) bool { return b }\r\n",
        "func Named(café bool) bool { return café }\r\n",
        "func Local(b bool) bool { côté := b; return côté }\r\n",
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
    use fortress_core::go_observation::{GoModuleSelection, observe_go_native_module};

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
