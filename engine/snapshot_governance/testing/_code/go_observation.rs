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

fn registered_schema(edition: u8) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = serde_json::from_slice(
        &fs::read(root.join("engine/standard_registry/_data/schema_manifest.json"))
            .expect("registered schemas are available in the test repository"),
    )
    .expect("registered schema manifest");
    let relative = format!("engine/program_semantics/_data/go_observation_schema_v{edition}.json");
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
    jsonschema::draft202012::validate(&registered_schema(1), &json)
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
    jsonschema::draft202012::validate(&registered_schema(2), &observed)
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
            jsonschema::draft202012::validate(&super::registered_schema(3), &rendered).unwrap();
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
