//! Exact native Go admission and refusal controls.

use std::fs;
use std::path::PathBuf;

use fortress_core::go_observation::{
    GoCollectorPin, GoObservationError, GoPackageSelection, observe_go_native,
};
use serde_json::{Value, json};

const NATIVE: &[u8] = include_bytes!("../_data/go_native_fixture_v1.json");
const SCHEMA: &str = include_str!("../../../program_semantics/_data/go_observation_schema_v1.json");
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
    jsonschema::draft202012::validate(&serde_json::from_str(SCHEMA).unwrap(), &json)
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
