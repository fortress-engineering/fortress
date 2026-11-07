//! Native CLI/RPC state comparison remains read-only and uses the shared facade.
use fortress_core::query::{QueryInput, QueryService};
use fortress_core::state_governance::ComparisonState;
use serde_json::{Value, json};
use std::io::Cursor;
use std::path::PathBuf;
fn state(n: u8) -> ComparisonState {
    ComparisonState::unavailable(Some(format!("sha256:{n:064x}")))
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        for n in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fortress-transition-cli-{}-{n}",
                std::process::id()
            ));
            if std::fs::create_dir(&path).is_ok() {
                return Self(path);
            }
        }
        panic!("bounded fresh fixture claim exhausted");
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
/// `T-TF-CLI-0001-R22-001`
/// Fortress requirement: TF-CLI-0001-R22
#[test]
fn native_comparison_json_human_capture_and_errors_do_not_mutate_states() {
    let fixture = Fixture::new();
    let root = fixture.0.to_str().unwrap();
    let before = state(1).to_canonical_bytes().unwrap();
    let after = state(2).to_canonical_bytes().unwrap();
    std::fs::write(fixture.0.join("before.json"), &before).unwrap();
    std::fs::write(fixture.0.join("after.json"), &after).unwrap();
    let script = br#"fn main(){std::fs::write("SCRIPT_EXECUTED",b"bad").unwrap();}"#;
    std::fs::write(fixture.0.join("build.rs"), script).unwrap();
    let mut json_output = vec![];
    let mut error = vec![];
    let args = [
        "transition",
        "--from",
        "before.json",
        "--to",
        "after.json",
        root,
        "--format",
        "json",
    ];
    assert_eq!(
        fortress_cli::run(args, &mut json_output, &mut error).unwrap(),
        0,
        "{}",
        String::from_utf8_lossy(&error)
    );
    let result: Value = serde_json::from_slice(&json_output).unwrap();
    assert_eq!(result["protocol_version"], 2);
    assert_eq!(result["result"]["kind"], "TRANSITION");
    let mut human = vec![];
    assert_eq!(
        fortress_cli::run(
            [
                "transition",
                "--from",
                "before.json",
                "--to",
                "after.json",
                root
            ],
            &mut human,
            &mut error
        )
        .unwrap(),
        0
    );
    let human = String::from_utf8(human).unwrap();
    assert!(human.contains(result["result"]["data"]["analysis_ref"].as_str().unwrap()));
    assert!(human.contains("UNKNOWN"));
    let mut capture = vec![];
    assert_eq!(
        fortress_cli::run(["transition", "capture", root], &mut capture, &mut error).unwrap(),
        0,
        "{}",
        String::from_utf8_lossy(&error)
    );
    ComparisonState::from_json_str(std::str::from_utf8(&capture).unwrap()).unwrap();
    assert_eq!(
        std::fs::read(fixture.0.join("before.json")).unwrap(),
        before
    );
    assert_eq!(std::fs::read(fixture.0.join("after.json")).unwrap(), after);
    assert_eq!(std::fs::read(fixture.0.join("build.rs")).unwrap(), script);
    assert!(!fixture.0.join("SCRIPT_EXECUTED").exists());
    assert_ne!(
        fortress_cli::run(
            [
                "transition",
                "--from",
                "../missing",
                "--to",
                "current",
                root
            ],
            &mut vec![],
            &mut error
        )
        .unwrap(),
        0
    );
}
/// `T-TF-CLI-0001-R22-002`
/// Fortress requirement: TF-CLI-0001-R22
#[test]
fn stdio_two_compares_explicit_loaded_refs_and_rejects_unknown_versions() {
    let a = state(1);
    let b = state(2);
    let from = a.digest().unwrap();
    let to = b.digest().unwrap();
    let service = std::sync::Arc::new(
        QueryService::new(QueryInput::empty(format!("sha256:{:064x}", 9)))
            .unwrap()
            .with_comparison_states(vec![a, b])
            .unwrap(),
    );
    let request = json!({"protocol_version":2,"request_id":"compare","method":"transition","state_ref":null,"context_ref":null,"parameters":{"from_state_ref":from,"to_state_ref":to}});
    let unknown =
        json!({"protocol_version":99,"request_id":"unsupported","method":"status","parameters":{}});
    let mut output = vec![];
    fortress_cli::rpc::serve(
        Cursor::new(format!("{request}\n{unknown}\n").into_bytes()),
        &mut output,
        &service,
    )
    .unwrap();
    let results = std::str::from_utf8(&output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let result = results
        .iter()
        .find(|r| r["request_id"] == "compare")
        .unwrap();
    assert_eq!(result["protocol_version"], 2);
    assert_eq!(result["result"]["kind"], "TRANSITION");
    assert!(result["error"].is_null());
    assert_eq!(
        results
            .iter()
            .find(|r| r["request_id"] == "unsupported")
            .unwrap()["error"]["code"],
        "UNSUPPORTED_VERSION"
    );
}
