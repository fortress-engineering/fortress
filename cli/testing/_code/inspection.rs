//! Native adapter and stdio protocol controls over the shared query result contract.

use std::io::Cursor;

use fortress_core::query::{QueryInput, QueryRequest, QueryService};
use serde_json::{Value, json};

fn service() -> QueryService {
    QueryService::new(QueryInput::empty(format!("sha256:{}", "a".repeat(64)))).unwrap()
}
fn request(id: &str, method: &str, parameters: Value) -> Value {
    let mut value = json!({"protocol_version":1,"request_id":id,"method":method,"state_ref":null,"context_ref":null});
    value["parameters"] = parameters;
    value
}
fn run_frames(bytes: Vec<u8>) -> Vec<Value> {
    let mut output = Vec::new();
    fortress_cli::rpc::serve(
        Cursor::new(bytes),
        &mut output,
        &std::sync::Arc::new(service()),
    )
    .unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// `T-TF-CLI-0001-R21-001`
/// Fortress requirement: TF-CLI-0001-R21
#[test]
fn adapters_share_exact_canonical_results_and_registered_methods() {
    let query = service();
    let frame = request("one", "status", json!({}));
    let req = QueryRequest::from_json_str(&frame.to_string()).unwrap();
    let expected = query.execute(&req, &std::sync::atomic::AtomicBool::new(false));
    let results = run_frames(format!("{frame}\n").into_bytes());
    assert_eq!(results[0], serde_json::to_value(expected).unwrap());
    let registry = fortress_cli::command::CommandRegistry::builtin();
    for name in ["status", "doctor", "query", "explain", "author", "serve"] {
        assert!(registry.find(name).is_some());
    }
    let mut output = Vec::new();
    let mut error = Vec::new();
    assert_eq!(
        fortress_cli::run(["serve"], &mut output, &mut error).unwrap(),
        fortress_cli::EXIT_USAGE
    );
}

/// `T-TF-CLI-0001-R21-002`
/// Fortress requirement: TF-CLI-0001-R21
#[test]
fn stdio_rejects_bad_frames_versions_parameters_and_recovers_at_newlines() {
    let mut unknown = request("version", "status", json!({}));
    unknown["protocol_version"] = json!(99);
    let bad_params = request("params", "status", json!({"run_build":true}));
    let bad_method = request("method", "repair", json!({}));
    let bytes = format!(
        "{{bad\n{unknown}\n{bad_params}\n{bad_method}\n{}\n",
        request("valid", "status", json!({}))
    )
    .into_bytes();
    let results = run_frames(bytes);
    assert_eq!(results.len(), 5);
    assert_eq!(results[0]["error"]["code"], "INVALID_REQUEST");
    assert_eq!(results[1]["error"]["code"], "UNSUPPORTED_VERSION");
    assert_eq!(results[2]["error"]["code"], "INVALID_PARAMETERS");
    assert_eq!(results[3]["error"]["code"], "UNKNOWN_METHOD");
    assert!(results[4]["error"].is_null());
}

/// `T-TF-CLI-0001-R21-003`
/// Fortress requirement: TF-CLI-0001-R21
#[test]
fn oversized_and_non_utf8_frames_have_bounded_recovery() {
    let mut bytes = vec![b'x'; fortress_core::query::MAX_REQUEST_BYTES + 128];
    bytes.push(b'\n');
    bytes.extend([0xff, b'\n']);
    bytes.extend(format!("{}\n", request("last", "protocol", json!({}))).as_bytes());
    let results = run_frames(bytes);
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["error"]["code"], "RESOURCE_LIMIT");
    assert_eq!(results[1]["error"]["code"], "INVALID_REQUEST");
    assert_eq!(results[2]["request_id"], "last");
}

/// `T-TF-CLI-0001-R21-004`
/// Fortress requirement: TF-CLI-0001-R21
#[test]
fn lifecycle_requests_remain_read_only_and_correlated() {
    let frames = [
        request("cancel", "cancel", json!({"request_id":"absent"})),
        request("progress", "progress", json!({"request_id":"absent"})),
        request("work", "status", json!({})),
        request("interrupt", "cancel", json!({"request_id":"work"})),
    ];
    let bytes = frames
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let results = run_frames(bytes);
    assert_eq!(results.len(), 4);
    for id in ["cancel", "progress", "work", "interrupt"] {
        assert_eq!(
            results
                .iter()
                .filter(|response| response["request_id"] == id)
                .count(),
            1
        );
    }
    assert_eq!(
        results
            .iter()
            .find(|response| response["request_id"] == "cancel")
            .unwrap()["result"]["data"]["active"],
        false
    );
    let work = results
        .iter()
        .find(|response| response["request_id"] == "work")
        .unwrap();
    assert!(matches!(
        work["operational_state"].as_str(),
        Some("COMPLETED" | "CANCELLED")
    ));
    assert!(
        results
            .iter()
            .all(|response| response["state_ref"] == results[0]["state_ref"])
    );
    verify_broken_output_shutdown();
}

struct BlockingInput {
    cursor: Cursor<Vec<u8>>,
    stop: std::sync::mpsc::Receiver<()>,
    closed: std::sync::mpsc::Sender<()>,
}
impl std::io::Read for BlockingInput {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut self.cursor, bytes)
    }
}
impl std::io::BufRead for BlockingInput {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.cursor.position() == u64::try_from(self.cursor.get_ref().len()).unwrap() {
            self.stop.recv().map_err(std::io::Error::other)?;
        }
        std::io::BufRead::fill_buf(&mut self.cursor)
    }
    fn consume(&mut self, count: usize) {
        std::io::BufRead::consume(&mut self.cursor, count);
    }
}
impl Drop for BlockingInput {
    fn drop(&mut self) {
        let _ = self.closed.send(());
    }
}
struct BrokenOutput;
impl std::io::Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn verify_broken_output_shutdown() {
    let (stop_sender, stop) = std::sync::mpsc::channel();
    let (closed, closed_receiver) = std::sync::mpsc::channel();
    let input = BlockingInput {
        cursor: Cursor::new(format!("{}\n", request("blocked", "status", json!({}))).into_bytes()),
        stop,
        closed,
    };
    let result =
        fortress_cli::rpc::serve(input, &mut BrokenOutput, &std::sync::Arc::new(service()));
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    stop_sender.send(()).unwrap();
    closed_receiver.recv().unwrap();
}
