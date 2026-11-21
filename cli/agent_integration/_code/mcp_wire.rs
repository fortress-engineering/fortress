//! Framing and request admission shared by the local read-only transports.

use fortress_core::query::{MAX_REQUEST_BYTES, QueryError};
use fortress_core::wire::{canonicalize_public_json, parse_public_json};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

const PROTOCOLS: [&str; 2] = ["2025-11-25", "2025-06-18"];
pub(super) const RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub(super) const ACTIVE_LIMIT: usize = 8;
const SESSION_REQUEST_LIMIT: usize = 4096;
const SESSION_FRAME_LIMIT: usize = 8192;
pub(super) type Active = Arc<Mutex<BTreeMap<Id, Arc<AtomicBool>>>>;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(untagged)]
pub(super) enum Id {
    Integer(i64),
    Text(String),
}

impl Id {
    fn admissible(&self) -> bool {
        match self {
            Self::Integer(_) => true,
            Self::Text(value) => {
                !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    jsonrpc: String,
    id: Option<Id>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Initialize {
    protocol_version: String,
    capabilities: BTreeMap<String, Value>,
    client_info: ClientInfo,
}

#[derive(Deserialize)]
struct ClientInfo {
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Call {
    pub(super) name: String,
    #[serde(default)]
    pub(super) arguments: Value,
    #[serde(default, rename = "_meta")]
    pub(super) metadata: Option<BTreeMap<String, Value>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cancel {
    request_id: Id,
}

pub(super) struct CancelActive(pub(super) Active);
impl Drop for CancelActive {
    fn drop(&mut self) {
        if let Ok(active) = self.0.lock() {
            for request in active.values() {
                request.store(true, Ordering::Release);
            }
        }
    }
}

pub(super) enum Incoming {
    Reply(Value),
    Work {
        id: Id,
        request: Work,
        cancel: Arc<AtomicBool>,
    },
}

pub(super) enum Work {
    Call(Call),
    List,
}

#[derive(PartialEq, Eq)]
pub(super) enum Lifecycle {
    New,
    Initializing,
    Ready,
}

pub(super) fn lock<T>(mutex: &Mutex<T>) -> io::Result<std::sync::MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| io::Error::other("MCP request registry poisoned"))
}

pub(super) fn write_response(output: &mut impl Write, response: &Value) -> io::Result<()> {
    let raw = response.to_string();
    let bytes = if raw.len() > RESPONSE_BYTES {
        canonicalize_public_json(
            &failure(
                &response["id"],
                -32000,
                "RESOURCE_LIMIT",
                "Response exceeds the local frame limit. Request a smaller inspection page.",
            )
            .to_string(),
        )
    } else {
        canonicalize_public_json(&raw)
    }
    .map_err(io::Error::other)?;
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    output.flush()
}

pub(super) fn ok(id: &Id, result: Value) -> Value {
    let mut envelope = json!({"jsonrpc":"2.0","id":id});
    envelope["result"] = result;
    envelope
}

pub(super) fn failure(id: &Value, number: i32, code: &str, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":number,"message":message,"data":{"code":code}}})
}

pub(super) fn cancelled(id: &Id) -> Value {
    failure(&json!(id), -32800, "CANCELLED", "Request cancelled.")
}

fn decode(frame: Result<Vec<u8>, fortress_core::query::QueryError>) -> Result<Message, Value> {
    let bytes = frame.map_err(|error| {
        if error.code == "TRUNCATED_FRAME" {
            failure(&Value::Null, -32700, "PARSE_ERROR", &error.message)
        } else {
            failure(&Value::Null, -32000, "RESOURCE_LIMIT", &error.message)
        }
    })?;
    let parse_error = || {
        failure(
            &Value::Null,
            -32700,
            "PARSE_ERROR",
            "Expected strict UTF-8 JSON.",
        )
    };
    let raw = std::str::from_utf8(&bytes).map_err(|_| parse_error())?;
    let value: Value = parse_public_json(raw).map_err(|_| parse_error())?;
    let invalid = || {
        failure(
            &Value::Null,
            -32600,
            "INVALID_REQUEST",
            "Invalid JSON-RPC request.",
        )
    };
    if value.get("id").is_some_and(Value::is_null) {
        return Err(invalid());
    }
    let message: Message = serde_json::from_value(value).map_err(|_| invalid())?;
    if message.jsonrpc != "2.0" || message.id.as_ref().is_some_and(|id| !id.admissible()) {
        return Err(invalid());
    }
    Ok(message)
}

pub(super) fn read_messages<R: BufRead>(
    mut input: R,
    sender: &mpsc::SyncSender<Incoming>,
    active: &Active,
) -> io::Result<()> {
    let _cancel_on_disconnect = CancelActive(Arc::clone(active));
    let mut state = Lifecycle::New;
    let mut seen = BTreeSet::new();
    for _ in 0..SESSION_FRAME_LIMIT {
        let Some(frame) = read_frame(&mut input, Some(2 * MAX_REQUEST_BYTES))? else {
            return Ok(());
        };
        let disconnect = frame
            .as_ref()
            .is_err_and(|error| matches!(error.code.as_str(), "DISCARD_LIMIT" | "TRUNCATED_FRAME"));
        let next = match decode(frame) {
            Err(error) => Incoming::Reply(error),
            Ok(message) => {
                let Some(id) = message.id else {
                    receive_notification(&message.method, message.params, &mut state, active)?;
                    continue;
                };
                if seen.len() >= SESSION_REQUEST_LIMIT {
                    let reply = failure(
                        &json!(id),
                        -32000,
                        "RESOURCE_LIMIT",
                        "The request identity budget is exhausted. Reopen the stdio connection.",
                    );
                    let _ = sender.send(Incoming::Reply(reply));
                    return Ok(());
                }
                if seen.insert(id.clone()) {
                    dispatch(id, &message.method, message.params, &mut state, active)?
                } else {
                    Incoming::Reply(failure(
                        &Value::Null,
                        -32600,
                        "DUPLICATE_REQUEST_ID",
                        "Request IDs are unique within the connection.",
                    ))
                }
            }
        };
        if sender.send(next).is_err() || disconnect {
            return Ok(());
        }
    }
    let _ = sender.send(Incoming::Reply(failure(
        &Value::Null,
        -32000,
        "RESOURCE_LIMIT",
        "The frame budget is exhausted. Reopen the stdio connection.",
    )));
    Ok(())
}

pub(super) fn receive_notification(
    method: &str,
    params: Value,
    state: &mut Lifecycle,
    active: &Active,
) -> io::Result<()> {
    match method {
        "notifications/initialized"
            if *state == Lifecycle::Initializing && (params.is_null() || params.is_object()) =>
        {
            *state = Lifecycle::Ready;
        }
        "notifications/cancelled" => {
            if let Ok(cancel) = serde_json::from_value::<Cancel>(params)
                && let Some(token) = lock(active)?.get(&cancel.request_id)
            {
                token.store(true, Ordering::Release);
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn dispatch(
    id: Id,
    method: &str,
    params: Value,
    state: &mut Lifecycle,
    active: &Active,
) -> io::Result<Incoming> {
    let invalid = || {
        failure(
            &json!(id),
            -32602,
            "INVALID_PARAMETERS",
            "Invalid method parameters.",
        )
    };
    let empty = || params.is_null() || params.as_object().is_some_and(serde_json::Map::is_empty);
    let request = match method {
        "ping" => {
            return Ok(Incoming::Reply(if empty() {
                ok(&id, json!({}))
            } else {
                invalid()
            }));
        }
        "initialize" if *state == Lifecycle::New => {
            let result = serde_json::from_value::<Initialize>(params).ok()
                .filter(|init| {
                    !init.client_info.name.is_empty() && !init.client_info.version.is_empty()
                        && init.capabilities.len() <= 64
                })
                .map_or_else(invalid, |init| {
                    *state = Lifecycle::Initializing;
                    let version = PROTOCOLS.iter().copied()
                        .find(|version| *version == init.protocol_version)
                        .unwrap_or(PROTOCOLS[0]);
                    ok(&id, json!({
                        "protocolVersion":version,
                        "capabilities":{"tools":{"listChanged":false}},
                        "serverInfo":{"name":"fortress","version":env!("CARGO_PKG_VERSION")},
                        "instructions":"Local inspection and explicitly enabled hypothetical evaluation. No tool mutates governed source or grants authorization."
                    }))
                });
            return Ok(Incoming::Reply(result));
        }
        _ if *state != Lifecycle::Ready => {
            return Ok(Incoming::Reply(failure(
                &json!(id),
                -32002,
                "NOT_INITIALIZED",
                "Complete MCP initialization before requesting tools.",
            )));
        }
        "tools/list" if empty() => Work::List,
        "tools/list" => return Ok(Incoming::Reply(invalid())),
        "tools/call" => {
            let Ok(call) = serde_json::from_value(params) else {
                return Ok(Incoming::Reply(invalid()));
            };
            Work::Call(call)
        }
        _ => {
            return Ok(Incoming::Reply(failure(
                &json!(id),
                -32601,
                "METHOD_NOT_FOUND",
                "This MCP method is not supported.",
            )));
        }
    };
    let mut entries = lock(active)?;
    if entries.len() == ACTIVE_LIMIT {
        return Ok(Incoming::Reply(failure(
            &json!(id),
            -32000,
            "RESOURCE_LIMIT",
            "The connection has too many active tool requests.",
        )));
    }
    let cancel = Arc::new(AtomicBool::new(false));
    entries.insert(id.clone(), Arc::clone(&cancel));
    Ok(Incoming::Work {
        id,
        request,
        cancel,
    })
}

pub(crate) fn read_frame<R: BufRead>(
    input: &mut R,
    strict_discard_limit: Option<usize>,
) -> io::Result<Option<Result<Vec<u8>, QueryError>>> {
    let mut frame = Vec::new();
    let mut oversized = false;
    let mut consumed = 0usize;
    loop {
        let bytes = input.fill_buf()?;
        if bytes.is_empty() {
            return Ok((!frame.is_empty() || oversized).then(|| {
                if oversized {
                    Err(QueryError::new(
                        "RESOURCE_LIMIT",
                        "request frame exceeds byte limit",
                    ))
                } else if strict_discard_limit.is_some() {
                    Err(QueryError::new(
                        "TRUNCATED_FRAME",
                        "stream closed before the frame delimiter",
                    ))
                } else {
                    Ok(frame)
                }
            }));
        }
        let newline = bytes.iter().position(|byte| *byte == b'\n');
        let count = newline.unwrap_or(bytes.len());
        consumed = consumed.saturating_add(count);
        if strict_discard_limit.is_some_and(|limit| consumed > limit) {
            return Ok(Some(Err(QueryError::new(
                "DISCARD_LIMIT",
                "oversized frame did not terminate within the discard bound",
            ))));
        }
        if !oversized {
            if count > MAX_REQUEST_BYTES.saturating_sub(frame.len()) {
                oversized = true;
                frame.clear();
            } else {
                frame.extend_from_slice(&bytes[..count]);
            }
        }
        input.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(if oversized {
                Err(QueryError::new(
                    "RESOURCE_LIMIT",
                    "request frame exceeds byte limit",
                ))
            } else {
                Ok(frame)
            }));
        }
    }
}
