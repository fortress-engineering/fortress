//! Local MCP stdio translation of immutable Fortress inspection and explicit previews.

use fortress_core::candidate::{CandidateRequest, CandidateWorkspace};
use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
use fortress_core::migration_adapter::CanonicalMigrationAuthority;
use fortress_core::query::{MAX_REQUEST_BYTES, QueryRequest, QueryService};
use fortress_core::session::SessionOptions;
use fortress_core::wire::{canonicalize_public_json, parse_public_json};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

const PROTOCOLS: [&str; 2] = ["2025-11-25", "2025-06-18"];
const RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const ACTIVE_LIMIT: usize = 8;
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
    name: String,
    #[serde(default)]
    arguments: Value,
    #[serde(default, rename = "_meta")]
    metadata: Option<BTreeMap<String, Value>>,
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

fn lock<T>(mutex: &Mutex<T>) -> io::Result<std::sync::MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| io::Error::other("MCP request registry poisoned"))
}

pub(super) fn serve<R: BufRead + Send + 'static, W: Write>(
    input: R,
    output: &mut W,
    query: &QueryService,
    root: &Path,
    storage: Option<&Path>,
) -> io::Result<()> {
    let active = Active::default();
    let _cancel_on_disconnect = CancelActive(Arc::clone(&active));
    let reader_active = Arc::clone(&active);
    let (sender, receiver) = mpsc::sync_channel(ACTIVE_LIMIT);
    let reader = std::thread::spawn(move || read_messages(input, &sender, &reader_active));
    let mut workspace = None;
    for frame in receiver {
        let response = match frame {
            Incoming::Reply(value) => value,
            Incoming::Work {
                id,
                request,
                cancel,
            } => {
                let response = if cancel.load(Ordering::Acquire) {
                    cancelled(&id)
                } else {
                    execute(&id, request, query, root, storage, &mut workspace, &cancel)
                };
                // Resolve publication and cancellation in the same active-ID critical section.
                let mut entries = lock(&active)?;
                let response = if cancel.load(Ordering::Acquire) {
                    cancelled(&id)
                } else {
                    response
                };
                entries.remove(&id);
                response
            }
        };
        write_response(output, &response)?;
    }
    reader
        .join()
        .map_err(|_| io::Error::other("MCP reader panicked"))?
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

fn ok(id: &Id, result: Value) -> Value {
    let mut envelope = json!({"jsonrpc":"2.0","id":id});
    envelope["result"] = result;
    envelope
}

fn failure(id: &Value, number: i32, code: &str, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":number,"message":message,"data":{"code":code}}})
}

fn cancelled(id: &Id) -> Value {
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

fn read_messages<R: BufRead>(
    mut input: R,
    sender: &mpsc::SyncSender<Incoming>,
    active: &Active,
) -> io::Result<()> {
    let _cancel_on_disconnect = CancelActive(Arc::clone(active));
    let mut state = Lifecycle::New;
    let mut seen = BTreeSet::new();
    for _ in 0..SESSION_FRAME_LIMIT {
        let Some(frame) = crate::rpc::read_frame(&mut input, Some(2 * MAX_REQUEST_BYTES))? else {
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

fn request_argument(request: &Value) -> Value {
    json!({"type":"object","required":["request"],"additionalProperties":false,
           "properties":{"request":request}})
}

fn query_argument() -> Value {
    request_argument(&json!({
        "type":"object","additionalProperties":false,
        "required":["protocol_version","request_id","method","parameters"],
        "properties":{
            "protocol_version":{"enum":[1,2,3,4,5]},
            "request_id":{"type":"string","minLength":1,"maxLength":128},
            "method":{"type":"string","description":"Use native capabilities to identify supported methods."},
            "state_ref":{"type":["string","null"]},
            "context_ref":{"type":["string","null"]},
            "parameters":{"type":"object","description":"Native parameters for the selected method and edition."}
        }
    }))
}

fn candidate_argument() -> Value {
    request_argument(&json!({
        "type":"object","additionalProperties":false,
        "required":["schema_version","base_source_ref","context_ref","operations"],
        "properties":{
            "schema_version":{"const":1},
            "base_source_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "context_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "operations":{"type":"array","maxItems":1024,"items":{"type":"object"},
                          "description":"Native migration operations with exact preimages and postimages."},
            "comparison_context":{"type":"object"}
        }
    }))
}

fn tool(name: &str, description: &str, schema: &Value) -> Value {
    json!({"name":name,"description":description,"inputSchema":schema,
           "annotations":{"readOnlyHint":true,"openWorldHint":false}})
}

fn list_tools(candidates: bool) -> Value {
    let mut tools = vec![tool(
        "fortress_inspect",
        "Inspect one loaded repository with an unchanged Fortress QueryRequest (versions 1–5). Use capabilities first, then status, doctor, query, explain, transition or candidate inspection. Preserve state and context references and follow continuation cursors. Stale and unavailable evidence remain explicit. No semantic analysis or project execution is triggered.",
        &query_argument(),
    )];
    if candidates {
        tools.push(tool("fortress_candidate_base",
            "Explicitly prepare the exact physical base and analysis context for an isolated candidate. This may run bounded Fortress analysis. It does not execute project code.",
            &json!({"type":"object","additionalProperties":false})));
        tools.push(tool("fortress_evaluate_candidate",
            "Evaluate a version 1 CandidateRequest with exact base identity, context and file operations. A result is hypothetical, supplies no grant and does not apply source changes. Only explicitly enabled local sessions offer this tool.",
            &candidate_argument()));
    }
    json!({"tools":tools})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments<T> {
    request: T,
}

fn execute(
    id: &Id,
    work: Work,
    query: &QueryService,
    root: &Path,
    storage: Option<&Path>,
    workspace: &mut Option<CandidateWorkspace>,
    cancel: &AtomicBool,
) -> Value {
    let Work::Call(call) = work else {
        let mut listing = list_tools(storage.is_some());
        listing["_meta"] = json!({
            "fortress/hostCapability": crate::agent_capabilities::mcp(storage.is_some())
        });
        return ok(id, listing);
    };
    // The MCP metadata extension cannot supply authorization or alter query semantics.
    drop(call.metadata);
    if call.name == "fortress_inspect" {
        return inspect(id, call.arguments, query, cancel);
    }
    if matches!(
        call.name.as_str(),
        "fortress_candidate_base" | "fortress_evaluate_candidate"
    ) && let Some(storage) = storage
    {
        return match candidate(&call.name, call.arguments, root, storage, workspace, cancel) {
            Ok(value) => tool_result(id, value, false),
            Err(error) => tool_result(id, json!({"error":error}), true),
        };
    }
    failure(
        &json!(id),
        -32602,
        "TOOL_UNAVAILABLE",
        "Tool is not advertised in this connection.",
    )
}

fn inspect(id: &Id, arguments: Value, query: &QueryService, cancel: &AtomicBool) -> Value {
    let request = serde_json::from_value::<Arguments<Value>>(arguments)
        .map_err(|_| "Expected one request object.")
        .and_then(|args| {
            QueryRequest::from_json_str(&args.request.to_string())
                .map_err(|_| "Expected a valid bounded Fortress QueryRequest.")
        });
    let Ok(request) = request else {
        return failure(
            &json!(id),
            -32602,
            "INVALID_PARAMETERS",
            request.unwrap_err(),
        );
    };
    if matches!(request.method.as_str(), "cancel" | "progress") {
        return failure(
            &json!(id),
            -32602,
            "INVALID_PARAMETERS",
            "Use MCP notifications/cancelled for transport cancellation.",
        );
    }
    let result = query.execute(&request, cancel);
    let is_error = result.error.is_some();
    let Ok(value) = result.to_canonical_bytes().and_then(|bytes| {
        serde_json::from_slice(&bytes).map_err(|error| {
            fortress_core::query::QueryError::new("INVALID_OUTPUT", error.to_string())
        })
    }) else {
        return failure(
            &json!(id),
            -32000,
            "RESOURCE_LIMIT",
            "Native response exceeded its bound.",
        );
    };
    tool_result(id, value, is_error)
}

fn tool_result(id: &Id, value: Value, is_error: bool) -> Value {
    let mut result =
        json!({"content":[{"type":"text","text":value.to_string()}],"isError":is_error});
    result["structuredContent"] = value;
    ok(id, result)
}

fn candidate(
    name: &str,
    args: Value,
    root: &Path,
    storage: &Path,
    workspace: &mut Option<CandidateWorkspace>,
    cancel: &AtomicBool,
) -> Result<Value, fortress_core::migration_governance::MigrationError> {
    use fortress_core::migration_governance::MigrationError;
    let error = |code: &str, message: &str| MigrationError {
        code: code.into(),
        message: message.into(),
        transaction_ref: None,
    };
    let request = if name == "fortress_candidate_base" {
        if !args.is_null() && !args.as_object().is_some_and(serde_json::Map::is_empty) {
            return Err(error(
                "INVALID_PARAMETERS",
                "Candidate base takes no arguments.",
            ));
        }
        None
    } else {
        let args: Arguments<Value> = serde_json::from_value(args)
            .map_err(|_| error("INVALID_PARAMETERS", "Expected one CandidateRequest."))?;
        let body = args.request.to_string();
        if body.len() > MAX_REQUEST_BYTES {
            return Err(error(
                "RESOURCE_LIMIT",
                "Candidate request exceeds the MCP frame bound.",
            ));
        }
        Some(parse_public_json::<CandidateRequest>(&body).map_err(|_| {
            error(
                "INVALID_PARAMETERS",
                "Expected a valid native CandidateRequest.",
            )
        })?)
    };
    if workspace.is_none() {
        *workspace = Some(CandidateWorkspace::open(
            root,
            storage,
            SessionOptions::default(),
        )?);
    }
    if cancel.load(Ordering::Acquire) {
        return Err(error("CANCELLED", "Request cancelled."));
    }
    let workspace = workspace
        .as_mut()
        .expect("explicit preparation installed the workspace");
    if let Some(request) = request {
        let authority = CanonicalMigrationAuthority {
            policy: None,
            host: &UnmediatedHost,
            validator: &NoGrantValidator,
            evaluation_time: None,
            reviewed_initial_intent_ref: None,
            finding_proposal: None,
            identity_plan: None,
        };
        let result = workspace.evaluate("mcp", "preview", request, &authority, cancel);
        workspace.release("mcp", "preview");
        let bytes = result?.to_canonical_bytes()?;
        if bytes.len() > RESPONSE_BYTES / 2 {
            return Err(error(
                "RESOURCE_LIMIT",
                "Proposal exceeds the inline MCP result bound.",
            ));
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| error("INVALID_OUTPUT", "Invalid proposal projection."))
    } else {
        let base_state_ref = workspace
            .base_state()
            .digest()
            .map_err(|failure| error(&failure.code, &failure.message))?;
        Ok(
            json!({"status":"OBSERVED_BASE","permission":"NONE","actual_certification":false,
                  "request_schema_version":1,"base_source_ref":workspace.base_source_ref(),
                  "context_ref":workspace.context_ref(),"base_state_ref":base_state_ref}),
        )
    }
}
