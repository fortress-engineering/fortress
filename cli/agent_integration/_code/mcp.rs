//! Local MCP stdio translation of immutable Fortress inspection and explicit previews.

use fortress_core::candidate::{CandidateRequest, CandidateWorkspace};
use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
use fortress_core::migration_adapter::CanonicalMigrationAuthority;
use fortress_core::query::{MAX_REQUEST_BYTES, QueryRequest, QueryService};
use fortress_core::session::SessionOptions;
use fortress_core::wire::parse_public_json;
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

use crate::agent_wire::{
    ACTIVE_LIMIT, Active, CancelActive, Id, Incoming, RESPONSE_BYTES, Work, cancelled, failure,
    lock, ok, read_messages, write_response,
};

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
        "Inspect one loaded repository with a native Fortress QueryRequest (versions 1–5). Start with method capabilities and empty parameters, then use status for source freshness and assurance. Use method query with parameters.kind (for example modules, routes or findings) and method explain with parameters.selector for evidence. Preserve state and context references and follow continuation cursors. Use MCP notifications/cancelled with the outer JSON-RPC ID. Stale or unavailable evidence does not establish current conformance. Inspection runs no project code.",
        &query_argument(),
    )];
    if candidates {
        tools.push(tool("fortress_candidate_base",
            "Call with empty arguments before evaluating a candidate. Use the returned base_source_ref and context_ref in fortress_evaluate_candidate. Preparing the physical base can run bounded Fortress analysis without executing project code.",
            &json!({"type":"object","additionalProperties":false})));
        tools.push(tool("fortress_evaluate_candidate",
            "Evaluate a version 1 CandidateRequest with exact base identity, context and file operations. PROPOSED is a hypothetical result, with no permission to write or certify. For STALE_BASE, reconnect and obtain a fresh base before rebuilding the request. An oversized result requires the native overlay command and preloaded candidate inspection.",
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
