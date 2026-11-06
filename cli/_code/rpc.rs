//! Bounded LF-framed stdio adapter over the transport-neutral query facade.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use fortress_core::query::{
    MAX_REQUEST_BYTES, QueryError, QueryOperation, QueryRequest, QueryResponse, QueryService,
};
use serde_json::json;

const MAX_ACTIVE_REQUESTS: usize = 16;
type ActiveRequests = Arc<Mutex<BTreeMap<String, Arc<AtomicBool>>>>;

enum Incoming {
    Request(QueryRequest, Arc<AtomicBool>),
    Response(Box<QueryResponse>),
}

impl Incoming {
    fn response(response: QueryResponse) -> Self {
        Self::Response(Box::new(response))
    }
}

/// Serves bounded strict UTF-8 JSON lines over caller-supplied streams.
///
/// A dedicated bounded reader handles cancellation while queries run. Only
/// loaded immutable results are queried; no analysis, subprocess or write
/// method exists. IDs must be unique among active requests. Queue saturation
/// backpressures input; it never creates an unbounded worker or request list.
/// The stream owner must close input on transport shutdown. A failed output
/// cancels active work and returns without waiting on a blocked input reader;
/// the single read-only reader releases its immutable handle when input closes.
///
/// # Errors
/// Returns an I/O error for failed input, output or worker lifecycle.
pub fn serve<R: BufRead + Send + 'static, O: Write>(
    input: R,
    output: &mut O,
    service: &Arc<QueryService>,
) -> io::Result<()> {
    let active: ActiveRequests = Arc::new(Mutex::new(BTreeMap::new()));
    let (sender, receiver) = mpsc::sync_channel(MAX_ACTIVE_REQUESTS);
    let _cancel_on_exit = CancelActive(Arc::clone(&active));
    let reader_active = Arc::clone(&active);
    let reader_service = Arc::clone(service);
    let reader =
        std::thread::spawn(move || read_requests(input, &sender, &reader_active, &reader_service));
    for incoming in receiver {
        let response = match incoming {
            Incoming::Response(response) => *response,
            Incoming::Request(request, token) => {
                let response = service.execute(&request, &token);
                active
                    .lock()
                    .map_err(|_| io::Error::other("active request registry poisoned"))?
                    .remove(&request.request_id);
                response
            }
        };
        output.write_all(&response.to_canonical_bytes().map_err(io::Error::other)?)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    reader
        .join()
        .map_err(|_| io::Error::other("stdio reader panicked"))?
}

fn read_frame<R: BufRead>(input: &mut R) -> io::Result<Option<Result<Vec<u8>, QueryError>>> {
    let mut frame = Vec::new();
    let mut oversized = false;
    loop {
        let bytes = input.fill_buf()?;
        if bytes.is_empty() {
            return Ok((!frame.is_empty() || oversized).then(|| {
                if oversized {
                    Err(QueryError::new(
                        "RESOURCE_LIMIT",
                        "request frame exceeds byte limit",
                    ))
                } else {
                    Ok(frame)
                }
            }));
        }
        let newline = bytes.iter().position(|byte| *byte == b'\n');
        let count = newline.unwrap_or(bytes.len());
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

struct CancelActive(ActiveRequests);
impl Drop for CancelActive {
    fn drop(&mut self) {
        if let Ok(entries) = self.0.lock() {
            for token in entries.values() {
                token.store(true, Ordering::Release);
            }
        }
    }
}

fn read_requests<R: BufRead>(
    mut input: R,
    sender: &mpsc::SyncSender<Incoming>,
    active: &ActiveRequests,
    service: &QueryService,
) -> io::Result<()> {
    while let Some(frame) = read_frame(&mut input)? {
        let request = match frame
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|error| QueryError::new("INVALID_REQUEST", error.to_string()))
            })
            .and_then(|source| QueryRequest::from_json_str(&source))
        {
            Ok(request) => request,
            Err(error) => {
                if sender
                    .send(Incoming::response(service.failure(None, error)))
                    .is_err()
                {
                    break;
                }
                continue;
            }
        };
        if let Ok(operation @ (QueryOperation::Cancel(_) | QueryOperation::Progress(_))) =
            request.operation_for_adapter()
        {
            let validation = service.execute(&request, &AtomicBool::new(false));
            if validation
                .error
                .as_ref()
                .is_none_or(|error| error.code != "ADAPTER_REQUIRED")
            {
                if sender.send(Incoming::response(validation)).is_err() {
                    break;
                }
                continue;
            }
            let (control, cancel) = match operation {
                QueryOperation::Cancel(control) => (control, true),
                QueryOperation::Progress(control) => (control, false),
                _ => unreachable!(),
            };
            let entries = active
                .lock()
                .map_err(|_| io::Error::other("active request registry poisoned"))?;
            let token = entries.get(&control.request_id);
            if cancel && let Some(token) = token {
                token.store(true, Ordering::Release);
            }
            let response = service.lifecycle_response(request.request_id,json!({"target_request_id":control.request_id,"active":token.is_some(),"cancellation_requested":cancel && token.is_some(),"state":if token.is_some(){"QUEUED_OR_RUNNING"}else{"NOT_ACTIVE"}}));
            drop(entries);
            if sender.send(Incoming::response(response)).is_err() {
                break;
            }
            continue;
        }
        let token = Arc::new(AtomicBool::new(false));
        let mut entries = active
            .lock()
            .map_err(|_| io::Error::other("active request registry poisoned"))?;
        let error = if entries.contains_key(&request.request_id) {
            Some(QueryError::new(
                "DUPLICATE_REQUEST_ID",
                "request ID is already active",
            ))
        } else if entries.len() >= MAX_ACTIVE_REQUESTS {
            Some(QueryError::new(
                "RESOURCE_LIMIT",
                "active request limit reached",
            ))
        } else {
            None
        };
        if let Some(error) = error {
            drop(entries);
            if sender
                .send(Incoming::response(
                    service.failure(Some(request.request_id), error),
                ))
                .is_err()
            {
                break;
            }
        } else {
            entries.insert(request.request_id.clone(), Arc::clone(&token));
            drop(entries);
            if sender.send(Incoming::Request(request, token)).is_err() {
                break;
            }
        }
    }
    Ok(())
}
