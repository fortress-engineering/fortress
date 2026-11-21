//! Focused private controls for the installed agent boundary.

use crate::agent_wire::{
    Active, CancelActive, Id, Incoming, Lifecycle, cancelled, dispatch, read_frame, read_messages,
    receive_notification, write_response,
};
use fortress_core::query::MAX_REQUEST_BYTES;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use std::sync::{Arc, mpsc};

/// `T-TF-AGENT-INTEGRATION-0001-R01-005`
/// Fortress requirement: TF-AGENT-INTEGRATION-0001-R01
#[test]
fn only_the_correlated_active_request_can_be_cancelled() {
    let active = Active::default();
    let mut state = Lifecycle::Ready;
    let a = Id::Integer(32);
    let b = Id::Text("32".into());
    let Incoming::Work { cancel: first, .. } =
        dispatch(a.clone(), "tools/list", Value::Null, &mut state, &active).unwrap()
    else {
        panic!("expected bounded work");
    };
    let Incoming::Work { cancel: second, .. } =
        dispatch(b, "tools/list", Value::Null, &mut state, &active).unwrap()
    else {
        panic!("expected bounded work");
    };
    for index in 1..=6 {
        assert!(matches!(
            dispatch(
                Id::Integer(index),
                "tools/list",
                Value::Null,
                &mut state,
                &active
            )
            .unwrap(),
            Incoming::Work { .. }
        ));
    }
    let Incoming::Reply(overloaded) = dispatch(
        Id::Integer(9),
        "tools/list",
        Value::Null,
        &mut state,
        &active,
    )
    .unwrap() else {
        panic!("expected active request limit");
    };
    assert_eq!(overloaded["error"]["data"]["code"], "RESOURCE_LIMIT");
    receive_notification(
        "notifications/cancelled",
        json!({"requestId":a}),
        &mut state,
        &active,
    )
    .unwrap();
    assert!(first.load(Ordering::Acquire));
    assert!(!second.load(Ordering::Acquire));
    drop(CancelActive(Arc::clone(&active)));
    assert!(second.load(Ordering::Acquire));
    assert_eq!(cancelled(&Id::Integer(2))["id"], 2);

    let input = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"wire-control","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fixed","arguments":{"x":1},"_meta":{"x":2}}}),
    ];
    let source = input
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let (send, receive) = mpsc::sync_channel(4);
    read_messages(std::io::Cursor::new(source), &send, &Active::default()).unwrap();
    assert!(matches!(receive.recv().unwrap(), Incoming::Reply(_)));
    let Incoming::Work {
        id,
        request: crate::agent_wire::Work::Call(call),
        cancel,
    } = receive.recv().unwrap()
    else {
        panic!("expected admitted raw call");
    };
    assert_eq!(id, Id::Integer(2));
    assert_eq!(call.name, "fixed");
    assert_eq!(call.arguments, json!({"x":1}));
    assert_eq!(call.metadata.unwrap()["x"], 2);
    assert!(cancel.load(Ordering::Acquire));
}

/// `T-TF-AGENT-INTEGRATION-0001-R01-006`
/// Fortress requirement: TF-AGENT-INTEGRATION-0001-R01
#[test]
fn frames_that_do_not_terminate_are_bounded() {
    let mut incomplete = std::io::Cursor::new(b"{");
    let frame = read_frame(&mut incomplete, Some(2 * MAX_REQUEST_BYTES))
        .unwrap()
        .unwrap();
    assert_eq!(frame.unwrap_err().code, "TRUNCATED_FRAME");
    let mut endless = std::io::Cursor::new(vec![b'x'; 3 * MAX_REQUEST_BYTES]);
    let frame = read_frame(&mut endless, Some(2 * MAX_REQUEST_BYTES))
        .unwrap()
        .unwrap();
    assert_eq!(frame.unwrap_err().code, "DISCARD_LIMIT");

    let mut response = Vec::new();
    write_response(
        &mut response,
        &json!({"id":25,"result":"x".repeat(3 * 1024 * 1024)}),
    )
    .unwrap();
    let response: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(response["id"], 25);
    assert_eq!(response["error"]["data"]["code"], "RESOURCE_LIMIT");
}
