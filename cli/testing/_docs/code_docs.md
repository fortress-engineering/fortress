# Code

## Role

Exercise the Module responsibility through directly owned verification logic without becoming normative authority.

## Execution

Cargo invokes each explicit test target; the code loads direct fixtures or the governed repository, performs deterministic assertions, and terminates with process success or failure.

## State

Verification is stateless apart from process-local values and isolated disposable runtime repositories where a scenario requires filesystem behavior.

## Failure Semantics

A violated assertion or fixture-loading failure fails the test target and surfaces its exact subject; verification never suppresses production errors.

## Files

### [`cli.rs`](../_code/cli.rs)

Invokes the built binary against controlled arguments and disposable repositories to verify public process behavior.

The application-publication regression captures an actual native negative StateView from original Unicode source paths, verifies independent native and local fingerprint domains, rejects a local fingerprint masquerading as a native subject before writes, publishes and replays exact application bytes through the Python adapter, and requires completed owned storage cleanup. Read-only reporting does not execute the fixture's application code or manufacture a successful implementation suite.

### [`inspection.rs`](../_code/inspection.rs)

Verifies exact core/RPC result equivalence, registered commands, strict version and parameter failures, bounded framing recovery, UTF-8 errors and correlated read-only lifecycle observations.
