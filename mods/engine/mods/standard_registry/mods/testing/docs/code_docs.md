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

### [`registry_primitives.rs`](../code/registry_primitives.rs)

Verifies stable identity parsing and exact draft rule registry metadata at the Standard Registry boundary.

### [`schema_registry.rs`](../code/schema_registry.rs)

Checks schema identities and references plus agreement between the draft manifest and implemented rule registry.

### [`std_id_001.rs`](../code/std_id_001.rs)

Exercises valid, invalid, and minimum-boundary stable identities for STD-ID-001.
