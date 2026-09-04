# Code

## Role

Turn implemented Engine behavior into validated native command execution and deterministic presentation.

## Execution

The native entrypoint delegates arguments to the CLI library, which resolves the command registry, validates options, invokes Engine behavior, renders the selected format, and returns a process status. Local certification runs the unfiltered Rust suite with an absolute Cargo target outside the governed repository, then emits content-addressed evidence for lightweight hosted freshness/stamp verification.

## State

Command execution is process-local; repository audit state is loaded for one invocation and no persistent job state is created.

## Failure Semantics

Malformed input, unsupported operations, invalid repository state, or evaluated rule failure returns non-success with an explicit diagnostic; no failure becomes a certification claim.

## Files

### [`command.rs`](../code/command.rs)

Defines the stable built-in command registry and rejects duplicate or unimplemented command contracts.

### [`lib.rs`](../code/lib.rs)

Dispatches supported arguments, invokes raw audit and progressive finding checks, performs explicit baseline/exception authority mutation, renders declared Module and analysis-territory ownership, explains exact-snapshot affected closure, reuses only verified dependency-bound projection bytes, invokes semantic projections and local full-snapshot certification, and assigns process status without conflating conformance with enforcement.

### [`main.rs`](../code/main.rs)

Provides the native process entrypoint and delegates all command behavior to the CLI library.
