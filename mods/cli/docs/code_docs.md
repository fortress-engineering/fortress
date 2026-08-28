# Code

## Role

Turn implemented Engine behavior into validated native command execution and deterministic presentation.

## Execution

The native entrypoint delegates arguments to the CLI library, which resolves the command registry, validates options, invokes Engine behavior, renders the selected format, and returns a process status.

## State

Command execution is process-local; repository audit state is loaded for one invocation and no persistent job state is created.

## Failure Semantics

Malformed input, unsupported operations, invalid repository state, or evaluated rule failure returns non-success with an explicit diagnostic; no failure becomes a certification claim.

## Files

### [`command.rs`](../code/command.rs)

Defines the stable built-in command registry and rejects duplicate or unimplemented command contracts.

### [`lib.rs`](../code/lib.rs)

Dispatches supported arguments, invokes Engine audit, CCG, Intended BFG, PSM, semantic-domain, state/effect, information-flow, environmental, and Realized BFG behavior, renders output, and assigns process status.

### [`main.rs`](../code/main.rs)

Provides the native process entrypoint and delegates all command behavior to the CLI library.
