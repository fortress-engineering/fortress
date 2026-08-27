# Code

## Role

Realize the Module responsibility through directly owned provider-independent implementation.

## Execution

Callers invoke the public typed boundary; the Code validates inputs, performs its deterministic processing sequence, and returns a complete result or typed failure.

## State

Execution owns only process-local state unless an explicitly documented artifact is read; no hidden persistent service state is introduced.

## Failure Semantics

Invalid inputs and inability to fulfill the responsibility return explicit typed errors or canonical findings at the owning boundary.

## Files

### [`architecture.rs`](../code/architecture.rs)

Loads zones, components, ownership paths, artifact classes, and dependencies and evaluates declared cycles.

### [`module_contract.rs`](../code/module_contract.rs)

Loads stable Module identities and sorted typed outbound relationships without duplicating filesystem containment.
