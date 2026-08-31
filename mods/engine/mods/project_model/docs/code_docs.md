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

### [`filing.rs`](../code/filing.rs)

Compiles the canonical recursive Project Filing System, validates Standard-owned ecosystem registrations and bounded Data/Info grammar, and retains complete deterministic leaf inventory outside the CCG.

### [`project.rs`](../code/project.rs)

Loads the root project configuration and validates canonical observation exclusions plus relocation-transparent logical Module contract and source bindings.
