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

### [`feature.rs`](../code/feature.rs)

Loads feature, requirement, and test-evidence declarations and rejects invalid or duplicate references.

### [`project.rs`](../code/project.rs)

Loads project identity, pinned standard claim, model paths, capabilities, languages, and observation exclusions.
