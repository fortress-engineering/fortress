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

### [`identity.rs`](../code/identity.rs)

Validates canonical stable entity and rule identities under the registered Fortress namespaces.

### [`standard.rs`](../code/standard.rs)

Loads the exact draft manifest and complete rule-document bundle while rejecting registry disagreement.
