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

Derives physical Module ownership and capability dependency edges from the resolved contract ecosystem, then evaluates dependency cycles.

### [`module_contract.rs`](../code/module_contract.rs)

Parses canonical Module Contract v2 files and deterministically resolves ecosystem identities, capabilities, constraints, guarantees, Features, requirements, behavioral checkpoints, provenance, and digests.
