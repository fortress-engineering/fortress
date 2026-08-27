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

Derives physical Module ownership and component views from the canonical CCG, then evaluates its declared dependency graph without rebuilding semantic resolution.

### [`diagnostics.rs`](../code/diagnostics.rs)

Builds deterministic production Module profiles, computes physical lowest common ancestors, and derives non-normative scope, isolation, consumer-distribution, and facade-pressure diagnostics with content-addressed provenance.

### [`realization.rs`](../code/realization.rs)

Reconciles independent observed Module dependencies with exact direct CCG authorization, preserves all realization states, and normalizes hard architecture findings.
