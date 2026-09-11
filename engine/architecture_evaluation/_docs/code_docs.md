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

### [`architecture.rs`](../_code/architecture.rs)

Derives physical Module ownership and component views from the canonical CCG, then evaluates its declared dependency graph without rebuilding semantic resolution.

### [`diagnostics.rs`](../_code/diagnostics.rs)

Builds deterministic production Module profiles, computes physical lowest common ancestors, and derives non-normative scope, isolation, consumer-distribution, and facade-pressure diagnostics with content-addressed provenance.

### [`realization.rs`](../_code/realization.rs)

Reconciles independent observed Module dependencies with exact direct CCG authorization, preserves all realization states, and normalizes hard architecture findings.

### [`semantic_conformance.rs`](../_code/semantic_conformance.rs)

Computes exact Module source-to-PSM-symbol coverage, compares Module Contract semantic policy with canonical direct/transitive State/Effect consequences, derives scoped defeating and limiting evidence from current coverage, call, operation-classification, and execution-provenance facts, preserves proven violations despite unrelated uncertainty, emits evidence-complete findings without inferring permission, and retains a presentation-only stable-symbol-to-qualified-name index without changing canonical machine identity. `DROPPED_OPERATION` is not emitted because the current PSM has no independent syntax-call inventory against which absence from semantic call outcomes can be proved; unresolved calls already present in the PSM become `UNRESOLVED_CALL_PATH`, while calls absent before PSM construction remain outside truthful detection until call observation authority expands.
