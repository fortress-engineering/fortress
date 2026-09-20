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

Compiles Module Contract effect and capability entries against the pinned State/Effect catalog, preserving overridden authored entries while explicit effect policy wins. Binds disposition-independent claim slots to the current policy, context and governed universe; evaluates direct and transitive State/Effect witnesses with exact source coverage and relevant uncertainty. Raw semantic verdict, authorization and blocking eligibility remain separate. Findings retain operation-site identity across line drift and fan-in, with production-capable causal support preferred for enforcement. The stable-symbol-to-qualified-name index is presentation-only and does not change canonical machine identity. The PSM syntactic operation inventory records omissions and unsupported outcomes; claim coverage must account for its relevant barriers before a favorable result is issued.
