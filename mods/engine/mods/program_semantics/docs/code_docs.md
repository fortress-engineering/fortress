# Code

## Role

The Code defines the language-neutral PSM and the Rust-specific translator that emits nominal type, impl, executable, typed-expression, call, neutral body/control, transfer, derivation, coverage, coherency, and provenance facts.

## Execution

The orchestrator verifies snapshot-bound bytes, derives Cargo package and target contexts, builds a workspace-wide nominal/interface/impl index, propagates supported local static types, resolves only unique type-directed call targets, derives graph and transfer topology, reconciles cross-Module calls with Implementation Observation, and serializes canonical output. The pinned stable toolchain exposes neither stable rustdoc JSON/HIR nor a pinned rust-analyzer component, so v2 uses snapshot-bound Cargo interpretation and structural `syn` semantics while labeling every conclusion by authority and every residual call by a stable reason.

## State

Analysis is stateless beyond deterministic process-local indexes built from one immutable input set.

## Failure Semantics

Snapshot mutation, malformed supported source, missing ownership, or analyzer disagreement returns a typed error. Ambiguous or unsupported language semantics remain explicit coverage facts instead of failures or invented exact targets.

## Files

### [`graph.rs`](../code/graph.rs)

Derives deterministic call adjacency, reachability, strongly connected components, recursion, entry/leaf facts, and cross-boundary projections.

### [`program.rs`](../code/program.rs)

Defines canonical language-neutral PSM v3 types, nominal and impl facts, structured places and mutations, input/output boundaries, canonical serialization, digests, resolution/coverage summaries, and analyzer coherency.

### [`rust.rs`](../code/rust.rs)

Translates snapshot-bound Cargo manifests and structurally parsed Rust declarations, nominal types, impls, explicit signatures, supported expression types, calls, and transfers into the language-neutral PSM. It resolves unique inherent and concrete trait implementation methods from proven receiver types, classifies known external ownership, and preserves ambiguity, dynamic dispatch, macros, custom dereference, and missing type information as explicit residual states.
