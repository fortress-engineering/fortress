# Code

## Role

The Code defines the language-neutral PSM and the Rust-specific translator that emits executable, interface, call, neutral body/control, transfer, derivation, coverage, coherency, and provenance facts.

## Execution

The orchestrator verifies snapshot-bound bytes, derives Cargo package and target contexts, indexes Rust declarations, resolves only provable call targets, derives graph and transfer topology, reconciles cross-Module calls with Implementation Observation, and serializes canonical output. The pinned stable toolchain exposes neither stable rustdoc JSON/HIR nor a pinned rust-analyzer component, so v1 deliberately uses snapshot-bound Cargo manifest interpretation and `syn` structure instead of claiming compiler-resolved expression semantics.

## State

Analysis is stateless beyond deterministic process-local indexes built from one immutable input set.

## Failure Semantics

Snapshot mutation, malformed supported source, missing ownership, or analyzer disagreement returns a typed error. Ambiguous or unsupported language semantics remain explicit coverage facts instead of failures or invented exact targets.

## Files

### [`graph.rs`](../code/graph.rs)

Derives deterministic call adjacency, reachability, strongly connected components, recursion, entry/leaf facts, and cross-boundary projections.

### [`program.rs`](../code/program.rs)

Defines canonical language-neutral PSM types, input/output boundaries, canonical serialization, digests, coverage summaries, and analyzer coherency.

### [`rust.rs`](../code/rust.rs)

Translates snapshot-bound Cargo manifests and structurally parsed Rust declarations, explicit signature types, calls, and transfers into the language-neutral PSM. Unique declaration paths may be structurally exact; inferred expression types, method dispatch, macro expansion, and other compiler-private semantics remain unresolved or unsupported.
