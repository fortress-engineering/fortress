# Code

## Role

Compile distributed behavioral intent preserved by the CCG into canonical per-Feature flow semantics and normalized modeled-flow findings.

## Execution

Callers provide one coherent immutable CCG. The compiler indexes checkpoints by Feature, builds canonical adjacency, derives reachability, SCC, boundary, dominator, and post-dominator facts, normalizes contradictions, and serializes the complete intended view without enumerating trigger-to-terminal paths.

## State

Execution is stateless beyond deterministic process-local graph indexes and derived collections.

## Failure Semantics

Missing root interpretation, canonical serialization failure, or finding normalization returns an explicit typed error. Graph contradictions remain represented in the BFG and become BEHAVIOR-FLOW-001 findings rather than causing a crash.

## Files

### [`behavior.rs`](../code/behavior.rs)

Defines Intended BFG v1 types, compilation, graph algorithms, provenance, deterministic serialization and digesting, modeling states, and BEHAVIOR-FLOW-001 normalization.
