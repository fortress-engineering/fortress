# Code

## Role

The Code verifies deterministic affected closure and machine-local reuse integrity.

## Execution

Fixtures construct exact canonical dependency snapshots and isolated cache roots, then compare invalidation, reuse states, serialization, and recomputed bytes.

## State

All state is confined to per-test temporary directories and immutable in-memory fixtures.

## Failure Semantics

Assertions fail on under-invalidation, nondeterminism, false cache currency, unsafe relocation identity, or excessive graph traversal cost.

## Files

### [`affected_analysis.rs`](../code/affected_analysis.rs)

Exercises change classification, transitive semantic invalidation, policy and governance boundaries, cache verification, relocation transparency, byte identity, and ten-thousand-node stress.
