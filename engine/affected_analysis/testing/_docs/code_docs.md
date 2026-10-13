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

### [`affected_analysis.rs`](../_code/affected_analysis.rs)

Exercises change classification, transitive semantic invalidation, policy and governance boundaries, cache verification, relocation transparency, byte identity, and ten-thousand-node stress.

### [`session_dependencies.rs`](../_code/session_dependencies.rs)

Verifies R05-001 through R05-006: complete real owner-query/input bindings, preserved missed-name buckets and new binders, current reverse closure for body changes, selected control authority versus retained availability, incomplete/unsupported descriptor fallback, and source/caller/current-unit identity validation.

The incomplete-coverage control changes each component of an otherwise valid call read independently. It requires conservative fallback for a mismatched source, caller, kind, query or result, while duplicate reads, alternate results and read ordering preserve the original exact existential coverage semantics.
