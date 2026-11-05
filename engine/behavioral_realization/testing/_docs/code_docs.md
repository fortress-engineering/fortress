# Code

## Role

The test Code proves the Behavioral Realization Feature requirements at the immediate parent boundary.

## Execution

Cargo invokes the explicit behavioral_realization target against canonical declarations, semantic-event and reconciliation assertions, and the live Fortress repository.

## State

Fixtures use deterministic immutable semantic models and do not persist mutable test state.

## Failure Semantics

Any contract, event, checkpoint, edge, decision, terminal, bypass, coverage, obligation, determinism, freshness, or live-realization mismatch fails its mapped test.

## Files

### [`behavioral_realization.rs`](../_code/behavioral_realization.rs)

Exercises complete realization authority, every semantic anchor class, event projection, next-checkpoint reconciliation, dominator bypasses, uncertainty, normalized findings, verification obligations, deterministic serialization, and live Fortress realization.

### [`lib.rs`](../_code/lib.rs)

The Cargo-declared `event_graph_paths` native test crate root imports the existing Core coverage type and compiles the actual parent-owned private index source. This preserves the existing Testing dependency and physical crate-root boundary.

### [`event_graph_paths.rs`](../_code/event_graph_paths.rs)

Checks 32,768 deterministic queries against an independent copy of the original string BFS, including Unicode, duplicates, cycles, multiple seeds, missing and edge-only endpoints, forbidden vertices and coverage ties. Separate controls check exact admission, refusal, empty/zero-hop behavior and arithmetic overflow before input consumption. These owner tests complement complete public realization and Session reuse/fallback controls; they do not substitute for authoritative certification.
