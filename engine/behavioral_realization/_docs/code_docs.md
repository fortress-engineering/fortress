# Code

## Role

The directly owned Code validates realization authority, builds semantic implementation events from already-compiled models, and reconciles those events with meaningful Intended BFG checkpoints.

## Execution

Contract loading resolves complete opt-in and exact anchor identity first. Realization then lowers supported program control and calls, composes state/effect, information-flow, and environmental events, derives next-checkpoint paths, checks intended dominators, and canonicalizes one Realized BFG.

## State

Execution is deterministic and process-local. Event graphs, reachability, edge states, bypasses, verification obligations, and digests derive only from immutable semantic inputs and distributed realization contracts.

## Failure Semantics

Invalid or incomplete realization authority returns typed errors, proven semantic contradictions become rule-specific findings, and incomplete implementation knowledge remains explicit partial, unknown, or unsupported coverage.

## Files

### [`realization.rs`](../_code/realization.rs)

Owns implementation-event derivation, coverage-aware checkpoint reachability, next semantic transitions, intended/realized reconciliation, dominator bypasses, findings, verification obligations, serialization, and digest identity.

### [`realization_contract.rs`](../_code/realization_contract.rs)

Owns canonical distributed Behavior Realization Contract v1 parsing, complete Feature opt-in, Module-local ownership, exact semantic anchor resolution, ordering, and distributed digest identity.

### [`event_graph.rs`](../_code/event_graph.rs)

Provides the private borrowed numeric event index used by repeated reachability queries. Before allocating, checked arithmetic conservatively charges the complete event/edge endpoint union, adjacency, collection overhead and one complete query scratch against 64 MiB. Refusal or arithmetic overflow selects the original string graph and BFS. This is optional temporary workspace within the existing process limits; no cache or global memory limit increases. The index borrows immutable IDs, orders numeric IDs exactly as their strings, preserves tuple neighbor order and first-visited coverage, and includes edge-only endpoints. Each query creates fresh state and returns the same owned witness strings. Unknown initial endpoints retain zero-hop semantics. The index is dropped before moving the completed event model; no analysis result is reused across evaluations.
