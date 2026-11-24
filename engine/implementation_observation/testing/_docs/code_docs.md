# Code

## Role

Provide direct verification evidence for the deterministic Rust observation behavior owned by the immediate parent.

## Execution

Cargo invokes the explicit test target, which builds snapshot-bound in-memory repositories, runs the public analyzer, and asserts exact observations, normalized edges, provenance, issue classes, and mutation rejection.

## State

Verification is stateless and retains only process-local fixture bytes and results.

## Failure Semantics

Any parse, resolution, ordering, ownership, or identity discrepancy fails the test target with the exact assertion; tests never suppress unsupported or unresolved facts.

## Files

### [`implementation_observation.rs`](../_code/implementation_observation.rs)

Exercises stable snapshot binding, Rust syntax/reference classes, namespace and facade resolution, ownership, edge collapse, explicit coverage, and deterministic repetition.

The native dependency controls in the same test target use independently fixed Go and Python source occurrences and exact authored ownership. They assert direction, complete Go package membership, static Python scope, determinism, conflicting ownership, unavailable endpoints, forged context, stale bytes, conflicting observations, path coordinates, and resource limits. The adapter also covers analysis-only scaffolding in an owner-local control.
