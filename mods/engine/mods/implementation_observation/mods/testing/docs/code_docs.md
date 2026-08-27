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

### [`implementation_observation.rs`](../code/implementation_observation.rs)

Exercises stable snapshot binding, Rust syntax/reference classes, namespace and facade resolution, ownership, edge collapse, explicit coverage, and deterministic repetition.
