# Code

## Role

Verify Finding Model requirements at the immediate parent Testing boundary.

## Execution

Cargo runs the explicit `proof_contract` integration target against synthetic evidence identities and proof graphs.

## State

All fixtures are process-local and deterministic.

## Failure Semantics

Any accepted malformed graph or rejected valid graph fails its owning Test ID.

## Files

### [`proof_contract.rs`](../_code/proof_contract.rs)

Exercises acyclicity, reference resolution, canonical ordering, and nonempty support.
