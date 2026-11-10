# Code

## Role

Verify Finding Model requirements at the immediate parent Testing boundary.

## Execution

Cargo runs the explicit `proof_contract` integration target against synthetic evidence identities, proof graphs and neutral lifecycle records.

## State

All fixtures are process-local and deterministic.

## Failure Semantics

Any accepted malformed graph or rejected valid graph fails its owning Test ID.

## Files

### [`proof_contract.rs`](../_code/proof_contract.rs)

Exercises acyclicity, reference resolution, canonical ordering, and nonempty support, all nine accepted true/false/unknown pairs for both ALL and ANY, preservation of Boolean sufficiency, omitted states and foreign evidence refusal.

### [`lifecycle.rs`](../_code/lifecycle.rs)

Directly verifies neutral admission and retirement bindings, monotonic baseline maintenance, original history, reintroduction, explicit exception review time and refusal of reference-only authorization. Synthetic metadata records exercise validation without claiming a semantic proof or importing State Governance.
