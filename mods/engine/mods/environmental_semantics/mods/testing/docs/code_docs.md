# Code

## Role

The test Code proves the Environmental Semantics Feature requirements at the immediate parent boundary.

## Execution

Cargo invokes the explicit environmental_semantics target against synthetic PSM-backed contracts and the live Fortress repository.

## State

Fixtures use deterministic process-local semantic models and do not persist mutable test state.

## Failure Semantics

Any contract, outcome, retry, duplicate, recovery, finding, scenario, coverage, determinism, or freshness mismatch fails its mapped test.

## Files

### [`environmental_semantics.rs`](../code/environmental_semantics.rs)

Exercises Environment Contract validation, handling totality, completion certainty, retry/idempotency, duplicate delivery, interruption/recovery, fault scenarios, normalized findings, and live integration.
