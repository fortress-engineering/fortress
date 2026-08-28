# Code

## Role

The directly owned Code loads distributed environmental authority and derives outcome, retry, duplicate, interruption, recovery, coverage, finding, and fault-scenario semantics.

## Execution

Contract loading resolves exact PSM ownership and existing domain/state/flow identities before analysis. Analysis then evaluates each outcome independently, checks reachable continuations and supported effects, and aggregates only after outcome handling is established.

## State

Execution is process-local and deterministic; all maps, closures, summaries, and scenarios derive from snapshot-bound semantic inputs.

## Failure Semantics

Invalid authority returns typed errors, supported contradictions become rule-specific canonical findings, and incomplete external, timing, durability, or call semantics remain explicit coverage.

## Files

### [`environment_contract.rs`](../code/environment_contract.rs)

Owns canonical Environment Contract v1 parsing, local symbol/state/domain/flow resolution, ordering, and distributed digest identity.

### [`environmental.rs`](../code/environmental.rs)

Owns outcome totality, retry/idempotency, duplicate delivery, bounded interruption/recovery, fault-scenario derivation, artifact serialization, and three rule-facing finding sets.
