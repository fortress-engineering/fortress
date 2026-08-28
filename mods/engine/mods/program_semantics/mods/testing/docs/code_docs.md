# Code

## Role

The Code proves the Program Semantics requirements at their immediate parent boundary.

## Execution

Cargo executes the explicit integration target against synthetic snapshot-bound repositories and the live Fortress repository.

## State

Tests use isolated in-memory inputs and temporary repositories only where filesystem invocation is essential; no persistent runtime state is owned.

## Failure Semantics

Any mismatch in exact identities, normalized types, coverage states, topology, transfers, provenance, deterministic bytes, digest, mutation handling, or analyzer coherency fails its owning Test ID.

## Files

### [`program_semantics.rs`](../code/program_semantics.rs)

Contains the complete parent-local PSM v2 conformance and self-application suite.
