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

### [`program_semantics.rs`](../_code/program_semantics.rs)

Contains the complete parent-local PSM v5 conformance and self-application suite.

### [`program_preparation.rs`](../_code/program_preparation.rs)

Verifies R09-001 through R09-008: cold/prepared canonical equality and actual reuse; exact borrowed-input descriptor equality with canonical provenance; changed-file body and shifted-span rebuilding; removal of type contributions; unresolved-to-resolved declaration invalidation; context, ownership, import and destructor fallback; repeated-call deletion and recursive graph changes; malformed-input error parity; and one thousand deterministic owner-level mutation comparisons. These PSM comparisons supplement the whole production-bundle controls owned by Snapshot Governance.
