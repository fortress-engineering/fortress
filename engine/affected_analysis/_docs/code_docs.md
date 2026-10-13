# Code

## Role

The Code owns canonical authority-input classification, affected dependency units, exact-snapshot comparison, deterministic closure, projection dependency keys, and verified machine-local content reuse.

## Execution

Callers construct exact dependency snapshots from existing Fortress semantic identities, including defeater units between semantic observations and governed claims. The resolver compares stable units, propagates coverage, provenance, call-resolution, operation-classification, and authority changes through indexed reverse dependencies, and admits cached bytes only after exact key and digest verification.

## State

All graph and cache identities are derived from canonical repository-relative paths, stable semantic identities, exact content digests, and explicit generator versions. Cache directories and execution-local paths never enter serialized authority.

## Failure Semantics

Malformed identities and graphs return typed errors. Cache metadata or content corruption yields an explicit `INVALID` state. A missing prior key is `MISSING`; a different latest key is `STALE`; neither can supply bytes. Cache writes take a local lease and reject writes that exceed the configurable projection budget while preserving existing bytes. The cache does not reclaim unknown or potentially active data.

## Files

### [`affected.rs`](../_code/affected.rs)

Defines the affected dependency model, exact input change classes, conservative invalidation closure, deterministic inspection output, dependency-complete projection keys, and verified machine-local reuse lifecycle.

The neutral resident dependency index binds complete current input descriptors and owner-supplied successful, missed and unsupported query traces to existing PSM and affected-unit identities. The composition root supplies resolved Source, Authority, Availability or Unsupported roles and selected authority paths. The index validates coverage, preserves missed lookup buckets, computes current reverse invalidation, and distinguishes nonrecursive retained availability changes from semantic input changes. Incomplete or unsupported authority requires `FULL_REEVALUATION_REQUIRED`; only semantic owners decide whether their units can be reused. This Module does not import Project interpretation or parse Rust.

Input coverage reads the PSM's exact borrowed provenance descriptors, including typed Cargo and Rust roles. It retains every source digest and query coverage check without materializing the entire PSM as JSON. Exact call and global query checks use the existing complete query-key and result index; caller kind coverage retains its original caller-and-kind predicate.

Coverage checks use the already-built exact scoped query map and a request-local caller/kind set. Source path, caller, query kind, query text and complete ordered provider result retain their original equality rules. Multiple results and duplicate reads preserve the original existential matching behavior; an unrelated scope or mismatched result cannot supply missing coverage. Every input, body, call evidence and provider validation still executes. These indexes remove repeated full-trace searches and temporary query formatting inside those searches; they do not cache a prior validation result.
