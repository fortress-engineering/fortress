# Code

## Role

The Code owns canonical authority-input classification, affected dependency units, exact-snapshot comparison, deterministic closure, projection dependency keys, and verified machine-local content reuse.

## Execution

Callers construct exact dependency snapshots from existing Fortress semantic identities. The resolver compares stable units, propagates affectedness through indexed reverse dependencies, and admits cached bytes only after exact key and digest verification.

## State

All graph and cache identities are derived from canonical repository-relative paths, stable semantic identities, exact content digests, and explicit generator versions. Cache directories and execution-local paths never enter serialized authority.

## Failure Semantics

Malformed identities and graphs return typed errors. Cache metadata or content corruption yields an explicit `INVALID` state. A missing prior key is `MISSING`; a different latest key is `STALE`; neither can supply bytes.

## Files

### [`affected.rs`](../code/affected.rs)

Defines the affected dependency model, exact input change classes, conservative invalidation closure, deterministic inspection output, dependency-complete projection keys, and verified machine-local reuse lifecycle.
