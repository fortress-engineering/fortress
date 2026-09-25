# Info

## Role

Persist root ecosystem resolution authority that remains part of project architecture. Durable Fortress assessment output is stored in immutable generations under `__fortress/evidence`; large deterministic projections remain externally materialized.

## Production

Cargo produces the resolver lock record from package constraints. Fortress producers emit generated assessment artifacts into a leased staging area, Certification validates their registered schemas, and Snapshot Governance publishes a complete content-addressed generation before updating the current selection index.

## Semantics

`_info/Cargo.lock` identifies one exact dependency resolution and remains project Info. Generated Intended BFG, Environmental Analysis, component resolution index, Evidence Graph, Certification result, Verified BFG, and quality certificate are immutable control-generation members. The CCG, PSM, Semantic Analysis, State/Effect Analysis, Module Semantic Conformance, Information Flow Analysis, Realized BFG, and Source Artifact Model are external logical artifacts whose exact IDs, sizes, and digests are bound by the selected manifest and certificate.

The source fingerprint excludes the generated evidence subtree while explicitly including `__fortress/.fsconfig`, active governance, every authored contract, source, schema, documentation file, workspace input, and `Cargo.lock`, regardless of Git ignore state. Generated integrity and subject freshness are validated separately. SHA-256 stamps are tamper-evident and do not establish issuer authenticity.

## Lifecycle

Cargo regenerates the lock record when dependency inputs change. Maintainers run `python engine/snapshot_governance/_code/quality_certificate.py issue .` through the storage supervisor. Issuance executes the canonical gate set, writes an immutable generation, and compare-and-replaces `__fortress/evidence/current.json` last. Verification resolves the exact selection and rejects missing, stale, corrupt, ambiguous, or unregistered content without searching for a different green generation.

Bulk artifacts may be materialized in an external cache keyed by exact source fingerprint. `artifact-status` distinguishes `CURRENT`, `MISSING`, `STALE`, and `INVALID`; absence never becomes favorable evidence. Historical generations remain evidence about their recorded subjects and are not automatically current.

## Files

### [`Cargo.lock`](../_info/Cargo.lock)

Records Cargo-produced exact dependency resolution for reproducible builds under the configured external lockfile path.
