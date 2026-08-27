# Info

## Role

Persist computational output whose exact content is required for reproducible repository operation.

## Production

Cargo is the authoritative producer and resolves declared package constraints into the persisted lock record.

## Semantics

The output identifies one exact dependency resolution; it supports reproducible dependency selection but does not become authored standard or project authority.

## Lifecycle

Cargo regenerates or replaces the output when dependency inputs change; build products remain transient outside the repository and stale lock content is not hand-authored.

## Files

### [`Cargo.lock`](../info/Cargo.lock)

Records Cargo-produced exact dependency resolution for reproducible builds under the configured external lockfile path.
