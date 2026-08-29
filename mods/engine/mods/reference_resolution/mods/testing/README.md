# Reference Resolution Testing

## Purpose

Verify relocation transparency against focused and large deterministic repository models.

## Responsibility

Exercise canonical identity resolution, reference classification, Markdown generation, Rust/Cargo path boundaries, subtree relocation, bounded churn, and live Fortress reference audit behavior.

## Scope

### Includes

Parent-local conformance, negative physical-coupling fixtures, idempotence, deterministic digests, upward and downward moves, and hundreds-of-Modules stress models.

### Excludes

Production reference authority, automatic filesystem mutation, package publishing, temporal history, and non-Rust import adapters.

## Relationships

### [Engine](../../../../README.md)

**Types:** `depends_on`

Supplies the composed public Rust facade used by black-box conformance tests.

### [Reference Resolution](../../README.md)

**Types:** `depends_on`, `verifies`

Supplies the implementation under test and owns the Feature verified by this canonical Testing boundary.

## Guarantees

Every declared test is deterministic, uses stable synthetic identities, and asserts exact relocation or finding outcomes without mutating the live repository hierarchy.
