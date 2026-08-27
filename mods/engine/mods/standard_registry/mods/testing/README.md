# Standard Registry Testing

## Purpose

This verification Module exists to prove stable identity behavior and registry coherence against independently authored conformance inputs.

## Responsibility

Exercise valid, invalid, and boundary stable IDs; validate schema identities and references; and prove exact agreement between the draft manifest and implemented registry.

## Scope

### Includes

Rust verification targets and direct specification-authored identity fixtures and expected findings.

### Excludes

Normative rule meaning, production registry implementation, and whole-repository audit orchestration.

## Relationships

### [Standard Registry](../../README.md)

**Types:** `depends_on`, `verifies`

Exercises the parent registry boundary and its stable identity and schema invariants.

## Guarantees

Verification is deterministic, fixture-driven, and subordinate to the Standard Registry contracts it checks.
