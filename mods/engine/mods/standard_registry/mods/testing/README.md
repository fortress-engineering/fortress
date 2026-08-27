# Standard Registry Testing

## Purpose

This verification Module exists to prove only the Standard Registry Feature introduced directly by its immediate parent Module.

## Responsibility

Exercise stable IDs, schemas, and draft registry metadata while mapping every result exclusively to parent-owned requirements.

## Scope

### Includes

Rust verification targets and direct specification-authored fixtures providing evidence for the immediate parent's local Feature.

### Excludes

Ancestor, sibling, or descendant Feature requirements; normative rule meaning; production registry implementation; and whole-repository audit orchestration.

## Relationships

### [Engine](../../../../README.md)

**Types:** `depends_on`

Executes as a separate Rust test crate through the Engine package facade while proving the narrower parent-owned Feature.

### [Standard Registry](../../README.md)

**Types:** `depends_on`, `verifies`

Exercises the parent registry boundary and its stable identity and schema invariants.

## Guarantees

Verification is deterministic, fixture-driven, and subordinate to the Standard Registry contracts it checks.
