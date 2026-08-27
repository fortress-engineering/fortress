# Project Model Testing

## Purpose

This verification Module exists to prove only the Project Model Feature introduced directly by its immediate parent Module.

## Responsibility

Load direct JSON fixtures through the public Project Model boundary and map each result exclusively to parent-owned requirements.

## Scope

### Includes

Rust verification code plus direct operational configurations providing evidence for the immediate parent's local Feature.

### Excludes

Ancestor, sibling, or descendant Feature requirements; production configuration parsing; Module-contract architectural intent; and cross-capability self-model checks.

## Relationships

### [Engine](../../../../README.md)

**Types:** `depends_on`

Executes as a separate Rust test crate through the Engine package facade while proving the narrower parent-owned Feature.

### [Project Model](../../README.md)

**Types:** `depends_on`, `verifies`

Exercises the parent loader and its uniqueness and path-boundary invariants.

## Guarantees

Fixtures remain deterministic and verification never converts malformed operational project state into successful configuration.
