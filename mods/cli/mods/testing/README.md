# CLI Testing

## Purpose

This verification Module exists to prove only the CLI Feature introduced directly by its immediate parent Module.

## Responsibility

Invoke the built native binary against controlled arguments and disposable repositories, then map each result exclusively to a parent-owned CLI requirement.

## Scope

### Includes

Rust process-level verification code and runtime-created repositories that provide evidence for the immediate parent's local Feature.

### Excludes

Ancestor, sibling, or descendant Feature requirements; provider-independent rule meaning; production command implementation; persisted fixture trees; and certification execution.

## Relationships

### [Engine](../../../engine/README.md)

**Types:** `depends_on`

Supplies provider-independent contract and audit types directly used to build controlled CLI repository scenarios.

### [CLI](../../README.md)

**Types:** `depends_on`, `verifies`

Exercises the parent native command surface from the process boundary.

## Guarantees

Tests isolate runtime state, require deterministic machine output, and reject false success for malformed or unsupported operations.
