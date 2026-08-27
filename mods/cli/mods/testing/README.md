# CLI Testing

## Purpose

This verification Module exists to prove process-level command discovery, version output, audit success and failure, malformed-state handling, deterministic JSON, and unsupported-input semantics.

## Responsibility

Invoke the built native binary against controlled arguments and disposable repositories, then verify exact output classes and process status.

## Scope

### Includes

Rust process-level verification code and runtime-created repositories scoped to each test invocation.

### Excludes

Provider-independent rule meaning, production command implementation, persisted fixture trees, and certification execution.

## Relationships

### [CLI](../../README.md)

**Types:** `depends_on`, `verifies`

Exercises the parent native command surface from the process boundary.

## Guarantees

Tests isolate runtime state, require deterministic machine output, and reject false success for malformed or unsupported operations.
