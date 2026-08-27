# Testing

## Purpose

Provide parent-local evidence that Program Semantics truthfully models supported Rust execution structure.

## Responsibility

Verify every requirement introduced directly by Program Semantics with deterministic positive, negative, boundary, coherency, and live-repository cases.

## Scope

### Includes

Free functions, associated functions, inherent and trait methods, typed interfaces, generics, call resolution states, aliases, re-exports, recursion, SCCs, transfers, Module ownership, Testing classification, snapshot identity, canonical bytes, digesting, and Implementation Observation consistency.

### Excludes

Verification of authored architecture, intended behavior, function correctness, refinement domains, effects, realized behavior, and semantic classes deliberately unsupported by PSM v1.

## Relationships

### [Engine](../../../../README.md)

**Types:** `depends_on`

Provides the public `fortress-core` crate facade through which the verification target is executed.

### [Program Semantics](../../README.md)

**Types:** `depends_on`, `verifies`

Consumes the production analyzer and verifies exactly the Feature requirements owned by its immediate parent Module.

## Guarantees

Fixtures assert exact semantic outcomes and coverage states, preserve parent-local Test IDs, and do not reinterpret unsupported resolution as successful analysis.
