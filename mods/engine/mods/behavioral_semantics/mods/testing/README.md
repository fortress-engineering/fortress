# Behavioral Semantics Testing

## Purpose

This verification Module exists to prove only the Behavioral Semantics Feature introduced directly by its immediate parent Module.

## Responsibility

Exercise Intended BFG compilation and BEHAVIOR-FLOW-001 across linear, branching, looping, contradictory, distributed, deterministic, provenance-preserving, and live Fortress behavior while mapping evidence exclusively to parent-owned requirements.

## Scope

### Includes

Rust verification code; synthetic Contract v2 ecosystems; exact local, CCG, and BFG failure assertions; canonical serialization and digest checks; graph derivation checks; self-BFG freshness; and live Fortress audit-flow compilation.

### Excludes

Ancestor, sibling, or descendant Feature requirements; production contract authority; observed implementation behavior; call, value, state, or effect analysis; visualization; and evidence that intended checkpoints execute.

## Relationships

### [Behavioral Semantics](../../README.md)

**Types:** `depends_on`, `verifies`

Exercises the parent compiler and rule projection while verifying its complete locally owned Feature.

### [Contract Coherency](../../../contract_coherency/README.md)

**Types:** `depends_on`

Compiles authoritative synthetic Contract v2 declarations into CCG fixtures used as Behavioral Semantics inputs.

### [Engine](../../../../README.md)

**Types:** `depends_on`

Executes the verification target through the Engine package facade without transferring ownership of the Feature under test.

## Guarantees

Fixtures assert exact semantic outcomes, deterministic bytes and digests, complete provenance, legal loop handling, and explicit unmodeled states without using implementation output as normative expected authority.
