# Architecture Evaluation Testing

## Purpose

This verification Module exists to prove only the Architecture Evaluation Feature introduced directly by its immediate parent Module.

## Responsibility

Exercise the parent architecture projection, dependency evaluator, implementation reconciliation, and Module semantic-policy evaluator against canonical intent and independent observation/effect facts, mapping findings exclusively to parent-owned requirements.

## Scope

### Includes

Rust verification code, dependency fixtures, synthetic observation facts, and the live Fortress CCG projection providing evidence for the immediate parent's local Feature.

### Excludes

Ancestor, sibling, or descendant Feature requirements; README synchronization; production source extraction; CCG authority; and documentation evaluation owned elsewhere.

## Relationships

### [Architecture Evaluation](../../README.md)

**Types:** `depends_on`, `verifies`

Exercises the parent CCG architecture projection and ARCH-DEPENDENCY-001 evaluator.

### [Contract Coherency](../../../contract_coherency/README.md)

**Types:** `depends_on`

Builds exact CCG intent fixtures required to verify dependency and realization semantics.

### [Engine](../../../../README.md)

**Types:** `depends_on`

Executes as a separate Rust test crate through the Engine package facade while proving the narrower parent-owned Feature.

### [Implementation Observation](../../../implementation_observation/README.md)

**Types:** `depends_on`

Supplies independent observed-implementation facts used by reconciliation conformance cases.

### [Program Semantics](../../../program_semantics/README.md)

**Types:** `depends_on`

Supplies deterministic executable identity and ownership for semantic-conformance fixtures.

### [Repository Observation](../../../repository_observation/README.md)

**Types:** `depends_on`

Provides stabilized live file facts used by the self-architecture verification target.

### [Semantic Analysis](../../../semantic_analysis/README.md)

**Types:** `depends_on`

Supplies the canonical domain layer required by State/Effect fixture construction.

### [State and Effect Analysis](../../../state_effect_analysis/README.md)

**Types:** `depends_on`

Supplies refined direct/transitive effects and causal evidence compared with authored Module policy.

## Guarantees

The suite is deterministic, CCG projections preserve canonical dependency identities, and expected findings remain specification-authored rather than generated from implementation output.
