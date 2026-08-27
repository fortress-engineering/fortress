# Contract Coherency Testing

## Purpose

Contract Coherency Testing exists to prove the semantic compiler behavior introduced directly by Contract Coherency.

## Responsibility

Verify Contract v2 compilation, provenance, dependency and constraint closure, contradiction detection, support topology, canonical serialization, graph digest stability, and Fortress self-CCG freshness at the immediate parent boundary.

## Scope

### Includes

Positive, negative, boundary, complex ecosystem, determinism, provenance, logical satisfiability, unsupported-semantics, and committed self-artifact checks for the parent Feature.

### Excludes

Architecture Evaluation behavior, Snapshot Governance orchestration, source dependency realization, BFG compilation, empirical certification evidence, and verification of Features owned by sibling or descendant Modules.

## Relationships

### [Contract Coherency](../../README.md)

**Types:** `depends_on`, `verifies`

Consumes the parent compiler and verifies exactly the Contract Coherency Feature introduced at that boundary.

### [Engine](../../../../README.md)

**Types:** `depends_on`

Executes as a separate Rust test crate through the Engine package facade while proving the narrower parent-owned Feature.

### [Snapshot Governance](../../../snapshot_governance/README.md)

**Types:** `depends_on`

Supplies the live stabilized audit orchestration used to regenerate and compare Fortress's committed self-CCG.

### [Standard Registry](../../../standard_registry/README.md)

**Types:** `depends_on`

Supplies exact standard bundle types and formal rule-logic validation used by compiler conformance fixtures.

## Guarantees

Fixtures remain deterministic, assert precise violations, and never present declared support topology as executed proof.
