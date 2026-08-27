# Architecture Evaluation

## Purpose

Architecture Evaluation exists to judge declared and realized architecture against normative rules and to expose evidence-backed structural pressure that deserves review without turning interpretation into conformance law.

## Responsibility

Consume the Contract Coherency Graph and independent Implementation Observation, derive physical ownership and production Module profiles, evaluate declared capability dependency cycles, reconcile observed direct source dependencies with intended architecture using canonical findings, and derive deterministic non-normative diagnostics with complete evidence.

## Scope

### Includes

CCG Module containment, direct dependency and reachability facts; observed Rust Module dependencies and evidence; production and verification topology separation; derived physical path ownership; component projections; Module lowest common ancestor; architecture profiles; scope and consumer-distribution diagnostics; facade-pressure and internal-isolation diagnostics; ARCH-DEPENDENCY-001 evaluation; and ARCH-REALIZATION-001 reconciliation.

### Excludes

Contract parsing or semantic compilation, repository byte observation, physical containment authority, language source extraction, capability-to-symbol realization, automatic restructuring decisions, natural-language architectural inference, correctness claims about candidate placement, Snapshot Governance aggregation, and terminal presentation.

## Relationships

### [Contract Coherency](../contract_coherency/README.md)

**Types:** `depends_on`

Supplies the one canonical semantic dependency and containment model consumed by architecture projections and cycle evaluation.

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Supplies the canonical normalized evidence representation used for dependency and realization violations.

### [Implementation Observation](../implementation_observation/README.md)

**Types:** `depends_on`

Supplies independently derived Rust source relationships, ownership, provenance, and explicit analyzer coverage for reconciliation.

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Uses operational project-model boundaries without treating project configuration as architectural authority.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Uses stable identities and the governing dependency rule contract.

## Guarantees

Architecture views preserve five distinct authorities: the CCG supplies declared semantic intent, Implementation Observation supplies source-derived facts, Architecture Realization establishes intent/implementation agreement, Architecture Diagnostics interprets those facts non-normatively, and canonical findings represent only Standard violations. Profiles and diagnostics exclude CCG-identified Testing Modules from production placement inference, never infer capability re-export or realization, never read intent from names or prose, and preserve deterministic evidence, ordering, and fingerprints.
