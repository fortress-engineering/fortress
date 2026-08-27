# Architecture Evaluation

## Purpose

Architecture Evaluation exists to interpret canonical CCG dependency and containment facts as architecture rule evidence without rebuilding contract semantics or duplicating filesystem authority.

## Responsibility

Consume the Contract Coherency Graph and independent Implementation Observation, derive physical ownership views, evaluate declared capability dependency cycles, and reconcile observed direct source dependencies with intended architecture using canonical findings.

## Scope

### Includes

CCG Module containment, direct dependency and reachability facts; observed Rust Module dependencies and evidence; derived physical path ownership; component projections; ARCH-DEPENDENCY-001 evaluation; and ARCH-REALIZATION-001 reconciliation.

### Excludes

Contract parsing or semantic compilation, repository byte observation, physical containment authority, language source extraction, capability-to-symbol realization, semantic restructuring advice, Snapshot Governance aggregation, and terminal presentation.

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

Architecture views preserve the distinctions among containment, declared dependency, reachability, and observed access; never infer capability re-export or capability realization; assign observed paths to the deepest containing Module; and report cycles, unauthorized edges, and transitive bypasses deterministically without owning competing intent or observation models.
