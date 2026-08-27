# Architecture Evaluation

## Purpose

Architecture Evaluation exists to interpret canonical CCG dependency and containment facts as architecture rule evidence without rebuilding contract semantics or duplicating filesystem authority.

## Responsibility

Consume the Contract Coherency Graph, derive physical ownership views for stabilized repository paths, and evaluate declared capability dependency cycles using canonical findings.

## Scope

### Includes

CCG Module containment and dependency facts, derived physical path ownership, component projections, and ARCH-DEPENDENCY-001 evaluation.

### Excludes

Contract parsing or semantic compilation, repository observation, physical containment authority, source dependency extraction, constraint satisfiability, Snapshot Governance aggregation, and terminal presentation.

## Relationships

### [Contract Coherency](../contract_coherency/README.md)

**Types:** `depends_on`

Supplies the one canonical semantic dependency and containment model consumed by architecture projections and cycle evaluation.

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Uses operational project-model boundaries without treating project configuration as architectural authority.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Uses stable identities and the governing dependency rule contract.

## Guarantees

Architecture views preserve the CCG distinction between containment and dependency, never infer capability re-export, assign observed paths to the deepest containing Module, and report dependency cycles deterministically without owning a competing resolved-contract model.
