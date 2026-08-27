# Architecture Evaluation

## Purpose

Architecture Evaluation exists to resolve distributed Module intent into a deterministic ecosystem model and evaluate capability dependency meaning without duplicating filesystem authority.

## Responsibility

Load and validate Module Contract v2, resolve repository-wide capabilities and typed intent with provenance, derive physical ownership and dependencies, and evaluate dependency cycles using canonical findings.

## Scope

### Includes

Module-contract schema and canonical serialization, ecosystem identity indexes, capability resolution, constraint inheritance, guarantee and Feature ownership, behavioral checkpoint validation, derived dependency ownership, and ARCH-DEPENDENCY-001 evaluation.

### Excludes

Repository observation, physical containment authority, source dependency extraction, future semantic satisfiability analysis, Snapshot Governance aggregation, and terminal presentation.

## Relationships

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Uses operational project-model boundaries without treating project configuration as architectural authority.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Uses stable identities and the governing dependency rule contract.

## Guarantees

Unknown providers or targets, duplicate identities or edges, incompatible capability versions, invalid inherited obligations, incoherent behavior, and prohibited dependency cycles fail deterministically without treating dependency as containment.
