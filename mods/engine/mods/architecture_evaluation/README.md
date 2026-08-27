# Architecture Evaluation

## Purpose

Architecture Evaluation exists to validate declared architectural ownership and dependency meaning separately from observed source dependencies and physical Module containment.

## Responsibility

Load typed zones, components, paths, artifacts, dependencies, and Module contracts, then evaluate declared dependency cycles using canonical findings.

## Scope

### Includes

Architecture and Module-contract schemas, declared component graph validation, explicit repository artifact classification, typed Module relationships, and ARCH-DEPENDENCY-001 evaluation.

### Excludes

Repository observation, filesystem placement inference, source dependency extraction, Snapshot Governance aggregation, and terminal presentation.

## Relationships

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Uses project-declared identity and path conventions when interpreting architecture inputs.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Uses stable identities and the governing dependency rule contract.

## Guarantees

Unknown targets, duplicate paths or relationships, self-relationships, invalid identities, and prohibited declared cycles fail deterministically without treating dependency as containment.
