# Project Model

## Purpose

The Project Model exists to hold operational project configuration that is neither architectural intent nor safely derivable from the repository grammar.

## Responsibility

Load and validate root operational configuration plus the remaining change and certification record schemas owned by the project-model boundary.

## Scope

### Includes

Observation exclusions and schema contracts for operational project, change, and certification record families.

### Excludes

Module identity, standard selection, capability and Feature authority, physical containment, observed repository facts, and generated certification evidence.

## Relationships

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Uses stable Fortress identity and standard semantics when validating governed configuration and record families.

## Guarantees

Operational configuration rejects unsafe or duplicate observation paths, while retained record schemas preserve explicit stable identities.
