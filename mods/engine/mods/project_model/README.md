# Project Model

## Purpose

The Project Model exists so Fortress evaluates explicit project claims rather than inferring identity, standard applicability, feature ownership, or required evidence from incidental source layout.

## Responsibility

Load and validate typed project, feature, requirement, change, command-reference, and certification declarations with stable identities and canonical repository-relative paths.

## Scope

### Includes

Project standard claims, model pointers, feature and requirement ownership, supported evidence references, observation exclusions, and schema contracts for current declaration families.

### Excludes

Normative standard meaning, observed repository facts, architecture rule findings, and generated certification evidence.

## Relationships

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Uses stable Fortress identity and standard-claim semantics when validating project declarations.

## Guarantees

Declarations reject invalid or duplicate identities, unsafe paths, inconsistent evidence references, and malformed standard claims before evaluation.
