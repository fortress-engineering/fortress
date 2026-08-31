# Implementation Observation

## Purpose

Implementation Observation exists so Fortress can establish source-level architectural facts independently from the contracts that describe intended architecture.

## Responsibility

Analyze exact snapshot-bound implementation source with supported language semantics and emit deterministic, normalized dependency observations with precise provenance, without interpreting those observations as architectural authorization.

## Scope

### Includes

Language-neutral observation facts, snapshot content verification, explicit source ownership backed by physical Module containment, authored logical path binding, or analysis-only Cargo authority, structural Cargo target-role and Rust namespace analysis, normalized dependencies, deterministic evidence ordering, and explicit unsupported or unresolved coverage.

### Excludes

CCG compilation, dependency authorization, architecture findings, capability-to-symbol realization, non-Rust languages, call or control-flow graphs, runtime tracing, external-package governance, and restructuring recommendations.

## Relationships

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Consumes validated logical Module contract locations and source bindings without becoming authority for Module identity or Project Filing conformance.

## Guarantees

Equal snapshot bytes and analyzer semantics yield identically ordered observations; declared dependencies never influence what is observed; Cargo analysis territories never become authored Modules; Project Filing violations do not hide otherwise analyzable source; cross-package references preserve the package facade boundary; and mutation, unsupported semantics, and unresolved targets remain explicit.
