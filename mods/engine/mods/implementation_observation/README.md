# Implementation Observation

## Purpose

Implementation Observation exists so Fortress can establish source-level architectural facts independently from the contracts that describe intended architecture.

## Responsibility

Analyze exact snapshot-bound implementation source with supported language semantics and emit deterministic, normalized dependency observations with precise provenance, without interpreting those observations as architectural authorization.

## Scope

### Includes

Language-neutral observation facts, snapshot content verification, physical Fortress Module source ownership, structural Cargo and Rust namespace analysis, governed and external target classification, normalized direct Module dependencies, deterministic evidence ordering, and explicit unsupported or unresolved coverage.

### Excludes

CCG compilation, dependency authorization, architecture findings, capability-to-symbol realization, non-Rust languages, call or control-flow graphs, runtime tracing, external-package governance, and restructuring recommendations.

## Relationships

This Module declares no outbound architectural relationships.

## Guarantees

Equal snapshot bytes and analyzer semantics yield identically ordered observations; declared dependencies never influence what is observed; cross-package references preserve the package facade boundary; and mutation, unsupported semantics, and unresolved targets remain explicit.
