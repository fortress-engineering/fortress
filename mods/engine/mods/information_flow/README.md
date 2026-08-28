# Information Flow

## Purpose

Information Flow exists to establish explainable security-relevant provenance and policy compatibility for values moving through the supported program model.

## Responsibility

Information Flow consumes canonical program, value-domain, state, and effect facts plus explicit project policy, propagates ordered facet classifications conservatively, and rejects supported flows that violate declared consumers.

## Scope

### Includes

This Module owns policy algebra, Function Contract flow interpretation, explicit value and field propagation, sink reconciliation, trusted-transition diagnostics, coverage, and deterministic derived information.

### Excludes

This Module excludes source parsing, architecture intent, behavioral intent, hard-coded sanitizer knowledge, complete implicit-flow proof, arbitrary alias analysis, and certification claims.

## Relationships

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Provides the normalized security finding representation used for supported sink contradictions.

### [Program Semantics](../program_semantics/README.md)

**Types:** `depends_on`

Provides canonical executable bodies, value transfers, calls, fields, reads, and mutations without security interpretation.

### [Semantic Analysis](../semantic_analysis/README.md)

**Types:** `depends_on`

Provides the value-domain result and input identity on which information-flow derivation is bound.

### [State and Effect Analysis](../state_effect_analysis/README.md)

**Types:** `depends_on`

Provides canonical state/effect consequences and field precision boundaries consumed by the information-flow layer.

## Guarantees

Information Flow preserves deterministic ordering and provenance, never improves trust or reduces confidentiality without explicit authority, retains opaque semantics as uncertainty, and never treats absence of a finding as comprehensive security proof.
