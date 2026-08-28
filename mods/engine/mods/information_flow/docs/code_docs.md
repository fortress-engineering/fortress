# Code

## Role

The directly owned Code validates project flow algebra and derives interprocedural security classifications, findings, diagnostics, coverage, and canonical Info.

## Execution

Policy loading occurs before analysis. Analysis builds on canonical PSM transfers and bodies, applies declared sources, reaches a deterministic fixed point, applies explicit trusted transitions, and checks declared sinks.

## State

Execution is process-local and deterministic; finite maps and sets are rebuilt from snapshot-bound semantic inputs for each analysis.

## Failure Semantics

Invalid policy or flow contracts return typed errors, supported sink contradictions become normalized findings, and unknown or unsupported flow remains explicit coverage rather than success.

## Files

### [`information_flow.rs`](../code/information_flow.rs)

Owns label propagation, interprocedural and field-flow derivation, sink checking, trusted-transition diagnostics, artifact serialization, and rule-facing findings.

### [`policy.rs`](../code/policy.rs)

Owns canonical project policy loading, finite facet ordering, validation, and policy digest identity.
