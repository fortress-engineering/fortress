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

### [`information_flow.rs`](../_code/information_flow.rs)

Owns label propagation, interprocedural and field-flow derivation, sink checking, trusted-transition diagnostics, artifact serialization, and rule-facing findings.

Binding-identity edges use a request-local borrowed index of argument, expression and place nodes keyed by the complete symbol identity and exact binding name. Matching candidates retain the original sorted-node order and both edge directions. Same-named bindings in other symbols remain separate. Every edge, propagation round, trusted transition and sink check still executes; no graph or fixed-point result is reused across analyses.

### [`policy.rs`](../_code/policy.rs)

Owns canonical project policy loading, finite facet ordering, validation, and policy digest identity.

### [`operation.rs`](../_code/operation.rs)

Defines strict bounded operation declarations, exact context/name/slot binding, finite-facet source and transform lowering, per-sink coverage and canonical defeaters, explicit profile scope, and read-only authoring previews. It reuses the parent propagation algebra and PSM facts. Declared transformation trust remains conditional and cannot self-authenticate.

The read-only operation-profile and claim-projection ports expose the same ordered records as the complete model serializer. Snapshot Governance checks profile selection before projecting claims and serializes only those records or trusted-transition diagnostics needed by its adapter. This avoids materializing unrelated propagation graphs without evaluating, filtering or strengthening a claim. The focused projection regression compares these ports with the complete canonical model for both selected and unselected operation profiles.

### [`native_scalar_flow.rs`](../_code/native_scalar_flow.rs)

Projects source-site data references for one admitted native scalar body by
reusing the existing Information Flow body-edge and expression-source helpers.
Assignment and return edges retain the exact enclosing occurrence identity
and source position. Earlier assignments still have source sites after an
overwrite. Condition records show which bindings occur in the guard, while
actual control influence remains unsupported. The projection stays outside the
canonical operation lanes. Empty edge lists, partial coverage, missing
bodies and resource refusals confer no classification, proof or policy result.
