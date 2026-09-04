# Affected Analysis

## Purpose

Determine which exact-snapshot semantic and governance results a repository change can invalidate, and which content-addressed results remain provably reusable.

## Responsibility

Compile stable authority and derived-unit dependencies into one deterministic affected graph, propagate invalidation conservatively with explicit reasons, and verify machine-local reusable projection bytes against their complete semantic input bindings.

## Scope

### Includes

Repository-input change classification, semantic dependency closure, recomputation reasons, projection dependency keys, verified machine-local reuse states, deterministic serialization, and cache-independent reconstruction.

### Excludes

Public temporal governance, historical meaning comparison, policy-strengthening judgments, semantic inference, external artifact services, and treating cache material as authority.

## Relationships

### [Architecture Evaluation](../architecture_evaluation/README.md)

**Types:** `depends_on`

Supplies Module semantic-conformance identities whose dependencies can be invalidated without reinterpreting policy.

### [Certification](../certification/README.md)

**Types:** `depends_on`

Supplies certification-obligation and evidence identities while continuing to bind final artifacts to the exact evaluated snapshot.

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Supplies stable finding identities kept separate from finding-governance enforcement authority.

### [Implementation Observation](../implementation_observation/README.md)

**Types:** `depends_on`

Supplies deterministic observed source ownership used to bind source and Module dependencies.

### [Program Semantics](../program_semantics/README.md)

**Types:** `depends_on`

Supplies stable symbol and call identities for conservative semantic propagation.

### [Repository Observation](../repository_observation/README.md)

**Types:** `depends_on`

Supplies exact repository-relative input paths and content identities.

### [Source Architecture](../source_architecture/README.md)

**Types:** `depends_on`

Supplies source-artifact identities and source-profile dependency boundaries.

### [State and Effect Analysis](../state_effect_analysis/README.md)

**Types:** `depends_on`

Supplies causal effect and capability consequences that propagate through proven call relationships.

## Guarantees

Reuse is accepted only when generator identity, semantic-version identity, complete dependency bindings, descriptor bytes, artifact bytes, and content digest all verify. Missing, stale, or invalid material never becomes current evidence, and removing the entire cache changes runtime only.
