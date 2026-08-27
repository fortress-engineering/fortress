# Behavioral Semantics

## Purpose

Behavioral Semantics exists to make explicitly authored Feature behavior mechanically intelligible without confusing intended flow with program execution.

## Responsibility

Compile CCG-preserved Contract v2 checkpoint declarations into deterministic Intended Behavioral Flow Graphs, validate graph-level coherency, derive explainable reachability, boundary, loop, dominator, and post-dominator facts, and preserve provenance for every conclusion.

## Scope

### Includes

Per-Feature intended flow compilation; explicit modeled, unmodeled, and incoherent states; distributed descendant-owned checkpoints; trigger and terminal reachability; decision viability; strongly connected component and loop interpretation; Module participation and boundary crossings; dominators and post-dominators; canonical serialization; and BEHAVIOR-FLOW-001 findings.

### Excludes

Contract parsing, architectural containment authority, source observation, function and call graphs, value or data flow, state and effect semantics, implementation realization, runtime evidence, visualization coordinates, natural-language satisfiability, and claims that intended behavior executes.

## Relationships

### [Contract Coherency](../contract_coherency/README.md)

**Types:** `depends_on`

Supplies the canonical distributed checkpoint declarations, Feature ownership, Module containment, source provenance, and source CCG digest from which intended behavior is derived.

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Supplies normalized normative evidence for contradictions in explicitly modeled Feature flows.

## Guarantees

Compilation is deterministic, snapshot-independent authored intent remains distinct from observed execution, loops remain legal when they can reach a terminal, every derived fact is explainable from contract provenance, unmodeled Features are never represented as passing modeled flows, and serialized graphs contain no timestamps, machine paths, presentation geometry, or implementation realization claims.
