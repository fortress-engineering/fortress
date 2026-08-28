# Certification

## Purpose

Certification establishes whether sufficient current evidence supports every obligation in an exact certification profile for an exact repository source snapshot.

## Responsibility

Certification constructs immutable content-addressed evidence nodes, validates their dependency DAG, binds current rule proofs and executed verification to obligations, evaluates deterministic certification status, and projects Intended and Realized behavior into the Verified BFG.

## Scope

### Includes

This Module owns Evidence Graph v1, Certification Profile and result v1, distributed Verification Binding v1, source-snapshot exclusion identity, test execution evidence semantics, affected-evidence closure, and Verified BFG v1.

### Excludes

This Module excludes semantic re-analysis, signatures, trusted issuer identity, timestamps, Git attestations, remote evidence, grades, hosted orchestration, badges, and claims that trusted assertions are mechanical proofs.

## Relationships

### [Behavioral Realization](../behavioral_realization/README.md)

**Types:** `depends_on`

Provides realized checkpoints, edges, contradictions, and generated verification obligations.

### [Behavioral Semantics](../behavioral_semantics/README.md)

**Types:** `depends_on`

Provides Intended BFG identity, modeled Feature structure, and the semantic artifact whose digest becomes authority evidence.

### [Contract Coherency](../contract_coherency/README.md)

**Types:** `depends_on`

Provides the canonical ecosystem authority, requirements, Testing topology, and exact semantic source provenance.

### [Environmental Semantics](../environmental_semantics/README.md)

**Types:** `depends_on`

Provides environmental proof results, generated scenarios, and trusted environmental assertions without Certification re-evaluation.

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Provides deterministic finding fingerprints attached to rule evidence.

### [Information Flow](../information_flow/README.md)

**Types:** `depends_on`

Provides information-flow proof coverage and explicit trusted endorsement or declassification dependencies.

### [Program Semantics](../program_semantics/README.md)

**Types:** `depends_on`

Provides the observed executable semantic artifact and source-bound coverage identity.

### [Repository Observation](../repository_observation/README.md)

**Types:** `depends_on`

Provides exact stabilized repository bytes from which the recursion-free certification source identity is derived.

### [Semantic Analysis](../semantic_analysis/README.md)

**Types:** `depends_on`

Provides deterministic value-domain proof evidence and coverage without reparsing program source.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Owns the canonical full-snapshot profile and Standard identity whose applicable rule results become static-proof evidence.

### [State and Effect Analysis](../state_effect_analysis/README.md)

**Types:** `depends_on`

Provides current typestate and effect proof identities, coverage, and exact upstream bindings.

## Guarantees

Certification never changes upstream semantic conclusions, never treats CI configuration as execution, never allows ignored or filtered tests to satisfy full evidence, and never hides stale, missing, invalid, unsupported, or trusted inputs behind a top-level PASS.
