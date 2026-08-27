# Snapshot Governance

## Purpose

Snapshot Governance exists to answer what is true and what violates the declared engineering model for one exact repository content state, operational configuration, canonical CCG, and draft standard.

## Responsibility

Build stabilized content-addressed repository snapshots, analyze supported Rust test facts, execute implemented rules truthfully, normalize deterministic findings, and orchestrate machine-readable and human repository audits.

## Scope

### Includes

Snapshot and audit schemas; findings; contract coherency, ownership, traceability, recursive Module, and documentation synchronization rules; Markdown and Rust analyzers; two-pass stabilization; and exact rule execution reporting.

### Excludes

Certification or attestation, onboarding and migration state, persistent jobs, provider-hosted execution, release orchestration, unsupported language analyzers, inferred source dependency reconciliation, semantic satisfiability outside the formal CCG v1 rule language, and BFG construction or visualization.

## Relationships

### [Architecture Evaluation](../architecture_evaluation/README.md)

**Types:** `depends_on`

Consumes CCG-backed architecture projections and shared dependency evaluation behavior.

### [Contract Coherency](../contract_coherency/README.md)

**Types:** `depends_on`

Consumes one immutable semantic graph containing resolved intent, derivations, logical coherency, provenance, and verification topology.

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Consumes only operational project configuration; project identity, Features, and requirements arrive through resolved Module contracts.

### [Repository Observation](../repository_observation/README.md)

**Types:** `depends_on`

Consumes deterministic repository file facts to construct and verify snapshots.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Consumes the exact applicable rule bundle and stable rule identities.

## Guarantees

No wall-clock or absolute path enters snapshot or CCG identity; repository mutation is rejected when observed bytes diverge; the CCG is compiled once per complete audit; unimplemented rules remain UNSUPPORTED; findings never redefine rules; audit output never claims certification. Stabilization is an optimistic content protocol rather than a filesystem lock, so a malicious host or a transient mutation reverted to identical bytes remains outside its trust guarantee.
