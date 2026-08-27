# Snapshot Governance

## Purpose

Snapshot Governance exists to answer what is true and what violates the declared engineering model for one exact repository content state, project declaration, architecture, and draft standard.

## Responsibility

Build stabilized content-addressed repository snapshots, analyze supported Rust test facts, execute implemented rules truthfully, normalize deterministic findings, and orchestrate machine-readable and human repository audits.

## Scope

### Includes

Snapshot and audit schemas; findings; ownership, traceability, recursive Module, and documentation synchronization rules; Markdown and Rust analyzers; two-pass stabilization; and exact rule execution reporting.

### Excludes

Certification or attestation, onboarding and migration state, persistent jobs, provider-hosted execution, release orchestration, unsupported language analyzers, and inferred source dependency reconciliation.

## Relationships

### [Architecture Evaluation](../architecture_evaluation/README.md)

**Types:** `depends_on`

Consumes validated architecture declarations and shared dependency evaluation behavior.

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Consumes project identity, feature contracts, requirement evidence declarations, and model pointers.

### [Repository Observation](../repository_observation/README.md)

**Types:** `depends_on`

Consumes deterministic repository file facts to construct and verify snapshots.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Consumes the exact applicable rule bundle and stable rule identities.

## Guarantees

No wall-clock or absolute path enters snapshot identity; repository mutation is rejected when observed bytes diverge; unimplemented rules remain UNSUPPORTED; findings never redefine rules; audit output never claims certification. Stabilization is an optimistic content protocol rather than a filesystem lock, so a malicious host or a transient mutation reverted to identical bytes remains outside its trust guarantee.
