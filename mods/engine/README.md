# Engine

## Purpose

The Engine exists to provide one provider-independent boundary through which Fortress semantics can be loaded, observed, evaluated, and consumed without presentation or service-provider coupling.

## Responsibility

Compose the implemented core capabilities behind a stable Rust library facade while assigning each durable semantic responsibility to its narrowest child Module.

## Scope

### Includes

The crate facade, package contract, and integration of standard registry, contract coherency, project model, repository observation, architecture evaluation, and Snapshot Governance capabilities.

### Excludes

Terminal rendering, hosted-provider adapters, persistent jobs, onboarding, deployment, attestation, and capability-specific semantics owned by the child Modules.

## Relationships

### [Architecture Evaluation](mods/architecture_evaluation/README.md)

**Types:** `depends_on`

Supplies CCG-backed architecture and dependency evaluation through the Engine facade.

### [Contract Coherency](mods/contract_coherency/README.md)

**Types:** `depends_on`

Supplies canonical Contract v2 compilation, semantic closure, contradiction analysis, provenance, and deterministic CCG serialization.

### [Project Model](mods/project_model/README.md)

**Types:** `depends_on`

Supplies typed project, feature, requirement, and evidence declarations composed by the Engine.

### [Repository Observation](mods/repository_observation/README.md)

**Types:** `depends_on`

Supplies deterministic repository file facts and explicit exclusion behavior.

### [Snapshot Governance](mods/snapshot_governance/README.md)

**Types:** `depends_on`

Supplies snapshot construction, rule execution, findings, and repository audit orchestration.

### [Standard Registry](mods/standard_registry/README.md)

**Types:** `depends_on`

Supplies stable identities and the exact draft standard bundle interpreted by the Engine.

## Guarantees

The Engine forbids unsafe code, denies warnings and broken documentation, preserves provider independence, and exposes child behavior without inventing a parallel source taxonomy.
