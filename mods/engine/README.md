# Engine

## Purpose

The Engine exists to provide one provider-independent boundary through which Fortress semantics can be loaded, observed, evaluated, and consumed without presentation or service-provider coupling.

## Responsibility

Compose the implemented core capabilities behind a stable Rust library facade while assigning each durable semantic responsibility to its narrowest child Module.

## Scope

### Includes

The crate facade, package contract, and integration of standard registry, finding model, contract coherency, Behavioral Semantics, project model, repository observation, implementation observation, Program Semantics, architecture evaluation, and Snapshot Governance capabilities.

### Excludes

Terminal rendering, hosted-provider adapters, persistent jobs, onboarding, deployment, attestation, and capability-specific semantics owned by the child Modules.

## Relationships

### [Architecture Evaluation](mods/architecture_evaluation/README.md)

**Types:** `depends_on`

Supplies CCG-backed architecture and dependency evaluation through the Engine facade.

### [Behavioral Semantics](mods/behavioral_semantics/README.md)

**Types:** `depends_on`

Supplies deterministic Intended BFG compilation, graph-level flow coherence, and explicit behavioral modeling states.

### [Contract Coherency](mods/contract_coherency/README.md)

**Types:** `depends_on`

Supplies canonical Contract v2 compilation, semantic closure, contradiction analysis, provenance, and deterministic CCG serialization.

### [Finding Model](mods/finding_model/README.md)

**Types:** `depends_on`

Supplies the shared validated, content-addressed evidence representation used by Engine evaluators.

### [Implementation Observation](mods/implementation_observation/README.md)

**Types:** `depends_on`

Supplies independent snapshot-bound Rust source facts and normalized direct Module dependency evidence.

### [Program Semantics](mods/program_semantics/README.md)

**Types:** `depends_on`

Supplies deterministic executable symbols, typed interfaces, supported static calls, bounded value-transfer facts, and analyzer-coherency evidence.

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
