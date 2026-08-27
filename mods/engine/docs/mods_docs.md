# Modules

## Composition

The Engine responsibility is decomposed where durable child boundaries have exclusive primary ownership and independent contracts; immediate children remain contained by this parent while cross-Module dependencies stay authoritative in contract.json.

## Modules

### [Architecture Evaluation](../mods/architecture_evaluation/README.md)

Consumes the CCG dependency and containment semantics to provide architecture rule evaluation and physical ownership views.

### [Contract Coherency](../mods/contract_coherency/README.md)

Compiles distributed contracts, containment, standard logic, and verification declarations into the deterministic semantic graph shared by downstream evaluators.

### [Finding Model](../mods/finding_model/README.md)

Provides the shared canonical finding representation used across rule-family boundaries without owning evaluator judgment.

### [Implementation Observation](../mods/implementation_observation/README.md)

Analyzes snapshot-bound Rust source independently and emits deterministic implementation dependency facts with provenance.

### [Project Model](../mods/project_model/README.md)

Provides the declared engineering subject and evidence obligations consumed by observation and Snapshot Governance.

### [Repository Observation](../mods/repository_observation/README.md)

Supplies reproducible repository facts to the snapshot builder without asserting what those facts mean.

### [Snapshot Governance](../mods/snapshot_governance/README.md)

Turns exact declarations and repository facts into deterministic rule executions and normalized development evidence.

### [Standard Registry](../mods/standard_registry/README.md)

Provides the normative identity and registry foundation required by every capability that interprets Fortress declarations or findings.

## Coordination

The immediate children collectively fulfill the Engine responsibility through the parent boundary. Their conceptual contributions compose here without restating or replacing the typed relationship graph declared by their Module contracts.
