# Engine Module

The Engine Module owns Fortress's provider-independent execution boundary. Its
direct code is only the crate facade that composes child capabilities; semantic
responsibilities sink into the narrowest child Module.

Immediate children are `standard_registry`, `project_model`,
`repository_observation`, `architecture_evaluation`, and
`snapshot_governance`. Their dependency direction follows standard authority,
declared project meaning, observed facts, architecture reconciliation, and
derived snapshot findings. Provider adapters, persistent jobs, temporal
workflows, onboarding, deployment, and attestation remain deferred and are not
represented by empty Modules.

The Engine may depend on standard and project declarations. It must not depend
on terminal presentation, GitHub, a shell, an IDE, or a CI provider. External
analyzers may report facts but remain subordinate to Fortress rule semantics.
