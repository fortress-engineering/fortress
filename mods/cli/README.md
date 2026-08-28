# CLI

## Purpose

The CLI exists to expose implemented Fortress operations through deterministic terminal and machine-readable interfaces without moving provider-independent semantics into presentation code.

## Responsibility

Own command registration, argument validation, process exit behavior, human rendering, and schema-versioned JSON rendering for version, help, repository audit, CCG inspection, Intended BFG inspection, PSM inspection, semantic-domain analysis, state/effect analysis, information-flow analysis, environmental analysis, Realized BFG inspection, and exact-snapshot local certification.

## Scope

### Includes

The native process boundary, built-in command registry, CLI package and command declarations, supported audit, CCG, Intended BFG, PSM, semantic-analysis, state/effect, information-flow, environmental, Realized BFG, and local certification formats, and explicit failure behavior for malformed or unsupported input.

### Excludes

Core standard or rule semantics, cryptographic attestation, hosted-provider execution, persistent jobs, and commands without real implementation.

## Relationships

### [Engine](../engine/README.md)

**Types:** `depends_on`

Invokes the Engine for command discovery, end-to-end Snapshot Governance audit behavior, deterministic CCG, Intended BFG, and Realized BFG inspection, snapshot-bound Program Semantic Model inspection, and function-domain, state/effect, information-flow, and environmental analysis inspection.

### [Certification](../engine/mods/certification/README.md)

**Types:** `depends_on`

Runs the canonical unfiltered Rust suite locally, constructs current execution evidence, and emits deterministic Evidence Graph, Certification, and Verified BFG artifacts without delegating long verification to hosted CI.

## Guarantees

Unsupported commands and options return non-success; audit succeeds only when every evaluated mandatory rule passes; CCG and Intended BFG inspection preserve their coherency boundaries; PSM inspection succeeds only without invalid facts or analyzer disagreement; semantic, state/effect, information-flow, environmental, and Realized BFG inspection fail on supported contradictions while preserving uncertainty; `certify` returns success only for a truthful full-profile PASS based on current local execution; JSON and human output remain deterministic; no command labels static realization as executed evidence or a digest stamp as an authenticated signature.
