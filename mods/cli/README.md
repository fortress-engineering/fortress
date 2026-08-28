# CLI

## Purpose

The CLI exists to expose implemented Fortress operations through deterministic terminal and machine-readable interfaces without moving provider-independent semantics into presentation code.

## Responsibility

Own command registration, argument validation, process exit behavior, human rendering, and schema-versioned JSON rendering for version, help, repository audit, CCG inspection, Intended BFG inspection, PSM inspection, semantic-domain analysis, state/effect analysis, information-flow analysis, environmental analysis, and Realized BFG inspection operations.

## Scope

### Includes

The native process boundary, built-in command registry, CLI package and command declarations, supported audit, CCG, Intended BFG, PSM, semantic-analysis, state/effect, information-flow, environmental, and Realized BFG formats, and explicit failure behavior for malformed or unsupported input.

### Excludes

Core standard or rule semantics, certification claims, hosted-provider execution, persistent jobs, and commands without real implementation.

## Relationships

### [Engine](../engine/README.md)

**Types:** `depends_on`

Invokes the Engine for command discovery, end-to-end Snapshot Governance audit behavior, deterministic CCG, Intended BFG, and Realized BFG inspection, snapshot-bound Program Semantic Model inspection, and function-domain, state/effect, information-flow, and environmental analysis inspection.

## Guarantees

Unsupported commands and options return non-success; audit succeeds only when every evaluated mandatory rule passes; CCG and Intended BFG inspection preserve their coherency boundaries; PSM inspection succeeds only without invalid facts or analyzer disagreement; semantic, state/effect, information-flow, environmental, and Realized BFG inspection fail on supported contradictions while preserving uncertainty; JSON and human output remain deterministic; no command labels a Realized BFG as a runtime trace, Verified BFG, total program safety, comprehensive security proof, comprehensive fault-tolerance proof, or certification.
