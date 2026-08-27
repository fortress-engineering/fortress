# CLI

## Purpose

The CLI exists to expose implemented Fortress operations through deterministic terminal and machine-readable interfaces without moving provider-independent semantics into presentation code.

## Responsibility

Own command registration, argument validation, process exit behavior, human rendering, and schema-versioned JSON rendering for version, help, repository audit, and CCG inspection operations.

## Scope

### Includes

The native process boundary, built-in command registry, CLI package and command declarations, supported audit and CCG formats, and explicit failure behavior for malformed or unsupported input.

### Excludes

Core standard or rule semantics, certification claims, hosted-provider execution, persistent jobs, and commands without real implementation.

## Relationships

### [Engine](../engine/README.md)

**Types:** `depends_on`

Invokes the Engine for command discovery, end-to-end Snapshot Governance audit behavior, and deterministic CCG inspection.

## Guarantees

Unsupported commands and options return non-success; audit succeeds only when every evaluated mandatory rule passes; CCG inspection succeeds only for a supported coherent graph; JSON and human output remain deterministic; no command labels an audit or graph as certification.
