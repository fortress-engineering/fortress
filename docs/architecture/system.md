# 03 — Fortress System Architecture

**Status:** Normative system architecture
**Authority class:** System architecture

## Architectural objective

Fortress is a standalone, local-first engineering control plane whose architecture separates normative standard data, project modeling, repository observation, analysis, execution, certification, persistence, provider integrations, and presentation.

The implementation MUST preserve the distinction between standard authority, project declarations, observed facts, execution, evidence, and UI presentation.

## Canonical implementation language

The canonical Fortress implementation SHOULD be Rust.

Rust is preferred for standalone cross-platform distribution, process supervision, concurrency, filesystem analysis, content hashing, deterministic systems behavior, and reliable CLI tooling.

The choice of Rust is implementation architecture, not standard authority.

Fortress MUST NOT maintain independent core standard implementations in Node, Python, or other languages merely for ecosystem convenience.

## Major subsystems

### Standard Registry

Loads immutable standard bundles, validates schemas, resolves archetype/capability composition, exposes rule metadata, resolves pinned editions, compares editions, and validates tool-policy compatibility.

It MUST NOT inspect project source directly.

### Project Model Engine

Represents project declarations for archetypes, capabilities, components, features, requirements, docs, tests, commands, pipelines, invariants, changes, and certifications.

It maintains stable entity identities and a canonical declared engineering graph.

### Repository Observation Engine

Inventories files; detects languages, packages, build systems, and frameworks; invokes analyzers; reconstructs imports, symbols, public surfaces, tests, generated artifacts, and pipeline definitions; and records confidence for inferred findings.

It produces observations, not ratified architecture.

### Architecture and Contract Evaluator

Compares observed topology to declared topology; enforces ownership, architecture zones, dependency direction, cycle policy, feature/requirement/test/document relationships, and normalized findings.

### Impact Engine

Computes changed entities and forward/reverse dependency closure, affected tests/docs/language surfaces/pipelines/certifications, and explanations for invalidation.

This powers `fortress affected`.

### Certification Engine

Defines certification DAGs, computes input closures and fingerprints, schedules required certification, reuses valid evidence, produces canonical certification artifacts, and verifies attestations.

### Command Registry and Runtime

Exposes project-level commands, typed parameters, prerequisites, inputs, outputs, executors, and certification/pipeline relationships.

Short operations may execute synchronously. Long operations are submitted to the job subsystem.

### Job Supervisor

Conceptual background service: `fortressd`.

Responsibilities include persistent local job state, process supervision, checkpoints, work-unit scheduling, logs/events, progress, pause/resume/cancel where semantics permit, remote provider synchronization, and artifact capture.

Users primarily interact with `fortress`, not `fortressd`.

### Pipeline Engine

Models provider-independent pipeline DAGs, executes local-compatible tasks, maps canonical pipelines to supported CI/CD providers, audits provider workflows, enforces certification prerequisites, and tracks remote runs as Fortress jobs.

### Temporal Ledger

Stores change intents, planned contracts, invariants, ADRs, migrations, executed change records, and release records.

### Onboarding Engine

Performs forensic scanning, architecture hypothesis generation, target model construction, convergence planning, migration ratcheting, violation activation, and staged onboarding certification.

### Adapter Host

Hosts language analyzers, tool adapters, package-manager adapters, framework detectors, CI/CD providers, security/mutation/fuzz integrations, and extension protocols.

Adapters do not redefine Fortress rule meaning.

## Canonical engineering graph

Fortress maintains nodes such as repository, archetype, capability, component, feature, requirement, file, symbol, dependency, test, doc, generated artifact, command, pipeline, certification, change, and invariant.

Edges have explicit semantics and provenance, such as:

- `owns`;
- `depends_on`;
- `implements`;
- `tests`;
- `documents`;
- `generates`;
- `certifies`;
- `invalidates`;
- `supersedes`;
- `introduced_by`.

## Declared, observed, and hypothesized graphs

Fortress preserves:

1. **Declared graph** — architecture the project claims.
2. **Observed graph** — relationships extracted from code and evidence.
3. **Hypothesized graph** — onboarding inferences with confidence.

Hypotheses are never silently promoted to declarations.

## Persistence

Ephemeral local runtime state and durable repository evidence are separate.

Local runtime state may include daemon PID, queues, transient logs, caches, provider tokens, and resumable work units. It should live outside versioned source or in a gitignored state area.

Durable repository state includes contracts, invariants, change records, certification artifacts required by project policy, standard locks, baselines, and exemptions.

A transactional local store such as SQLite is appropriate for job runtime state; it is not the normative architecture authority.

## Determinism

Given identical repository content, standard edition, project model, analyzer/tool versions, and relevant environment inputs, Fortress model evaluation and fingerprint calculation must be deterministic.

Nondeterministic metadata such as wall-clock timestamps must be isolated from semantic digests unless explicitly part of provenance.

## Trust boundaries

Fortress treats arbitrary repository source, third-party analyzers, external tool output, remote CI results, user-authored certification files, and provider responses as potentially untrusted inputs.

Schemas and provenance must be validated.

## Offline behavior

Core standard loading, project modeling, affected analysis, local command execution, and certification verification must work offline when required inputs are present.

Remote integrations degrade explicitly rather than invalidating unrelated local functions.

## Extension boundary

Extensions communicate through versioned Fortress contracts. They may observe source, return canonical findings, expose tool commands, and provide evidence. They may not mutate Fortress normative standard semantics.

## Layering rule

Presentation and provider integrations depend inward on stable core interfaces.

Core modeling and standard evaluation MUST NOT depend on GitHub, a specific shell, an IDE, a CI provider, or one package ecosystem.
