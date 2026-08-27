# 05 — Contract Model

**Status:** Normative contract architecture
**Authority class:** Contract architecture

## Purpose

Fortress contracts convert engineering intent into machine-verifiable relationships.

A contract is not merely configuration. It is a versioned declaration of what an entity is, what it owns, what it may depend on, what behavior it promises, and what evidence is required.

## Stable identity classes

Recommended identity namespaces include:

- `PF-*` — Product Feature
- `AF-*` — Architecture/Foundation Capability
- `TF-*` — Tooling Capability
- feature-scoped `*-R*` — Normative Requirement
- `T-*` — Test Identity
- `DOC-*` — Documentation Artifact
- `INV-*` — Project Invariant
- `CHG-*` — Change Contract
- `TRANS-*` — Architectural Transition
- `CERT-*` — Certification Unit
- `EX-*` — Exemption
- `ADR-*` — Architecture Decision

Projects may define namespaced variants, but stable IDs are immutable and never reused for different semantics.

## Feature contract

Every externally meaningful product feature must have a feature contract.

A feature contract should define:

- stable feature ID;
- title;
- status;
- parent feature where applicable;
- summary;
- owning component;
- architecture zone;
- owned paths/symbols where appropriate;
- public surfaces;
- dependencies;
- forbidden dependencies;
- canonical semantic artifacts;
- language/runtime applicability;
- normative requirements;
- test obligations;
- documentation obligations;
- risk class;
- introduction/deprecation metadata.

## Subfeatures

Large features may be decomposed into subfeatures when the boundary is semantically meaningful.

Subfeatures MUST NOT be invented merely to reduce file size or produce artificial granularity.

Parent/child relationships are explicit and machine-validated.

## Normative requirements

Each requirement describes one independently verifiable behavior or invariant.

Bad:

> The scheduler handles time correctly.

Good:

> During a configured DST overlap, the occurrence selector applies the declared overlap policy and produces a stable occurrence identity.

Requirement identity remains stable across implementation refactors.

## Requirement-to-test traceability

Every active mandatory normative requirement must map to automated evidence unless a standard rule explicitly permits a documented non-automatable evidence class.

Product-behavior tests receive globally unique IDs, for example:

`T-PF-SCHED-0017-R01-001`

Fortress enforces:

- zero duplicate test IDs;
- zero invalid requirement references;
- zero orphan normative requirements;
- zero unclassified product-behavior tests.

The objective is not merely 100% feature coverage. It is 100% required requirement coverage.

## Test obligation classes

A feature may require:

- positive;
- negative;
- boundary;
- integration;
- conformance;
- cross-platform;
- property-based;
- fuzz;
- mutation;
- performance;
- security;
- migration;
- differential.

Risk class and feature type determine which are mandatory.

A single trivial test cannot create false 100% coverage of a broad feature.

## File and symbol ownership

Every hand-authored production source file must have exactly one primary owning entity and may have declared secondary relationships.

Substantive symbols inherit or explicitly refine ownership.

Generic unowned utility areas are prohibited. If behavior is genuinely shared, the preferred outcome is to promote it into a named architectural capability with explicit consumers.

## Dependency contracts

Cross-entity dependencies are explicit.

Fortress compares:

- declared dependency graph;
- observed import/reference graph.

Failures include:

- undeclared edge;
- forbidden edge;
- prohibited reverse dependency;
- illegal architecture-layer crossing;
- unexpected cycle;
- stale mandatory dependency declaration.

## Dependency granularity

Contracts should use the highest granularity that still gives meaningful impact analysis without creating per-symbol bureaucracy.

Typical levels are:

- component;
- feature;
- selected public symbol/surface for high-risk boundaries.

The standard may require finer granularity for critical architecture.

## Cycle policy

Architectural cycles are forbidden by default.

A genuinely inseparable strongly connected cluster should usually be modeled as one component rather than disguised as mutually dependent modules.

Exceptional cycles require a governed transition or exemption.

## Public API contracts

Public surfaces must have owners and compatibility rules.

Fortress should extract or snapshot public API structure and compare changes with:

- feature requirements;
- semantic version policy;
- migration documentation;
- authorized change contracts.

An implementation cannot silently create a new public contract merely by exporting a symbol.

## Canonical semantic artifacts

Where a product has cross-language or cross-runtime semantics, canonical schema-versioned JSON artifacts should represent normative meaning independent of implementation language.

They must be:

- versioned;
- schema-valid;
- deterministic;
- language-neutral.

Idiomatic language APIs project to/from these semantics without independently redefining them.

## Documentation contracts

Documentation artifacts identify:

- stable doc ID;
- document type;
- governed features/components;
- authority;
- required sections;
- code/API references;
- examples;
- review/version state.

Documentation becomes part of the impact and certification graph.

## Command contracts

Project operations are contract entities.

A command defines:

- stable command ID;
- name and aliases;
- description;
- typed parameters;
- prerequisites;
- inputs;
- outputs;
- executor;
- artifacts;
- resumability class;
- certification implications.

## Certification contracts

A certification unit defines:

- exact dependency closure specification;
- toolchain requirements;
- upstream certification units;
- execution contract;
- evidence outputs;
- trust requirements;
- cache and reuse semantics.

## Contract-code synchronization

Fortress detects both directions of drift.

### Code exceeds contract

Examples:

- new import not declared;
- new public API unowned;
- new file not assigned;
- new dependency unregistered.

### Contract exceeds code

Examples:

- mandatory dependency no longer exists;
- declared public symbol is missing;
- owner references nonexistent files;
- tests refer to retired requirements.

## Pure refactors

A pure refactor does not need artificial semantic contract changes.

Fortress recomputes relationships. If behavior, ownership, API, dependency graph, and docs remain valid, unchanged contracts are the correct result.

Strictness requires proof of consistency, not meaningless edits.

## Contract history

Normative contract changes occur through temporal change governance.

A contract MUST NOT be silently rewritten without preserving the historical change record that authorized the new meaning.

## Goal

The contract system should let Fortress answer not only “what files changed?” but:

> **Which engineering entities changed meaning, which relationships are affected, what evidence must be refreshed, and what remains provably unchanged?**
