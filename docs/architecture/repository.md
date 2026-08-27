# 04 — Fortress Repository Architecture

**Status:** Normative repository architecture
**Authority class:** System architecture

## Purpose

The `fortress-engineering/fortress` repository is both the reference implementation of Fortress and the canonical source repository for the Fortress Engineering Standard.

It must preserve a clear boundary between normative standard material, implementation, docs, conformance fixtures, integrations, and generated certification evidence.

## Target top-level structure

```text
/
├── .fortress/
├── .github/
├── crates/
├── standard/
├── schemas/
├── analyzers/
├── adapters/
├── conformance/
├── tests/
├── docs/
├── examples/
├── scripts/
├── AGENTS.md
├── CONTRIBUTING.md
├── GOVERNANCE.md
├── SECURITY.md
├── LICENSE
├── README.md
├── Cargo.toml
├── Cargo.lock
└── fortress.toml
```

The exact bootstrap implementation may introduce additional explicitly contracted roots. New top-level directories require an architecture declaration.

## `.fortress/`

Fortress applies Fortress to itself. The repository-local control area contains project-specific Fortress declarations and durable temporal/certification artifacts.

Conceptually:

```text
.fortress/
├── project.yaml
├── architecture/
├── features/
├── invariants/
├── changes/
│   ├── active/
│   └── archive/
├── pipelines/
├── commands/
├── exemptions/
├── certifications/
└── baseline/
```

Transient runtime state MUST NOT be mixed with committed governance artifacts. If `.fortress/state/` exists, it must be gitignored.

## `standard/`

Normative released and draft Fortress Standard material.

```text
standard/
├── README.md
├── drafts/
└── versions/
    └── 1.0/
        ├── manifest.yaml
        ├── core/
        ├── rules/
        ├── archetypes/
        ├── capabilities/
        ├── languages/
        └── tools/
```

Released edition contents are immutable. Draft development MUST NOT modify released version directories.

## `schemas/`

Versioned schemas for rules, features, requirements, project manifests, architecture, dependencies, docs, commands, pipelines, changes, invariants, onboarding, certifications, attestations, analyzer protocols, and standard bundles.

Schemas are normative for serialized structure where declared.

## `crates/`

Rust workspace containing the canonical Fortress implementation.

Target conceptual responsibilities include:

- CLI;
- core shared types;
- standard loading/evaluation;
- project model;
- repository analysis;
- impact analysis;
- certification;
- runtime/commands;
- jobs;
- pipelines;
- temporal governance;
- onboarding;
- protocol types.

The bootstrap task MUST NOT create empty crates merely to mirror a diagram. Crates should be introduced when they establish a meaningful compile-time dependency boundary.

## `analyzers/`

First-party language/framework analyzers that are sufficiently separable from core evaluation.

Analyzer logic depends on versioned analyzer protocols and returns canonical observations/findings.

Language-specific analysis must not redefine standard semantics.

## `adapters/`

Integrations for formatters, linters, type checkers, package managers, security tools, mutation tools, CI/CD providers, and similar systems.

Adapters normalize external behavior into Fortress contracts.

## `conformance/`

Specification-authored fixture repositories and expected findings used to certify rules and analyzers.

```text
conformance/
├── manifest.yaml
├── repositories/
│   ├── valid/
│   └── invalid/
├── expected/
└── tool-conflicts/
```

A Fortress rule is not complete without positive, negative, and boundary evidence appropriate to the rule.

## `tests/`

Implementation tests for Fortress itself.

Implementation tests remain distinct from normative standard conformance fixtures. Tests do not define standard meaning.

## `docs/`

Recommended structure:

```text
docs/
├── product/
├── standard/
├── architecture/
├── governance/
├── development/
├── operations/
├── onboarding/
├── certification/
├── integrations/
├── decisions/
└── history/
```

The public website may render or adapt public documentation, but repository docs retain developer and standard-source material appropriate to the flagship repo.

## `examples/`

Curated examples should eventually demonstrate greenfield adoption, legacy onboarding, a single-language package, a multilingual project, a service with persistence, custom commands, and incremental certification reuse.

Examples should be executable or certifiable where practical.

## Root file policy

Root files must be explicitly approved. The root should remain navigable and institutional, not become a dumping ground.

External-tool configuration that Fortress generates or governs must be documented as a projection rather than hidden independent policy.

The bootstrap-approved root files are `AGENTS.md`, `CONTRIBUTING.md`,
`GOVERNANCE.md`, `SECURITY.md`, `README.md`, `Cargo.toml`, `Cargo.lock`,
`rust-toolchain.toml`, and `.gitignore`. `LICENSE` remains intentionally absent
pending owner authorization. `rust-toolchain.toml` pins the implementation
toolchain used for reproducible validation; `.gitignore` separates build and
transient Fortress runtime state from durable repository authority.

## Naming and placement

Repository paths should use predictable lowercase naming unless ecosystem conventions require otherwise.

Temporary task/campaign identifiers MUST NOT pollute permanent source symbol names.

Generated artifacts must occupy declared families with authoritative inputs, generator identity, output patterns, determinism, and certification implications.

## Bootstrap promotion

The temporary bootstrap packet must be transformed into permanent authorities. It must not remain a parallel permanent documentation tree.

## Repository architecture certification

Fortress must eventually certify its own layout so unauthorized roots, wrong file classes, implementation islands, prohibited crate/module dependencies, and misplaced governance artifacts fail mechanically.
