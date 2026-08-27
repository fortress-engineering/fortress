# 17 — Documentation and Source Commentary Standard

**Status:** Normative documentation quality standard
**Authority class:** Quality and trust

## Principle

A Fortress repository is not considered coherent merely because implementation is correct.

Documentation, code commentary, contracts, and architecture descriptions are part of the engineering system and must remain synchronized with source and behavior.

## File-level source documentation

Every hand-authored implementation file must have language-appropriate module/file documentation defining applicable:

- purpose;
- primary owning contract/entity;
- architecture zone/component;
- responsibilities;
- important invariants;
- major dependencies;
- side effects or platform behavior.

Generated files are exempt only when explicitly registered as generated.

## Symbol documentation

Every substantive hand-authored symbol must be documented, including applicable:

- classes;
- structs;
- enums;
- traits/interfaces;
- functions/methods;
- constructors;
- domain constants;
- public and important private abstractions.

Documentation must cover applicable:

- purpose;
- parameters;
- return value;
- errors/exceptions;
- panics;
- safety constraints;
- side effects;
- mutation;
- concurrency/thread safety;
- preconditions;
- postconditions;
- invariants;
- examples.

## Language-specific projections

### TypeScript/JavaScript

Use JSDoc/TypeDoc-style documentation with applicable `@param`, `@returns`, and `@throws` semantics.

### Python

Use a standardized project docstring convention with parameters, returns, raises, and behavioral notes. Strict typing remains separately mandatory.

### Rust

Use rustdoc and applicable `# Errors`, `# Panics`, `# Safety`, and `# Examples` sections.

Other language profiles define equivalent idiomatic forms.

## Commentary quality

Comments should explain why, invariants, compatibility, safety, performance, or platform constraints rather than restating syntax.

Recognized rationale categories may include:

- `WHY:`;
- `INVARIANT:`;
- `SAFETY:`;
- `COMPAT:`;
- `PERF:`;
- `PLATFORM:`.

Certain constructs such as unsafe operations, linter suppressions, compatibility quirks, complexity exemptions, and platform-specific branches may require explicit rationale.

## Documentation artifacts

Normative/user-facing docs should have machine-readable metadata, conceptually including:

- stable doc ID;
- document type;
- feature/component IDs;
- authority/status;
- standard/contract version;
- review metadata.

## Required document structures

Document types may define required sections.

Example feature specification:

1. Purpose
2. Scope
3. Semantics
4. Invariants
5. Errors
6. Compatibility
7. Examples
8. Test / Conformance References

Example architecture decision:

1. Context
2. Boundary
3. Decision
4. Dependencies
5. Invariants
6. Consequences
7. Alternatives
8. Migration / Compatibility

Missing mandatory sections fail documentation certification.

## Executable documentation

Code examples should compile or execute where practical.

Fortress should validate:

- links;
- headings;
- contract references;
- API symbol references;
- schema references;
- executable examples;
- ownership metadata.

Stale API examples are failures, not cosmetic warnings.

## Documentation dependencies

Docs participate in dependency and certification graphs.

If a feature changes, docs that contractually explain it may become stale.

If a normative doc defines a behavior or architecture input, changing it may invalidate implementation/certification downstream.

## Generated docs

Generated API or certification docs are non-normative projections unless explicitly declared otherwise.

Their generators and authoritative sources must be registered.

## Public website relationship

The `fortress-engineering/website` repository is the canonical public learning/documentation surface for end users.

The flagship `fortress` repository owns implementation/developer architecture and normative standard source materials.

Duplication should be generated or intentionally separated by audience, not manually drifted copies.

## Technical debt markers

Anonymous `TODO`, `FIXME`, `HACK`, or `TEMP` markers are prohibited in governed source.

Permitted debt annotations must reference a tracked issue/change/exemption and retirement condition where appropriate.

## Documentation coverage

Fortress should report documentation coverage separately for:

- files;
- substantive symbols;
- feature documentation obligations;
- public API documentation;
- architecture docs.

The strict target for governed hand-authored source is 100% applicable documentation coverage.

## Goal

Documentation should become reliable engineering memory rather than prose that gradually diverges from the code.
