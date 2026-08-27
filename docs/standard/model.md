# 02 — Fortress Engineering Standard Model

**Status:** Normative standard model
**Authority class:** Standard architecture

## Standard identity

The **Fortress Engineering Standard** is the normative rule system consumed by the Fortress engine.

The standard and Fortress executable are separately versioned authorities.

A repository certifies against an immutable standard edition, for example `Fortress Engineering Standard 1.3.0`. The installed CLI may be newer than the edition being certified.

## Composition

The standard is composed from:

1. **Core rules** — universally applicable engineering governance.
2. **Archetypes** — recognizable forms of software systems.
3. **Capabilities** — reusable engineering concerns activated by archetypes or project declarations.
4. **Language profiles** — language-specific source, typing, documentation, build, and tool policy.
5. **Runtime/tool profiles** — package managers, framework integrations, deployment technologies, and specialized analyzers.
6. **Project extensions** — project-specific rules that strengthen or specialize the standard.
7. **Bounded exemptions** — explicit exceptions that do not modify the standard.

## Fortress Core

Core defines requirements meaningful across essentially all software repositories, including repository integrity, explicit ownership, governed dependencies, contract identity, documentation expectations, tracked debt, generated-artifact authority, deterministic certification, change impact, bounded exceptions, and certification provenance.

Core MUST NOT assume irrelevant architecture such as HTTP services, databases, or multiple languages.

## Archetypes are compositional

A project is not assigned one monolithic profile. It declares or ratifies a composition of archetypes such as:

- `package.library`;
- `package.cli`;
- `frontend.application`;
- `backend.service`;
- `api.http`;
- `worker.background`;
- `persistence.relational`;
- `compiler`;
- `language.binding`;
- `infrastructure.container`;
- `infrastructure.cloud`.

Archetypes activate reusable capabilities and rule sets.

## Capabilities

Capabilities represent concerns shared across archetypes. Examples include public API governance, state management, observability, persistence boundaries, migration integrity, package metadata, accessibility, lifecycle, concurrency, reproducible build, configuration, security boundaries, and cross-language conformance.

Capabilities prevent rule duplication across a large archetype catalog.

## Strict inheritance

An extension may strengthen a parent standard requirement. It MUST NOT silently weaken a mandatory parent rule.

A project-specific departure uses the formal exemption mechanism and remains visible in certification.

## Applicability

Every rule must define its applicability predicate. Applicability may depend on archetype, capability, language, runtime, risk class, public/private surface, generated/manual status, or explicit project declaration.

Fortress must be able to explain why a rule applies.

## Rule evaluation states

A rule evaluation may produce:

- `PASS`;
- `FAIL`;
- `LOCKED`;
- `PROVISIONAL`;
- `INAPPLICABLE`;
- `UNSUPPORTED`;
- `EXEMPTED` with a valid exemption reference.

On a fully onboarded repository, mandatory applicable rules should normally collapse to PASS or FAIL. Additional states are important during onboarding and analyzer gaps.

## No quality tiers

The standard MUST NOT define lower certification grades that permit mandatory violations.

Subsystems may be independently certified and onboarding may expose progress, but the final claim remains binary for the claimed scope and standard edition.

## Tool projections

The standard may define canonical policy projected into specialized tool configuration, including formatting, naming, type-checker strictness, linting, and documentation rules.

Generated tool configuration is subordinate to the Fortress rule source.

Conflicting tool rules MUST be resolved before a standard/profile is released.

## Stable rule vocabulary

Every normative rule has a stable public ID such as `ARCH-*`, `DEP-*`, `CONTRACT-*`, `SRC-*`, `DOC-*`, `TEST-*`, `CERT-*`, `PIPE-*`, `CHANGE-*`, `ONBOARD-*`, or `SEC-*`.

IDs are never reused for a semantically different rule.

Each rule includes at minimum its ID, normative statement, purpose, failure prevented, applicability, enforcement mechanism, examples, remediation, exception policy, and version history.

## Immutable released editions

Once a standard edition is released, its normative bundle is immutable and receives a canonical digest.

A repository lock identifies the exact edition and digest.

A later edition does not invalidate an older certification merely by existing.

## New-edition discovery

When network access or cached release metadata is available, Fortress SHOULD report that a newer standard exists.

Example: `Standard 1.2.0: PASS — newer edition 1.3.0 available`.

The warning is informational. Offline certification remains valid and reproducible.

## Standard upgrade

`fortress upgrade --to 1.3.0 --plan` should compare editions, determine applicable changes, compute affected entities, and predict required migration.

The repository does not claim the new edition until its standard pin changes.

After the pin changes, all new mandatory requirements become hard gates.

## Standard SemVer

### Patch

Clarifies or repairs behavior without intentionally adding materially new compliance obligations.

### Minor

May add or strengthen compatible 1.x engineering requirements and therefore may require repository changes.

### Major

May alter fundamental authority, contract, certification, or compatibility principles.

## Standard self-conformance

The standard bundle must be schema-valid, internally non-contradictory, deterministically serialized, and covered by rule conformance fixtures before release.

Fortress must test valid repositories, invalid repositories, expected findings, overlapping tool policies, and deterministic upgrade behavior.

## Project declaration

A Fortress project declares standard edition, archetypes, capabilities, languages, analyzers, tool profiles, project extensions, exemptions, and certification policy.

These declarations are part of the project fingerprint.

## Canonical separation

The standard defines **what must be true**.

The project model defines **what engineering system is being certified**.

The Fortress engine defines **how truth is measured and proven**.

These responsibilities must remain distinct.
