# 07 — Archetype and Capability System

**Status:** Normative archetype architecture
**Authority class:** Standard architecture

## Principle

Fortress must be suitable for virtually any software repository without imposing irrelevant structure.

It achieves this by decomposing the engineering system into archetypes and reusable capabilities.

> **Certification scales by decomposition, not by weakening the standard.**

## Archetype definition

An archetype represents a recognizable engineering form with characteristic responsibilities and risks.

The taxonomy should support forms such as:

- package/library;
- CLI;
- frontend application;
- backend service;
- HTTP/API surface;
- background worker;
- relational persistence;
- non-relational persistence;
- compiler;
- language binding;
- desktop application;
- containerized infrastructure;
- cloud infrastructure;
- documentation/public website.

The catalog is extensible and versioned.

## Composite systems

A project may declare many archetypes at once.

Example:

```text
frontend.application
api.http
backend.service
worker.background
persistence.relational
infrastructure.container
infrastructure.cloud
package.typescript
package.python
```

Fortress composes the relevant rules and capabilities.

## Capabilities

Capabilities are reusable concerns activated by one or more archetypes.

Examples:

- public API governance;
- accessibility;
- browser compatibility;
- routing;
- state management;
- lifecycle;
- configuration;
- observability;
- concurrency;
- persistence boundaries;
- migration integrity;
- package publishing;
- installation;
- reproducible build;
- security boundaries;
- cross-language semantics;
- runtime compatibility;
- release provenance.

Capabilities prevent rule duplication across archetypes.

## Universal core versus archetype requirements

Every project inherits Fortress Core.

Archetypes add requirements meaningful to that engineering form.

A pure library does not need database migration certification. A database-owning backend does. A compiler may need deterministic semantic artifacts and target conformance that a static website does not.

## Boundary certification

Composite certification is not merely a set of independent component passes.

Fortress must certify applicable relationships such as:

- frontend → API;
- API → backend;
- backend → persistence;
- worker → queue;
- application → infrastructure;
- package → runtime;
- language binding → canonical core.

Boundary rules may include schema compatibility, ownership, dependency direction, authentication/authorization expectations, version compatibility, deployment configuration, and lifecycle contracts.

## Detection

On an unmodeled repository, Fortress may infer probable archetypes from evidence such as:

- package manifests;
- framework dependencies;
- entrypoints;
- Dockerfiles;
- infrastructure definitions;
- database migrations;
- route definitions;
- package exports;
- build systems;
- language bindings.

Detection results are hypotheses with confidence, not normative declarations.

## Adoption

A project explicitly ratifies archetypes.

If Fortress detects a meaningful new engineering responsibility that is not declared, certification requires resolution:

- adopt the archetype;
- demonstrate the evidence is not applicable;
- remove the accidental responsibility.

This prevents architecture from expanding silently.

## Archetype versioning

Archetypes are versioned within a Fortress Standard edition family.

A newer standard may strengthen one archetype without making unrelated rules applicable to every project.

Upgrade planning must report applicable changes only.

## Avoiding monolithic profiles

Fortress should avoid giant profiles such as “enterprise web app” if they merely duplicate many capability rules.

Prefer:

`archetype → capabilities → rules`

over duplicated rule sets.

## Risk classification

Archetypes and capabilities may activate risk dimensions, for example:

- untrusted input parser;
- persistence migration;
- cryptographic boundary;
- public network service;
- package distribution;
- concurrency/state machine.

Risk changes evidence obligations, not unrelated quality requirements.

## Multi-repository systems

Fortress should remain extensible to a system model spanning multiple repositories.

Each repository may certify independently while a higher system certification verifies cross-repository contracts and release compatibility.

The first stable implementation may focus on one repository at a time while preserving this extension path.

## Goal

The archetype system lets Fortress say:

> “You are a library; here is the strict coherent standard for an excellent library.”

or:

> “You are a multilingual full-stack system with infrastructure; here is the composed strict standard for that system.”

without architecture theater and without diluted certification.
