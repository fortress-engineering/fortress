# Reference Resolution

## Purpose

Make governed Module relocation a low-churn operation by separating stable semantic identity from current repository placement and execution-local machine location.

`AF-FOO-0001` and `CAP-FOO` identify what an engineering entity is; `mods/platform/mods/foo` records where it is currently placed in the repository; a path such as `C:\\work\\fortress\\mods\\platform\\mods\\foo` is machine-local execution state and never persistent authority. A physical move preserves identity unless the authored contract intentionally changes semantics.

## Responsibility

Resolve CCG identities into canonical repository paths, classify understood references, reconcile path-only projections, inventory legitimate resolution boundaries, and preview physical relocation without redefining architecture.

## Scope

### Includes

CCG-backed Module lookup, portable path normalization, Markdown relationship projection, Rust native import identities and crate-root path boundaries, Cargo workspace and target paths, REPO-REFERENCE-001 findings, deterministic semantic-delta and relocation simulation, and a focused derived resolution index.

### Excludes

Automatic filesystem moves, arbitrary source rewriting, non-Rust language profiles, authored component manifests, temporal rename history, natural-language path inference, and semantic changes hidden as relocation.

## Relationships

### [Contract Coherency](../contract_coherency/README.md)

**Types:** `depends_on`

Supplies stable Module identities, current physical containment, capabilities, relationships, and the exact CCG digest without delegating architectural authority.

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Supplies deterministic content-addressed findings for supported REPO-REFERENCE-001 violations without turning the resolver into a second rule-result model.

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Supplies project-level repository interpretation while the resolver remains a derived location and projection service.

## Guarantees

Identical CCG and snapshot reference inputs yield byte-identical resolution output; a pure Module move requires zero semantic-reference edits; persisted resolved paths are repository-relative, forward-slash normalized, case-exact, and free of dot segments; machine-absolute paths never become governed authority.

References use the narrowest stable authority shared by source and target: same-Module references may remain relative, cross-Module Fortress relationships use stable IDs, Rust code uses stable crate/module surfaces, Cargo and registries are explicit authored location boundaries, Markdown navigation is a generated physical projection, and machine-local paths remain runtime-only. Relocation simulation deliberately reports semantic changes separately so a move cannot hide a changed provider, capability, dependency, or Feature relationship.
