# Fortress authority map

**Status:** Permanent repository authority index
**Authority class:** Governance navigation

## Purpose

This document defines how permanent Fortress authorities relate after the
temporary bootstrap packet is disposed. It is the entrypoint for resolving
disagreement; it does not replace the controlling document or bundle.

## Precedence

When authorities conflict, apply the most specific controlling authority within
the following order. A lower class cannot silently redefine a higher class.

1. **Constitutional product meaning** —
   [product definition](product/definition.md) and
   [engineering philosophy](standard/philosophy.md).
2. **Normative standard meaning** — immutable released bundles under
   `standard/versions/`; during bootstrap, explicitly labeled candidates under
   `standard/drafts/` are proposed authority and cannot claim a stable release.
3. **Architecture and governance** — system, repository, contract,
   certification, temporal, onboarding, trust, operational, versioning, and
   release-scope documents in this tree.
4. **Versioned schemas and ratified project contracts** — serialized structure
   under `schemas/` and repository-specific declarations under `.fortress/`.
   These encode their governing documents and must be changed through temporal
   governance when meaning changes.
5. **Implementation** — Rust source and integrations measure or execute the
   authorities above. An implementation defect does not redefine them.
6. **Specification-authored conformance material** — fixtures and expected
   findings exercise an already governed rule. They clarify test cases but do
   not independently create normative meaning.
7. **Implementation tests and generated evidence** — tests, reports,
   certification artifacts, and tool output prove or refute conformity. They are
   evidence, never normative authority.
8. **History** — decisions, change records, prior acceptance material, and
   release records preserve what was authorized and when. They do not override
   current authority except when interpreting the historical state they record.

Within architecture and governance, use the permanent authority classes
promoted from the bootstrap manifest in this order: constitutional,
standard architecture, system architecture, contract architecture,
certification, temporal governance, onboarding governance, operational
architecture, quality and trust, release scope, brand, and bootstrap history.

## Controlling entrypoints

- Product: [definition](product/definition.md), [1.0 scope](product/1.0-scope.md),
  and [brand](product/brand.md)
- Standard design: [model](standard/model.md), [rules](standard/rules.md),
  [archetypes](standard/archetypes.md), and [naming](standard/naming.md)
- Architecture: [system](architecture/system.md),
  [repository](architecture/repository.md), and
  [contracts](architecture/contracts.md)
- Certification: [model](certification/model.md) and
  [incremental evidence](certification/incremental.md)
- Governance: [temporal](governance/temporal.md),
  [self-application](governance/self-application.md), and
  [onboarding](onboarding/governance.md)
- Quality and trust: [documentation](standard/documentation.md),
  [testing](standard/testing.md), and [trust](architecture/trust.md)
- History: [bootstrap acceptance](history/bootstrap-acceptance.md) and the
  packet disposition record created at bootstrap completion

## Change discipline

Normative meaning changes require an appropriate `CHG-*` record once the current
temporal schema can represent the change. Tests, fixture output, generated
configuration, documentation projections, and CLI behavior must be reconciled
to authority; none may be used as a shortcut to change it implicitly.
