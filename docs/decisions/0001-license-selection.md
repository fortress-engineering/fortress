# Owner decision 0001 — Repository license

**Status:** Owner decision required
**Authority class:** Release scope
**Decision ID:** `ADR-LICENSE-0001`

## Question

Which license, if any, should govern the `fortress-engineering/fortress`
repository and its distinct normative standard, schema, documentation,
conformance, and implementation materials?

## Evidence and constraints

- The bootstrap authority and task do not authorize a license.
- Different artifact classes may create materially different goals for use,
  modification, redistribution, specification implementation, patent grants,
  and conformance claims.
- Selecting a license creates a public legal permission and is therefore not a
  reversible implementation default.

## Alternatives

1. Select one owner-approved license for the complete repository.
2. Use an owner-approved multi-license structure for distinct artifact classes.
3. Keep the repository unlicensed while private evaluation continues.

## Recommendation

Obtain explicit legal and owner review of the intended openness, patent,
conformance, trademark, and contribution model before selecting an option. Do
not copy the license used by another organization or repository as an implicit
decision.

## Exact decision required

The owner must name the approved license or approved multi-license allocation
and authorize adding the corresponding license and notice files. Until then,
the repository intentionally omits `LICENSE` and makes no grant of rights.
