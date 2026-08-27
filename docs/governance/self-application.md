# 21 — Fortress Self-Application Principle

**Status:** Normative self-application principle
**Authority class:** Quality and trust

## Principle

Fortress must develop under Fortress from the earliest practical point.

Early Fortress cannot enforce capabilities that do not yet exist. It must therefore govern itself with the strongest released or candidate Fortress standard it can truthfully enforce and ratchet upward as capabilities mature.

## No retroactive perfection claim

A historical development stage must record what standard/capability set actually governed it.

Fortress MUST NOT claim that a version was certified under rules that did not yet exist.

## Progressive inward application

When Fortress gains a generally applicable capability, the Fortress repository should become one of the first repositories required to satisfy it.

Examples:

- symbol documentation auditor;
- dependency declaration enforcement;
- temporal change contracts;
- content-addressed certification;
- onboarding migration rules.

If a new rule exposes deficits in Fortress itself, those deficits become explicit migration work rather than grounds for quietly exempting Fortress.

## Self-application rule

> **Fortress MUST develop under the strongest released or candidate Fortress standard that its current implementation can truthfully enforce. New generally applicable Fortress requirements MUST be applied to the Fortress repository itself before the corresponding standard is declared stable. Fortress MUST NOT exempt itself solely because compliance is inconvenient.**

## Monotonic self-governance

As Fortress gains governance capabilities, its repository should monotonically converge toward the stronger standard.

Transitional deficits must be:

- explicit;
- bounded;
- historically traceable;
- incapable of being represented as completed certification.

## Previous-version bootstrap trust

Once mature, version `N` should help certify development of `N+1`.

For consequential certification-engine changes, release should prefer dual proof:

1. previous trusted Fortress release certifies the candidate under the previous applicable standard;
2. candidate Fortress self-certifies the exact candidate source under the proposed standard;
3. evidence is compared and discrepancies resolved.

This prevents a candidate verifier from simply changing the rules and declaring itself correct.

## Fortress as falsification environment

Self-application is not merely branding. It is a design test.

If Fortress repeatedly requires arbitrary exemptions from its own rules, the standard may be over-generalized.

If contract maintenance makes ordinary Fortress development incoherent, the contract model may be too granular.

If affected analysis misses Fortress's own changes, the dependency model is defective.

Fortress development should reveal these problems before external adopters do.

## Recursive evidence

Fortress should eventually certify:

- its own standard integrity;
- source quality;
- architecture;
- contracts;
- testing;
- docs;
- job runtime;
- pipelines;
- temporal ledger;
- onboarding engine;
- certification/attestation implementation.

## Release milestone

The defining 1.0 milestone includes Fortress being able to produce a credible full self-certification under Fortress Engineering Standard 1.0.0, subject to any explicitly documented bootstrap trust root required to avoid circularity.

## Goal

Every time Fortress learns a better way to govern software, it should first prove that it can live under the knowledge it asks other projects to adopt.
