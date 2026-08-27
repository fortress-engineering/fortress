# 11 — Onboarding and Convergence Governance

**Status:** Normative onboarding-governance architecture
**Authority class:** Onboarding governance

## Principle

Any repository should be able to begin Fortress adoption without already being Fortress-shaped.

The repository may be undocumented, inconsistent, cyclic, architecturally confused, multi-language, full of duplicated implementations, governed by conflicting tools, or missing tests and contracts.

Fortress must audit that state honestly and guide convergence.

## Onboarding is not “run every rule”

Dumping tens of thousands of violations on a legacy project is not useful migration governance.

Fortress must reconstruct enough engineering structure to determine **which invariants must be established first**.

## Observation before prescription

Initial forensic scan should collect:

- languages and runtimes;
- packages/workspaces;
- build systems;
- applications/services;
- entrypoints;
- persistence;
- infrastructure;
- source dependency graph;
- tests;
- docs;
- generated artifacts;
- CI/CD;
- public surfaces;
- observed conventions;
- policy contradictions;
- probable components;
- probable duplicated responsibilities.

This produces an **Observed Repository Model**.

## Knowledge states

Onboarding data must distinguish:

- `OBSERVED`;
- `INFERRED`;
- `RATIFIED`;
- `UNKNOWN`.

Architecture inference receives confidence.

Fortress must not silently convert clustering heuristics into project law.

## Observed versus target architecture

Onboarding maintains:

- observed state;
- target Fortress model.

The gap becomes the migration plan.

Sometimes no coherent hidden architecture exists; the target architecture must be deliberately designed.

## Convergence graph

Onboarding progress is phase/invariant based, not violation-count based.

Recommended prerequisite progression:

1. Repository Discovery
2. System / Archetype Classification
3. Architecture Establishment
4. Component and Source Ownership
5. Dependency Governance
6. Feature / Contract Model
7. Requirement Traceability
8. Test Governance
9. Documentation Governance
10. Source / Tool Convention Normalization
11. Generated Artifact and Pipeline Governance
12. Certification Closure

The exact execution may branch where prerequisites permit, but later rule families activate only when their foundations are sufficiently authoritative.

## Violation activation states

Rules/findings during onboarding may be:

- `LOCKED` — prerequisites not established;
- `PROVISIONAL` — useful hypothesis but not authoritative;
- `ACTIVE` — rule is actionable;
- `SATISFIED`;
- `INAPPLICABLE`;
- `UNSUPPORTED`.

This prevents false precision.

## Progress is not violation count

A later stage may expose far more violations because Fortress understands more of the system.

A repository at Dependency Governance with 900 active findings is objectively farther through onboarding than one still at Architecture Establishment with 12 visible findings if the former has certified all earlier stages.

Primary progress is therefore:

- highest certified convergence stage;
- completed prerequisite invariants;
- current frontier;
- blocking migration units.

A global “percent certified” is prohibited.

## Revealed versus introduced violations

Fortress tracks separately:

- newly revealed existing violations;
- violations actually introduced by migration work;
- violations resolved.

An increase in revealed violations may indicate better knowledge.

An increase in introduced violations inside a governed region is regression.

## Migration baseline

Initial onboarding creates a fingerprinted baseline.

The baseline may record extensive unresolved debt but MUST say **NOT CERTIFIED**.

It exists to preserve historical state and enable ratcheting.

## Ratchet

After baseline:

- existing bounded violations may temporarily remain;
- new violations in governed scope are prohibited;
- clean components cannot regress;
- the strict perimeter expands monotonically.

## Causal remediation groups

Fortress groups findings by structural cause.

For example, `MIG-001 Establish component ownership` may unlock hundreds of dependency and documentation findings.

Migration ordering optimizes prerequisite correctness, not easy warning-count reduction.

## Migration DAG

Onboarding work units have dependencies.

Fortress should expose the next eligible migration work rather than globally sorting every finding.

`fortress onboard next` can return a bounded dependency-valid migration unit suitable for a human or AI agent.

## Authorized temporary degradation

Correct architecture surgery may temporarily create downstream issues.

A transition contract may authorize bounded temporary consequences, but must define exact scope, target state, completion evidence, and retirement condition.

Temporary degradation is not certification.

## Policy contradictions

Fortress should detect conflicting existing sources such as CONTRIBUTING versus EditorConfig, formatter versus linter, documented architecture versus observed imports, or CI policy versus local tooling.

Migration establishes a canonical Fortress authority and reconciles projections.

## AI-assisted remediation

Fortress should deliberately produce bounded work suitable for AI, such as classifying ambiguous files, generating missing docs, adding requirement IDs, breaking dependency boundaries, or normalizing tool configuration.

Fortress supplies context and verifies the result.

## Historical violation identity

Violations should preserve temporal identity where practical: first detected, baseline, owner/component, rule, remediation change, and resolved time.

Onboarding becomes auditable engineering history.

## Completion

Onboarding ends only when all mandatory applicable convergence stages close and full certification passes.

At completion:

- no onboarding-only legacy allowances remain;
- target architecture is authoritative;
- full certification baseline is created;
- the project transitions to ordinary temporal governance.

## Goal

Fortress onboarding is a **convergence engine**, not a warning counter.

It creates disciplined engineering structure procedurally in repositories that did not previously possess it.
