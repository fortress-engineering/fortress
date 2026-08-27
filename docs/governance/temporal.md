# 10 — Temporal Engineering Governance

**Status:** Normative temporal-governance architecture
**Authority class:** Temporal governance

## Principle

Fortress does not treat software development as a sequence of unexplained diffs.

It models development as a sequence of declared, impact-analyzed, evidence-backed state transitions.

A repository state `S0` changes to `S1` through an authorized change contract `C1`.

Fortress may certify both the resulting state and the transition itself.

## Change lifecycle

A Fortress change progresses through a state machine such as:

```text
INTENT
  ↓
ANALYZED
  ↓
PLANNED
  ↓
AUTHORIZED
  ↓
IN_PROGRESS
  ↓
VERIFYING
  ↓
CERTIFIED
  ↓
ARCHIVED
```

Additional states may include BLOCKED, REJECTED, SUPERSEDED, or CANCELLED.

## Intent

Intent may be incomplete human language.

Example:

> Add a search bar.

Fortress accepts this as a request, not as a sufficient engineering plan.

## Planned change contract

Analysis converts intent into an explicit transition contract containing:

- stable `CHG-*` ID;
- baseline fingerprint;
- objective and rationale;
- affected archetypes/components/features;
- proposed new entities;
- requirements added/changed/removed;
- expected implementation surfaces;
- dependency changes;
- public API impact;
- security implications;
- documentation impact;
- test obligations;
- expected stale certifications;
- migration/compatibility implications;
- non-goals;
- decisions/blockers;
- authorization requirements.

An AI may help draft the plan, but Fortress validates its structural completeness.

## Change contract drift

During implementation, observed impact is compared with the authorized plan.

If implementation introduces an undeclared dependency or touches a new component outside scope, Fortress reports **change contract drift**.

Resolution:

- expand and reauthorize the contract;
- remove the unintended impact.

Scope may evolve, but not silently.

## Executed change record

Completion records:

- actual files/symbols changed;
- actual dependency changes;
- actual contracts changed;
- actual tests/docs changed;
- certifications rerun;
- plan deviations;
- completion evidence;
- resulting repository fingerprint;
- resulting state certification.

## Canonical storage

Project change records should live in a governed repository structure such as:

```text
.fortress/changes/
├── active/
└── archive/
    └── YYYY/
```

Machine-readable records are canonical. Generated human summaries and GitHub Issues are projections.

## GitHub integration

A Fortress change may synchronize with GitHub Issues or Projects for discussion, assignment, notification, and community participation.

GitHub prose is not the canonical engineering contract unless imported and ratified into Fortress.

This keeps Fortress provider-independent.

## Project invariants

Projects define durable rules using stable `INV-*` identities.

An invariant includes normative statement, rationale, scope, effective period/version, enforcement, originating change/ADR, superseded version, and migration implications.

Example:

> Persistence clients may only be created by infrastructure factories.

## Temporal validity

Fortress preserves what a rule meant historically.

A rule may evolve:

`INV-0031 v1 → INV-0031 v2`

The old rule remains historical evidence rather than being erased.

## Rule changes are changes

Changing a project invariant itself requires a change contract.

The change computes architecture impact and may create an explicit migration.

The rules governing change are themselves changed through governed change.

## Transition contracts

Large architecture migrations may use `TRANS-*` records.

A transition defines current state, target state, temporary allowed deviations, completion evidence, retirement condition, and affected entities.

Temporary violations exist only within a bounded transition and do not constitute certification.

## Historical queries

Fortress should eventually support queries such as:

- `fortress history <entity>`;
- `fortress why <path-or-symbol>`;
- `fortress changes <feature>`;
- `fortress invariant history <id>`.

The goal is to answer **why** something exists, not merely who changed a line.

## Release records

A release is a certified cut through the temporal ledger.

A release record includes the previous baseline, included changes, new/changed/deprecated features, invariant changes, architecture changes, certification baseline, and resulting fingerprints.

## Change dependency graph

Changes may depend on other changes.

Fortress can determine readiness from the change DAG.

A change cannot become Ready while prerequisite engineering contracts remain unresolved.

## Temporal ledger versus Git

Git remains implementation history.

Fortress maintains engineering history.

They complement rather than replace one another.

## Goal

Temporal governance prevents a system from becoming incoherent through thousands of individually reasonable but globally untracked changes.

Fortress certifies not only:

> “This repository is coherent.”

but also:

> **“This is the declared and verified path by which it became this repository.”**
