# 01 — Engineering Philosophy

**Status:** Normative engineering philosophy
**Authority class:** Constitutional

## Governing premise

Fortress begins from the observation that software quality is not equivalent to local code correctness.

A codebase may be formatted, strongly typed, fully unit-tested, documented, and performant and still be globally incoherent because architectural boundaries, dependency intent, feature ownership, public contracts, generated artifacts, pipeline behavior, and historical decisions have drifted apart.

> **Correctness is necessary but insufficient. Coherence is a release requirement.**

## Nothing important remains implicit

If a relationship materially affects the safety, maintainability, behavior, architecture, or evolution of the project, Fortress should seek to represent it explicitly and mechanically.

Examples include feature ownership, dependency permission, architecture direction, normative behavior, test obligations, documentation ownership, public API guarantees, tool configuration, generated-artifact authority, certification dependencies, migration exceptions, commands, and pipeline prerequisites.

The purpose is not bureaucracy. The purpose is to eliminate hidden relationships that become expensive or impossible to reconstruct at scale.

## Specification sovereignty

Normative specifications and explicitly versioned contracts define intended behavior.

Implementation, generated output, historical fixtures, AI-generated prose, tests, and reference implementations provide evidence but do not silently become the specification.

Expected conformance output MUST NOT be generated from an implementation and then used as the normative oracle for that same implementation.

## Architecture is data

Architectural intent must be representable as machine-readable relationships.

A statement such as “domain components should not depend on persistence adapters” is incomplete until Fortress can inspect the observed dependency graph and determine whether it is true.

Folder structure, component hierarchy, public/private surfaces, dependency direction, ownership, and transition exceptions are therefore certifiable data.

## Strictness without architecture theater

Fortress intentionally targets unusually strict engineering standards. Strictness MUST be semantically justified.

Fortress MUST NOT:

- require meaningless contract edits because a pure refactor occurred;
- force object-oriented class structures onto languages where they are inappropriate;
- demand irrelevant service layers for a tiny pure library;
- optimize a metric at the expense of clarity or correctness;
- treat warnings as proof of architectural defects without context.

A pure refactor may correctly result in no contract changes if Fortress can prove that semantic, public, ownership, and dependency relationships remain unchanged.

## Strictness scales by decomposition

A tiny library and a large distributed platform can both be Fortress Certified.

The standard does not become weaker for the larger system. Fortress decomposes the system into applicable archetypes, capabilities, components, boundaries, and feature contracts and certifies each relevant layer.

Complexity expands the certification graph; it does not dilute certification meaning.

## The repository as a living system

Fortress treats the repository as both a structural state and a sequence of governed transformations through time.

Software rarely becomes incoherent because of one obviously disastrous commit. It becomes incoherent through thousands of locally reasonable changes whose cumulative effects are not tracked.

Fortress therefore governs both current state and state transition.

## Post-AI engineering

Fortress is explicitly designed for an environment in which AI can generate and modify code at high volume.

AI is strong at bounded tasks but can be inconsistent across tasks and cannot reliably hold the full architecture of a million-line system in working context.

Fortress should provide the externalized engineering memory AI lacks: exact context, allowed dependencies, reverse dependents, applicable rules, contracts, tests, docs, rationale, and expected certification impact.

The intended division of labor is:

**Fortress**
- defines and exposes coherence;
- constrains work;
- computes impact;
- detects inconsistency;
- verifies completion.

**AI or human implementers**
- perform bounded engineering work inside those constraints.

## Governance becomes procedural

Fortress seeks to replace recurring ambiguous questions with deterministic operations.

Instead of “what might this change affect?” use `fortress affected`.

Instead of “are we probably ready to release?” use `fortress certify --all`.

Instead of “which of these thousands of legacy violations should we fix?” use the dependency-valid onboarding frontier.

Instead of “what does strict Python mean here?” use the pinned Fortress language/tool policy.

## One coherent policy over fragmented tools

Independent development tools frequently overlap or disagree. Fortress MUST reconcile these conflicts into one canonical project policy.

Underlying tools remain provenance sources; Fortress rules provide the stable issue vocabulary and certification interpretation.

## Exceptions are governed debt

Every consequential suppression, waiver, transitional boundary, coverage exception, or temporary architecture violation must have stable identity, scope, rule affected, rationale, owner, start, and retirement or expiration condition.

An exception does not rewrite the rule.

## Honest knowledge states

Fortress MUST distinguish observed facts, inferred hypotheses, ratified declarations, provisional findings, active violations, and unsupported analysis.

This is essential during onboarding. Fortress must never turn confidence into false certainty merely to produce a cleaner report.

## Monotonic governance

Once a repository has certified a foundational invariant, ordinary subsequent development MUST NOT silently weaken it.

A stronger standard may expose downstream work. An authorized architecture transition may temporarily invalidate a bounded area. But completed foundational governance should otherwise ratchet monotonically.

## Evidence over assertion

A statement that “this project passes” is not trusted merely because a tool wrote it.

Certification is bound to exact inputs, dependency closure, toolchain identity, standard edition, certification definition, result, evidence digests, and provenance.

## Self-application

Fortress must progressively apply Fortress to itself.

A proposed general rule should survive the question: **Are we willing to require this of Fortress itself indefinitely?**

The Fortress repository is both implementation and continuous falsification environment for the Fortress philosophy.

## Engineering convention doctrine

**Source:** Added as a task-authorized bootstrap supplement during permanent
promotion. This doctrine was not part of the temporary packet artifact.

Fortress exists to reduce software entropy and make engineering coherence
procedural and mechanically verifiable. When establishing a convention or rule,
use this priority:

1. **Meaningful engineering strategy first.** Prefer a defensible architectural,
   semantic, reliability, maintainability, interoperability, security,
   performance, or correctness rationale.
2. **Consistency and entropy reduction second.** If alternatives are materially
   equivalent, choose one canonical convention and enforce it instead of
   permitting arbitrary variation.
3. **Lowest adoption friction as the tie-breaker.** Among strategically
   equivalent choices, prefer established ecosystem conventions and
   least-surprising behavior unless a stronger cross-project principle justifies
   divergence.
4. **Language-agnostic structure where feasible.** Ownership, feature hierarchy,
   contracts, folder responsibilities, dependency direction, documentation
   classes, change records, and certification should converge across languages
   when doing so is not harmful or unnatural.
5. **Language-specific divergence requires a reason.** Do not diverge merely
   from habit, but do not force sameness when language semantics, tooling,
   packaging, safety, or adoption cost justify idiomatic design.
6. **Arbitrary conventions may be explicitly arbitrary.** When no strategic
   distinction exists, say that a convention exists to eliminate variation
   instead of inventing a false rationale.

Naming rules are designed and encoded separately. Examples do not establish a
universal casing rule. A language profile may select an idiomatic convention,
while cross-language serialized identities may use a distinct canonical form
for deterministic interchange.

When stronger Fortress capabilities expose weaknesses in Fortress itself,
refactor through explicit change records and tests. Such self-hardening is
progress when the architectural or entropy-reduction reason is stated. Avoid
gratuitous churn and preserve no incoherent structure merely to avoid justified
remediation.

## Final principle

The desired property is not that bugs become mathematically impossible.

The desired property is:

> **Important relationships become difficult to keep invisible.**

Fortress makes the engineering system explicit enough that humans and AI can change it at high velocity without treating global coherence as an act of memory or faith.
