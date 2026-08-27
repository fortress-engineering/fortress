# 00 — Product Definition

**Status:** Normative product definition
**Authority class:** Constitutional

## Product identity

**Product:** Fortress
**Formal standard:** Fortress Engineering Standard
**CLI:** `fortress`
**Organization:** Fortress Engineering
**GitHub organization:** `fortress-engineering`

Fortress is an **executable engineering control plane for software repositories and software systems**. It combines a versioned engineering standard with an auditing engine, architecture and contract model, workflow runtime, incremental certification system, temporal development ledger, onboarding convergence engine, and integrations with specialized language and tool ecosystems.

Fortress does not merely ask whether source code passes tests. It asks whether the entire engineering system is coherent enough to certify.

## Product thesis

Modern AI has materially reduced the scarcity of implementation throughput. A capable agent can produce substantial quantities of locally good code quickly, but neither humans nor AI can reliably reconstruct and reason over all architectural relationships, historical decisions, contracts, documentation, tests, dependencies, deployment rules, and cross-language semantics of a very large codebase on every change.

Fortress externalizes that missing global memory into explicit, machine-readable structure.

> **Fortress turns engineering architecture and governance from informal intentions into executable, certifiable properties of a living software system.**

Its purpose is to make high-volume development compatible with long-term global coherence.

## What Fortress governs

Fortress treats a project as an engineering system containing, where applicable:

- archetypes and capabilities;
- components and architectural zones;
- product features and subfeatures;
- normative requirements;
- source files and substantive symbols;
- public APIs;
- language and runtime surfaces;
- internal and external dependencies;
- tests and conformance fixtures;
- documentation;
- generated artifacts;
- development commands;
- long-running jobs;
- pipelines and deployment environments;
- change contracts;
- project invariants and architecture decisions;
- certification units and evidence.

The repository is evidence of that system, not merely a bag of files.

## Three governance modes

### Snapshot governance

Fortress audits and certifies the current state of the engineering system. It verifies that observed source, architecture, contracts, dependencies, tests, documentation, tooling, generated artifacts, and certification evidence agree with the declared model.

### Temporal governance

Fortress models software development as authorized state transitions rather than unstructured diffs. Intent becomes a change contract; implementation is checked against that contract; resulting state and evidence are preserved in a temporal ledger.

### Onboarding governance

Fortress can enter a repository that was not designed for Fortress, reconstruct its observable engineering system, distinguish observation from inference and ratification, establish a target architecture, build a dependency-ordered convergence plan, maintain a migration ratchet, and guide the repository to full certification.

## Applicability

Fortress MUST be suitable for systems ranging from a small single-language utility package to a multi-runtime engineering system containing libraries, packages, CLIs, frontend applications, backend services, persistence, workers, compilers, language bindings, infrastructure-as-code, containers, cloud deployment, and multiple package ecosystems.

Fortress achieves this through **archetype-based decomposition**, not by weakening the standard for complex systems or imposing irrelevant architecture on simple ones.

## Standard plus engine

Fortress consists conceptually of four layers:

1. **Fortress Engineering Standard** — normative rules and archetype/capability definitions.
2. **Fortress Project Model** — the declared model of a particular engineering system.
3. **Fortress Runtime** — the control plane that audits, builds, tests, runs, certifies, manages jobs, manages pipelines, and exposes project commands.
4. **Fortress Evidence** — content-addressed records proving what was analyzed or executed against what exact inputs.

The standard is authoritative over the implementation. A bug in the Fortress implementation does not redefine the standard.

## Relationship to specialized tools

Fortress MUST NOT unnecessarily reimplement mature specialized tools. It should integrate formatters, type checkers, language linters, compilers, security scanners, test frameworks, mutation systems, package managers, and CI providers.

Fortress owns:

- policy selection;
- conflict reconciliation;
- canonical configuration;
- applicability;
- normalized findings;
- architecture and contract rules specialized tools do not understand;
- orchestration;
- certification;
- evidence and provenance.

Specialized tools supply domain-specific analysis or execution.

> **Other tools enforce individual facts. Fortress decides whether the engineering system as a whole satisfies a coherent standard.**

## Certification meaning

There is one final certification meaning:

- **CERTIFIED**
- **NOT CERTIFIED**

Migration readiness, stage progress, and partial subsystem status may be reported, but MUST NOT be represented as weaker certification tiers such as “80% certified,” Bronze, Silver, or Gold.

A certification claim always names the exact Fortress Standard edition and applicable project/archetype model.

## Universal auditability versus deep certification

Fortress SHOULD perform useful repository-level analysis on arbitrary repositories even when no deep analyzer exists for a language or framework.

Fortress MUST NOT claim full semantic source certification for properties it cannot inspect reliably. Unsupported deep analysis is reported as unsupported or blocking, never silently skipped.

## Local-first requirement

Core Fortress operation MUST be locally usable and MUST NOT require a hosted Fortress service. Network integrations may check releases, execute remote jobs, or retrieve external evidence, but local auditing, project modeling, affected analysis, certification verification, and core development workflows remain first-class.

## Non-goals

Fortress is not:

- a generic hosted project-management SaaS;
- a replacement for Git;
- a replacement for every compiler, linter, package manager, or scanner;
- a security product merely because it integrates security certification;
- a single universal application architecture imposed on all software;
- an AI code generator;
- a scoring system that hides violations behind aggregate percentages;
- a mechanism for accepting arbitrary exceptions until code passes.

## Defining product outcome

A mature Fortress-governed repository should be able to answer mechanically:

- What is this system?
- What archetypes and components does it contain?
- Which feature owns this file and symbol?
- What may this feature depend on?
- Why does this file exist?
- Which requirements define this behavior?
- Which tests prove those requirements?
- Which documentation explains them?
- What will this change affect?
- Which certifications became stale?
- What is running now?
- Can this long job resume?
- What exact evidence certified this release?
- What was the project architecture historically?
- Which rule changed and why?
- How did an incoherent legacy system converge to this state?

That answerability is a defining feature of Fortress.
