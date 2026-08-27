# 06 — Rule System

**Status:** Normative rule architecture
**Authority class:** Standard architecture

## Rule purpose

A Fortress rule is a stable engineering requirement with explicit applicability and enforcement.

Rules may be implemented by Fortress-native analysis, an integrated external tool, multiple tools, a project-model consistency check, or certification evidence.

The rule meaning belongs to Fortress, not to the external tool.

## Rule record

Every released rule must include:

- stable rule ID;
- title;
- normative statement;
- rationale;
- failure prevented;
- applicability;
- category;
- integrity tier;
- evaluation method;
- required analyzer/tool capabilities;
- canonical finding shape;
- remediation guidance;
- valid example;
- invalid example;
- exception policy;
- introduced version;
- revision history.

## Integrity tiers

Tiers classify consequence, not whether a failure is optional.

### Tier 0 — Certification Integrity

Examples:

- invalid attestation;
- stale input fingerprint;
- corrupt evidence;
- missing standard digest;
- certification graph inconsistency.

### Tier 1 — Architecture Integrity

Examples:

- undeclared dependency;
- ownership violation;
- illegal layer crossing;
- dependency cycle;
- public contract drift.

### Tier 2 — Behavioral Integrity

Examples:

- failing normative requirement;
- missing test ID;
- incomplete requirement coverage;
- conformance divergence;
- required mutation/fuzz evidence missing.

### Tier 3 — Source Integrity

Examples:

- formatting;
- strict typing;
- naming;
- symbol documentation;
- complexity;
- unsafe constructs.

### Tier 4 — Repository and Process Hygiene

Examples:

- stale generated artifact;
- untracked TODO;
- wrong file placement;
- incomplete document structure;
- invalid metadata.

A mandatory Tier 4 failure still blocks certification.

## Normalized findings

Fortress produces a canonical finding regardless of which analyzer or external tool detected the underlying problem.

A finding should include:

- finding identity;
- Fortress rule ID;
- severity/tier;
- language;
- path;
- source span and symbol where applicable;
- message;
- source analyzer/tool provenance;
- standard edition;
- project entity ownership;
- remediation;
- exemption state;
- temporal metadata where tracked.

External tool codes remain provenance rather than the primary project vocabulary.

## Tool-policy synthesis

Fortress defines canonical engineering policy and projects it into tool-specific configuration.

Examples include:

- TypeScript naming through linter rules;
- Python typing through a configured type checker;
- Rust formatting through rustfmt;
- repository-wide whitespace conventions through EditorConfig.

The project should not independently maintain contradictory policies across each tool.

## Rule compatibility analysis

Before Fortress publishes a standard/profile, it must check for overlapping and contradictory tool rules.

Examples:

- formatter emits lines a separate hard rule rejects;
- generic naming rule demands camelCase while language convention demands snake_case;
- one linter requires annotations another forbids.

Unresolved contradictions block standard/profile release.

## Language idiom

Fortress aims for coherent strictness, not one spelling convention across all languages.

Language profiles encode appropriate conventions. CamelCase may be correct in TypeScript while snake_case is correct in Python.

The common standard principle is idiomatic consistency.

## Hard gates

Released mandatory rules are hard gates unless inapplicable or explicitly exempted according to the standard.

Warnings must not accumulate as accepted background noise. If a rule is intentionally advisory, the rule contract says so explicitly.

## Suppression discipline

Inline suppression of an underlying tool does not resolve a Fortress finding unless Fortress recognizes a valid exemption or rule-specific rationale contract.

Every suppression must be visible to the Fortress model.

## Complexity rules

Complexity thresholds may be very strict defaults, but they must support governed exceptions where decomposition would reduce correctness or clarity.

Fortress must not optimize a metric by forcing worse design.

## Documentation rules

Documentation rules may require file-level purpose, symbol purpose, parameters, return values, thrown/error behavior, invariants, safety notes, side effects, concurrency semantics, and examples.

Language profiles translate expectations into JSDoc, docstrings, rustdoc, XML docs, or other idiomatic forms.

## Rule implementation tests

Every Fortress rule must have conformance evidence appropriate to the rule, including:

- valid fixture;
- invalid fixture;
- boundary fixture;
- expected canonical finding;
- exemption case where allowed;
- conflict case where relevant.

A rule is not complete because one implementation function returns the desired result on one repository.

## Rule evolution

A rule ID remains stable only while core meaning remains compatible.

A materially different rule receives a new ID or major-version treatment.

Historical certifications retain the exact meaning of the standard edition under which they were produced.

## Project-specific rules

Projects may add rules such as:

> The canonical semantic core may never depend on adapters.

Project rules use the same contract, finding, evidence, and exemption machinery.

They may strengthen Fortress but cannot silently reinterpret Fortress rules.

## Goal

The rule system gives projects one stable engineering vocabulary even when enforcement is distributed across many specialized tools.
