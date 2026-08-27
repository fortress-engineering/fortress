# 15 — Language, Analyzer, and Tool Adapter Architecture

**Status:** Normative analyzer and adapter architecture
**Authority class:** Operational architecture

## Purpose

Fortress aims to audit arbitrary repositories while preserving one coherent standard across languages and specialized tools.

It therefore requires a layered analyzer and adapter architecture.

## Universal analysis

Fortress should perform useful analysis independent of programming language, including:

- repository topology;
- file placement;
- docs and contracts;
- package/build manifests;
- CI/CD files;
- generated artifacts;
- temporal ledger;
- certification integrity;
- ownership declarations;
- dependency metadata available from manifests.

Unsupported language semantics must not make all repository auditing impossible.

## Language analyzers

Language analyzers provide deeper facts such as:

- AST structure;
- symbols;
- imports/references;
- visibility;
- public API;
- type declarations;
- documentation;
- naming;
- complexity;
- suppression directives.

Analyzers emit canonical Fortress observations rather than private ad hoc output.

## Initial first-party languages

The first stable Fortress implementation SHOULD provide deep first-party support for:

- Rust;
- TypeScript/JavaScript;
- Python.

These languages provide strong test coverage across systems, dynamic/high-level, and mainstream web/package ecosystems.

This initial set does not limit Fortress's architectural applicability.

## Unsupported languages

If a deep analyzer is unavailable, Fortress must say exactly what is and is not certified.

Example:

```text
Repository-level analysis       COMPLETE
Generic source analysis         COMPLETE
Semantic source analysis        UNSUPPORTED
Full Fortress certification     BLOCKED
```

Fortress MUST NOT silently skip required semantic checks.

## Analyzer protocol

A versioned analyzer protocol should define:

- supported language/version range;
- capabilities;
- input root/files;
- canonical symbol representation;
- dependency edges;
- source spans;
- docs metadata;
- findings/observations;
- deterministic behavior;
- analyzer version/provenance.

## Third-party analyzers

Third parties may provide analyzers for additional languages/frameworks.

A third-party analyzer is not automatically trusted for protected certification.

It must pass the Fortress Analyzer Conformance Suite for the capabilities it claims.

## Tool adapters

Tool adapters wrap specialized systems such as:

- formatters;
- linters;
- compilers;
- type checkers;
- package managers;
- test runners;
- mutation frameworks;
- fuzzers;
- security scanners;
- dependency/license scanners.

Adapters translate canonical Fortress policy into invocation/configuration and normalize resulting evidence/findings.

## Canonical policy, generated configuration

Fortress policy is authoritative.

Tool-specific configuration may be generated or validated as a projection.

Possible operations:

```text
fortress configure
fortress configure --check
```

A project should not maintain incompatible independent policies merely because different tools use different file formats.

## Toolchain pinning

Certification-relevant tool versions and meaningful configuration must be fingerprinted.

The standard/profile may define accepted version ranges while the project lock records exact resolved tools for reproducibility.

## Native process integration

External tools may execute as subprocesses, through libraries, containers, or providers.

The adapter contract must expose:

- command/tool identity;
- version;
- normalized config;
- inputs;
- outputs;
- failure classification;
- evidence extraction.

## Analyzer independence

A language analyzer reports facts.

It should not independently decide general Fortress architecture meaning.

For example, the TypeScript analyzer may report imports and symbols; the Fortress dependency evaluator decides whether an import violates a feature contract.

## IDE/LSP integration

Fortress should eventually expose normalized findings through an IDE/LSP-compatible interface.

Developers should see stable Fortress rules such as `ARCH-*`, `DOC-*`, or `SRC-*` even when the underlying evidence came from several tools.

## Goal

The adapter architecture lets Fortress become the coherent policy and certification layer above a diverse development ecosystem without recreating every specialized tool or allowing each tool to define project policy independently.
