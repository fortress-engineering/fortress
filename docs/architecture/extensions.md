# 16 — Extension and Ecosystem Model

**Status:** Normative extension architecture
**Authority class:** Operational architecture

## Purpose

Fortress must be extensible enough to support languages, frameworks, analyzers, tools, archetypes, provider integrations, commands, and organizational policies not known when Fortress 1.0 ships.

Extensibility must not permit plugins to silently redefine Fortress semantics or compromise certification trust.

## Extension classes

Fortress should support versioned extension classes such as:

- language analyzer;
- framework detector;
- tool adapter;
- package-manager adapter;
- CI/CD provider;
- archetype/capability pack;
- project command pack;
- certification provider;
- IDE integration.

## Extension manifest

Every extension declares:

- identity;
- version;
- extension class;
- Fortress protocol versions supported;
- claimed capabilities;
- required permissions;
- external executables/services used;
- deterministic/non-deterministic behavior;
- trust/conformance metadata.

## Capability negotiation

Fortress must not assume an extension implements capabilities it does not declare and certify.

Example analyzer capabilities might include:

- symbol inventory;
- imports;
- visibility;
- documentation parsing;
- public API extraction;
- complexity metrics.

Rules requiring unsupported capabilities become unsupported or use another analyzer; they do not silently pass.

## Extension conformance

Third-party extensions used for protected certification SHOULD pass an appropriate Fortress extension conformance suite.

Conformance validates protocol correctness, deterministic serialization, source-location integrity, failure handling, and claimed capabilities.

## Trust

Extensions are code and may be unsafe or malicious.

Fortress must support trust policy distinguishing:

- first-party bundled extension;
- signed/certified third-party extension;
- explicitly trusted local extension;
- untrusted extension.

Untrusted extensions may be usable for exploratory audits but cannot automatically satisfy protected certification requirements.

## Isolation

Where practical, third-party extensions should run out-of-process or in another bounded execution environment rather than sharing unrestricted memory with the Fortress core.

The architecture should leave room for sandboxing without making sandbox support a prerequisite for every initial first-party integration.

## Versioned protocols

Extensions communicate through versioned, language-neutral contracts where practical.

A Fortress upgrade must be able to determine whether installed extensions remain compatible.

## Archetype packs

External organizations may define additional archetypes or stricter profiles.

An archetype pack may extend Fortress rules but cannot silently weaken mandatory Fortress Core behavior.

## Project-specific extensions

A project may add local rules, commands, or analyzers.

Local extensions remain part of the project fingerprint and certification model.

A local rule is still governed: it receives identity, applicability, evidence, tests, and history.

## Distribution

The distribution mechanism should not be permanently tied to one language package manager.

Fortress may support a registry/index later, but the core extension format should be transport-independent and locally installable.

## Upgrade safety

An extension upgrade is an engineering input change.

If certification-relevant behavior may change, affected certifications become stale.

## Standard versus extension authority

The Fortress Standard remains authoritative over the semantics of its rules.

Extensions provide facts, execution, or additional stricter rules. They do not redefine existing rule meaning.

## Goal

The extension model should allow Fortress to grow toward arbitrary languages and project forms without fragmenting into independent incompatible Fortress implementations.
