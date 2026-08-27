# Naming and stable identity convention

**Status:** Draft standard-design authority
**Authority class:** Standard architecture
**Governing rule:** `STD-ID-001`

## Purpose

This document separately designs the initial naming conventions needed for
deterministic Fortress identity and repository navigation. It does not infer a
universal casing rule from examples, and it does not prescribe one spelling
style across programming languages.

## Stable serialized identities

Machine-readable Fortress entity IDs use uppercase ASCII segments separated by
ASCII hyphens. Every ID contains a recognized namespace followed by at least one
non-empty uppercase alphanumeric segment. Examples include:

- `ARCH-DEPENDENCY-001` — standard rule;
- `PF-PROJECT-MODEL-0001` — product feature;
- `AF-STANDARD-REGISTRY-0001` — architecture/foundation capability;
- `TF-CLI-0001` — tooling capability;
- `T-TF-CLI-0001-R01-001` — test identity;
- `DOC-AUTHORITY-0001` — documentation artifact;
- `INV-ARCH-0001` — project invariant;
- `CHG-BOOTSTRAP-0001` — change record;
- `CERT-BOOTSTRAP-TEST` — certification unit.

Uppercase ASCII avoids locale-dependent case folding and produces one
case-sensitive interchange form. Hyphens make segments legible across JSON,
TOML, YAML, CLI, and documentation surfaces. These conventions optimize stable
cross-language identity, not source-code aesthetics.

Initial namespaces are `ARCH`, `DEP`, `CONTRACT`, `SRC`, `DOC`, `TEST`, `CERT`,
`PIPE`, `CHANGE`, `ONBOARD`, `SEC`, `REPO`, and `STD` for rules; `PF`, `AF`, and
`TF` for feature/capability ownership; and `T`, `INV`, `CHG`, `TRANS`, `CERT`,
`EX`, `ADR`, `DOC`, and `CMD` for their corresponding contract classes.

IDs are immutable after publication and must never be reused for different
semantics. Human-readable titles may evolve while their stable meaning remains
compatible.

## Repository paths

Fortress-controlled directory and ordinary document names use lowercase ASCII
with hyphens between words. Ecosystem-defined names such as `Cargo.toml`,
`README.md`, `AGENTS.md`, and Rust crate/module conventions retain their
established spelling because adoption friction and tool compatibility outweigh
artificial cross-language sameness.

## Language projections

Each language profile must select its own idiomatic source naming rules and give
a tooling, semantic, safety, or adoption rationale for divergence. The Rust
implementation follows Rust ecosystem naming. Future TypeScript and Python
profiles may differ where their ecosystems require it. No source-language rule
may change the canonical serialized identity format.

## Explicitly arbitrary choices

Where two spellings are materially equivalent, the standard may choose one
solely to eliminate variation. Such choices must be described as entropy
reduction, not justified with invented semantic claims.
