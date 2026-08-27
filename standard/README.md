# Fortress Engineering Standard source

**Status:** Normative bundle repository

**Authority class:** Standard architecture

This directory contains machine-readable Fortress Engineering Standard bundles.

- `drafts/` contains mutable, explicitly pre-release candidate work.
- `versions/` is reserved for immutable released editions and is intentionally
  absent until a standard edition is authorized and released.

Moving a bundle into `versions/` requires schema and conformance validation, a
canonical digest, release authorization, and an immutable edition identity.
Released contents must never be edited in place. A correction that changes
normative meaning requires a new edition.

The prose design authorities live under [`docs/standard/`](../docs/standard/).
Machine-readable bundles encode those authorities and do not supersede the
constitutional product definition or engineering philosophy.
