# 20 — Versioning, Compatibility, Locks, and Upgrades

**Status:** Normative versioning and upgrade architecture
**Authority class:** Release scope

## Distinct versions

Fortress must distinguish at least:

- Fortress CLI/engine version;
- Fortress Engineering Standard edition;
- schema/protocol versions;
- analyzer/extension versions;
- project package/release versions.

Equal numbers do not imply identical compatibility responsibility.

## Initial stable standard

The first stable public standard is **Fortress Engineering Standard 1.0.0**.

During development, the repository may use pre-release/draft identities, but it must not claim final 1.0 certification until the standard and implementation meet the 1.0 release criteria.

## Project pin

A project declares a standard version and immutable digest.

Conceptually:

```toml
[fortress]
standard = "1.2.0"
```

A lockfile records exact resolved standard/tool protocol identity, conceptually:

```text
standard = 1.2.0
standard_digest = sha256:...
```

## Newer CLI with older standard

A newer Fortress executable must be able to certify an older supported standard edition without silently applying newer requirements.

Example:

```text
Fortress CLI: 1.8.4
Pinned Standard: 1.2.0
Latest Standard: 1.3.0
Certification against 1.2.0: PASS
Update available: informational warning
```

## Standard immutability

A released standard bundle is immutable.

Corrections that alter normative meaning require a new edition.

Historical certifications remain interpretable under the exact edition they claimed.

## Standard SemVer

### Patch

May repair tooling/schema defects or clarify wording without intentionally adding material new compliance obligations.

### Minor

May add or strengthen compatible 1.x rules and can require repository remediation.

### Major

May alter fundamental certification, authority, contract, or compatibility principles.

## Upgrade planning

`fortress upgrade --to <version> --plan` should report:

- new applicable rules;
- changed applicable rules;
- removed/deprecated rules;
- affected archetypes/capabilities;
- affected project entities;
- expected stale certifications;
- predicted compliance failures;
- migration prerequisites.

The command is read-only unless an explicit apply operation is requested.

## Upgrade activation

The project remains certified against its old standard until it deliberately changes its standard pin.

Once it pins a new edition, new mandatory rules become hard gates.

There is no silent grandfathering under the new claim.

## Offline behavior

Certification does not require contacting Fortress Engineering to discover whether a newer edition exists.

Latest-version checks are optional metadata and may use cached signed release information.

Network failure must not invalidate an otherwise reproducible pinned certification.

## Protocol compatibility

Standard schemas, analyzer protocols, extension protocols, and attestation formats are independently versioned.

Fortress must negotiate or reject incompatible protocol versions explicitly.

## Deprecation

Rules, archetypes, commands, or protocols may be deprecated before removal.

Deprecation must state:

- replacement;
- effective version;
- planned removal boundary;
- migration guidance.

## Release channels

The implementation may use development, prerelease, and stable channels, but protected certification must record the exact engine identity.

## Goal

Versioning should let Fortress evolve aggressively while preserving the ability to reproduce, understand, and validate older certification claims precisely.
