# Repository Observation

## Purpose

Repository Observation exists to turn an ordinary local repository tree into stable content facts without confusing those facts with declarations or ownership.

## Responsibility

Walk repository files using explicit operational exclusions, normalize repository-relative paths, hash bytes, and return a deterministically ordered observation suitable for snapshot stabilization whether or not project governance authority is present.

## Scope

### Includes

Ordinary-file discovery, path normalization, byte sizes, SHA-256 digests, exclusion policy identity, symlink rejection, and local filesystem error reporting.

### Excludes

Project ownership claims, semantic rule interpretation, source-language analysis, remote provider state, and filesystem locking against a malicious host.

## Relationships

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Consumes a project-authored observation exclusion policy when present. Without project authority, tooling may apply a documented operational exclusion such as `.git` without materializing that behavior as authored intent.

## Guarantees

Equivalent included content produces equivalent sorted facts; unsafe exclusions and symlinks fail explicitly; no timestamp or absolute host path enters semantic observation identity.
