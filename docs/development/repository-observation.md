# Universal repository file observation

**Status:** Implemented development architecture
**Authority class:** Implementation documentation
**Owning capability:** `AF-REPOSITORY-OBSERVATION-0001`

## Purpose

`fortress-core` can recursively observe ordinary files beneath a repository root
and emit deterministic repository-relative facts: canonical forward-slash path,
byte size read, and lowercase SHA-256 content identity. Results are sorted by
path and labeled `OBSERVED`.

The caller supplies an explicit exclusion policy. Fortress's self-application
excludes `.git`, `target`, and `.fortress/state`; those are project declarations,
not universal hidden defaults in the observer.

## Trust and determinism boundary

The observer does not follow symbolic links. Non-file/non-directory entries,
non-Unicode paths, invalid exclusion prefixes, unreadable files, and arithmetic
overflow produce explicit errors. Absolute paths and parent traversal are never
serialized into observation output.

Given the same readable file tree, bytes, and exclusion policy, output ordering,
sizes, and digests are deterministic. This initial implementation does not lock
the repository or prove that a file remained unchanged while it was read. A
later snapshot/fingerprint unit must close that race before observation can
support protected certification evidence.

## Non-claims

File inventory does not infer language, package, symbol, import, ownership,
architecture, generated status, or feature meaning. It does not apply
`.gitignore`, compare declared and observed graphs, persist an observation, or
expose a CLI command. It supplies observed facts for those downstream units and
makes no certification claim.
