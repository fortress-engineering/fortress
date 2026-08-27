# Initial project model capability

**Status:** Implemented development architecture
**Authority class:** Implementation documentation
**Owning capability:** `AF-PROJECT-MODEL-0001`

## Purpose

`fortress-core` loads the version-one JSON project manifest into typed,
provider-independent structures and rejects invalid declared identities,
standard state, duplicate declarations, malformed archetype/language names,
non-canonical digests, and paths that are absolute or escape the repository.

The loader validates declarations only. It does not yet inventory the
repository, confirm that referenced files exist, reconcile declared and observed
graphs, evaluate dependencies, or certify the project. Those are downstream
capabilities and must not be inferred from successful manifest loading.

## Dependency boundary

The project model depends on stable identity validation and is owned by the core
library. CLI presentation, GitHub, shell execution, CI providers, and package
ecosystems do not participate in parsing or domain validation.

## Evidence

Unit and integration tests use stable `T-AF-PROJECT-MODEL-*` identities and
cover a valid model, the minimum supported declaration boundary, a duplicate
language, an escaping parent path, and non-canonical SHA-256 text. These are
implementation fixtures under `tests/`, not normative rule conformance fixtures.
