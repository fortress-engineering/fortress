# Canonical repository snapshot

**Status:** Implemented Snapshot Governance foundation
**Authority class:** Implementation documentation
**Owning capability:** `AF-SNAPSHOT-GOVERNANCE-0001`

## Purpose

`fortress-core` builds a schema-versioned repository snapshot that binds the
validated project identity and standard claim to exact declaration bytes, an
explicit observation policy, a stabilized repository file inventory, and the
Fortress engine version that interprets the snapshot contract.

For a mutable draft standard, the snapshot records a canonical input fingerprint
over the manifest and every supplied rule document. A released project may also
declare the standard bundle's immutable release digest.

The snapshot has two additional SHA-256 identities. The repository-content
fingerprint is computed from canonical observed file facts. The snapshot fingerprint also
binds the standard manifest, project declaration, architecture declaration,
feature-contract inputs, exclusion policy, and engine/provenance contract.
Neither identity contains a wall-clock timestamp or an absolute repository path.

## Stabilization

Snapshot creation performs two complete canonical observation passes. The
included relative paths, byte sizes, and content digests must be identical.
Changed, added, and removed included files reject snapshot creation. Mutations
entirely beneath an explicit excluded prefix do not change governed snapshot
identity.

This is an optimistic stabilization protocol, not a filesystem lock. It proves
that both completed passes produced identical content facts. A mutation that is
reverted to the exact same bytes and path set before both observations complete
does not alter content identity; filesystem metadata and transient intermediate
states are deliberately not semantic evidence. Host storage, the Rust runtime,
SHA-256, and successful ordinary-file reads remain within the local trust
boundary.

## Knowledge and certification boundary

Snapshot documents preserve distinct inputs:

- standard edition/status and any declared immutable bundle digest;
- computed digest of the exact draft or released standard manifest supplied;
- declared project, architecture, and feature-contract digests;
- caller-authored exclusion policy;
- observed ordinary-file facts;
- derived repository and complete snapshot fingerprints.

A snapshot is reproducible local evidence for downstream rule evaluation. It
does not ratify observations as architecture, does not turn findings into rule
meaning, and does not constitute certification or attestation.
