# Repository Observation Module

This Module owns deterministic provider-independent observation of ordinary
repository files. Observations are facts, never declarations or ownership.

Paths are normalized to forward-slash repository-relative form, sorted
deterministically, and paired with byte size and SHA-256 content identity.
Explicit exclusions are caller-authored and fingerprinted. Symlinks and unsafe
parent-relative exclusions are rejected. Snapshot stabilization performs two
complete passes and rejects changed path sets, sizes, or digests.
