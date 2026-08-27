# Bootstrap continuous integration

**Status:** Implemented development architecture
**Authority class:** Pipeline implementation documentation
**Owning capability:** `AF-BOOTSTRAP-GOVERNANCE-0001`

## Purpose

`.github/workflows/ci.yml` runs only low-cost checks that the current Fortress
implementation can truthfully perform: deterministic Rust formatting,
warnings-denied Clippy, structural schema/draft-registry validation, self-model
consistency, implemented `STD-ID-001` conformance, workspace tests, and Rust
documentation with warnings denied.

The workflow pins Rust 1.85.1, grants only read access to repository contents,
does not persist checkout credentials, and has a bounded timeout. It runs on
`dev` pushes and pull requests targeting `dev` or owner-controlled `main`.

## Non-claims

Hosted CI currently executes checks; it does not verify content-addressed
certification fingerprints, signatures, attestations, protected identities, or
expensive local evidence. A green workflow is not a Fortress certification and
must not populate the `MISSING` certification units in the self-model with fake
PASS evidence.

The workflow can later shift from rerunning expensive proof to verifying trusted
evidence when certification fingerprints and attestation are genuinely
implemented.
