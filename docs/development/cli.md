# Fortress CLI capability

**Status:** Implemented development architecture
**Authority class:** Implementation documentation
**Owning capability:** `TF-CLI-0001`

## Purpose and boundary

The Rust workspace separates provider-independent command contracts in
`fortress-core` from terminal parsing and rendering in `fortress-cli`. The
registry validates stable `CMD-*` identities and prevents duplicate names or
aliases before commands can be discovered.

The current executable implements:

```text
fortress --version
fortress help
fortress help <implemented-command>
fortress audit [path] [--format human|json]
```

`fortress audit` loads the declared project, exact standard bundle,
architecture, and feature contracts; builds a stabilized snapshot; verifies
loaded declaration bytes against that snapshot; extracts supported Rust test
facts; and evaluates all implemented applicable snapshot rules. Human output is
concise and JSON output uses `schemas/v1/snapshot-audit.schema.json`. The
operation is local and synchronous. It does not execute CI providers or create
certification evidence.

`certify`, `affected`, job, pipeline, change, and onboarding operations remain
unsupported. Invoking one returns exit code 2 and an explicit diagnostic; it
never returns a green placeholder result.

## Failure behavior

Argument-shape, malformed project/snapshot state, and unsupported-command
failures use exit code 2. Evaluated rule violations use exit code 1. A valid
audit uses exit code 0 only when every actually evaluated mandatory snapshot
rule passes; applicable unsupported rules remain explicitly reported and do
not masquerade as passes. Output write failures use a general non-success exit.

## Evidence

Core, presentation, and process-level tests use stable `T-TF-CLI-0001-*`
identities. They cover registry validation, alias discovery, help, version,
unsupported certification, audit success and failure, malformed project state,
deterministic JSON, unsupported audit options, and argument boundaries.
