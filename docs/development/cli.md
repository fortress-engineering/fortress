# Initial Fortress CLI capability

**Status:** Implemented development architecture
**Authority class:** Implementation documentation
**Owning capability:** `TF-CLI-0001`

## Purpose and boundary

The Rust workspace separates provider-independent command contracts in
`fortress-core` from terminal parsing and rendering in `fortress-cli`. The
registry validates stable `CMD-*` identities and prevents duplicate names or
aliases before commands can be discovered.

The current executable implements only:

```text
fortress --version
fortress help
fortress help <implemented-command>
```

No `audit`, `certify`, `affected`, job, pipeline, change, or onboarding operation
is registered. Invoking an unsupported operation returns exit code 2 and an
explicit diagnostic; it never returns a green placeholder result.

## Failure behavior

Argument-shape and unsupported-command failures use exit code 2. Output write
failures use a general non-success exit. Help and version return success only
after their output is written.

## Evidence

Core, presentation, and process-level tests use stable `T-TF-CLI-0001-*`
identities. They cover registry validation, alias discovery, help, version,
unsupported certification, and an extra-argument boundary.
