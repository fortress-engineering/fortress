# Generated artifact governance

**Status:** Implemented development policy
**Authority class:** Quality and trust
**Owning capability:** `AF-BOOTSTRAP-GOVERNANCE-0001`

## Committed generated artifacts

`Cargo.lock` is the only generated file committed during bootstrap.

- **Authoritative inputs:** workspace and crate `Cargo.toml` manifests plus the
  resolved crates.io package index state.
- **Generator:** Cargo 1.85.1 under `rust-toolchain.toml`.
- **Output:** root `Cargo.lock`.
- **Deterministic expectation:** identical manifests, registry content, Cargo
  version, and resolution inputs produce the same lockfile.
- **Check:** `cargo +1.85.1 metadata --locked --format-version 1` validates that
  the committed lock resolves the declared workspace without mutation. A
  deliberate dependency update regenerates the lockfile and requires normal
  review and tests.

## Uncommitted generated output

Cargo build products and rustdoc output live under ignored `target/`. Transient
Fortress runtime state is reserved under ignored `.fortress/state/`. Neither is
durable authority or certification evidence.

No generated schemas, standard bundles, configuration projections,
certification artifacts, or public documentation were introduced. When such an
artifact is justified, its authoritative source, generator identity, output
family, determinism, and drift check must be declared before it is committed.
