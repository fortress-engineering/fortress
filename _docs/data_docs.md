# Data

## Role

Persist root-owned build inputs and distributed root Module contracts that remain part of project architecture.

## Origin

Maintainers author the root audit-Feature realization bindings, workspace manifest, Cargo configuration, and toolchain pin. Operational configuration and active project governance live under the fixed `__fortress` control namespace. Certification is generated control evidence and is never authored here.

## Semantics

The Data declares configuration, structure, identity, applicability, or normative input meaning used by the Module; it is not computational output. Cargo package manifests remain Data in their owning Modules, while Cargo's resolved lock record remains root Info.

Cargo commands use `_data/Cargo.toml` as the workspace manifest and `_data/cargo_config.toml` as the repository configuration. `CARGO_RESOLVER_LOCKFILE_PATH` must identify the absolute `_info/Cargo.lock` path, and `CARGO_TARGET_DIR` must identify a location outside the governed repository.

## Validity

Consumers require valid UTF-8 where textual, correct schema or ecosystem syntax, canonical identities and paths, complete required fields, and compatible declared versions. Cargo 1.97.1 or newer is required for stable `resolver.lockfile-path`; formatting, Clippy, tests, documentation, and audit operate through explicit `--manifest-path _data/Cargo.toml` and `--config _data/cargo_config.toml` arguments.

## Lifecycle

Maintainers update Data through reviewed semantic changes; schema versions change only when representation identity changes, while Git retains superseded history.

## Files

### [`behavior_realization_contracts.json`](../_data/behavior_realization_contracts.json)

Binds every checkpoint of the root Fortress audit Feature to exact supported program-semantic anchors without authoring reachability, realized transitions, bypasses, or verification evidence.

### [`cargo_config.toml`](../_data/cargo_config.toml)

Configures Cargo to keep generated lock and build state outside authored Data locations under the canonical grammar.

### [`Cargo.toml`](../_data/Cargo.toml)

Declares the Cargo workspace members, common package metadata, Rust edition, and warnings-denied workspace lint policy.

### [`rust_toolchain.toml`](../_data/rust_toolchain.toml)

Pins the minimum stable Rust toolchain that supports the canonical Cargo lockfile strategy.
