# Data

## Role

Persist the project-wide declarations and build inputs that govern Fortress as one repository, including its exact project, architecture, feature, workspace, toolchain, and truthful certification state.

## Origin

Maintainers author the project and architecture declarations, feature registry, workspace manifest, Cargo configuration, and toolchain pin. The certification scaffold is also authored because it states the current absence of certification evidence rather than recording a generated audit result.

## Semantics

The Data declares configuration, structure, identity, applicability, or normative input meaning used by the Module; it is not computational output. Cargo package manifests remain Data in their owning Modules, while Cargo's resolved lock record remains root Info.

Cargo commands use `data/Cargo.toml` as the workspace manifest and `data/cargo_config.toml` as the repository configuration. `CARGO_RESOLVER_LOCKFILE_PATH` must identify the absolute `info/Cargo.lock` path, and `CARGO_TARGET_DIR` must identify a location outside the governed repository.

## Validity

Consumers require valid UTF-8 where textual, correct schema or ecosystem syntax, canonical identities and paths, complete required fields, and compatible declared versions. Cargo 1.97.1 or newer is required for stable `resolver.lockfile-path`; formatting, Clippy, tests, documentation, and audit operate through explicit `--manifest-path data/Cargo.toml` and `--config data/cargo_config.toml` arguments.

## Lifecycle

Maintainers update Data through reviewed semantic changes; schema versions change only when representation identity changes, while Git retains superseded history.

## Files

### [`architecture.json`](../data/architecture.json)

Declares capability zones, ownership paths, repository artifact classes, and the current component dependency graph.

### [`cargo_config.toml`](../data/cargo_config.toml)

Configures Cargo to keep generated lock and build state outside authored Data locations under the canonical grammar.

### [`Cargo.toml`](../data/Cargo.toml)

Declares the Cargo workspace members, common package metadata, Rust edition, and warnings-denied workspace lint policy.

### [`certification.json`](../data/certification.json)

Records the truthful NOT CERTIFIED scaffold without fabricated evidence or upgraded claims.

### [`features.json`](../data/features.json)

Declares active Fortress capabilities, mandatory requirements, and canonical Rust test evidence identities.

### [`project.json`](../data/project.json)

Declares Fortress project identity, pinned draft standard, model inputs, capabilities, languages, and observation exclusions.

### [`rust_toolchain.toml`](../data/rust_toolchain.toml)

Pins the minimum stable Rust toolchain that supports the canonical Cargo lockfile strategy.
