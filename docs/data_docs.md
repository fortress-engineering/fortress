# Data

## Role

Persist root-owned operational and build inputs that cannot be derived from Module contracts or physical containment.

## Origin

Maintainers author the observation configuration, project information-flow facet vocabulary, root audit-Feature realization bindings, workspace manifest, Cargo configuration, and toolchain pin. The certification scaffold is also authored because it states the current absence of certification evidence rather than recording a generated audit result.

## Semantics

The Data declares configuration, structure, identity, applicability, or normative input meaning used by the Module; it is not computational output. Cargo package manifests remain Data in their owning Modules, while Cargo's resolved lock record remains root Info.

Cargo commands use `data/Cargo.toml` as the workspace manifest and `data/cargo_config.toml` as the repository configuration. `CARGO_RESOLVER_LOCKFILE_PATH` must identify the absolute `info/Cargo.lock` path, and `CARGO_TARGET_DIR` must identify a location outside the governed repository.

## Validity

Consumers require valid UTF-8 where textual, correct schema or ecosystem syntax, canonical identities and paths, complete required fields, and compatible declared versions. Cargo 1.97.1 or newer is required for stable `resolver.lockfile-path`; formatting, Clippy, tests, documentation, and audit operate through explicit `--manifest-path data/Cargo.toml` and `--config data/cargo_config.toml` arguments.

## Lifecycle

Maintainers update Data through reviewed semantic changes; schema versions change only when representation identity changes, while Git retains superseded history.

## Files

### [`behavior_realization_contracts.json`](../data/behavior_realization_contracts.json)

Binds every checkpoint of the root Fortress audit Feature to exact supported program-semantic anchors without authoring reachability, realized transitions, bypasses, or verification evidence.

### [`cargo_config.toml`](../data/cargo_config.toml)

Configures Cargo to keep generated lock and build state outside authored Data locations under the canonical grammar.

### [`Cargo.toml`](../data/Cargo.toml)

Declares the Cargo workspace members, common package metadata, Rust edition, and warnings-denied workspace lint policy.

### [`certification.json`](../data/certification.json)

Records the truthful NOT CERTIFIED scaffold without fabricated evidence or upgraded claims.

### [`information_flow_policy.json`](../data/information_flow_policy.json)

Declares the project-wide ordered integrity and confidentiality facet vocabulary without assigning classifications to undeclared sources or sinks.

### [`project.json`](../data/project.json)

Declares only the root observation exclusions that are operational input rather than architectural intent.

### [`rust_toolchain.toml`](../data/rust_toolchain.toml)

Pins the minimum stable Rust toolchain that supports the canonical Cargo lockfile strategy.
