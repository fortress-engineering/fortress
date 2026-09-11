# Data

## Role

Persist root-owned operational and build inputs that cannot be derived from Module contracts or physical containment.

## Origin

Maintainers author the observation configuration, finding baseline/exception authority, project information-flow facet vocabulary, root audit-Feature realization bindings, workspace manifest, Cargo configuration, and toolchain pin. Certification is derived Info and is never authored here.

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

### [`finding_governance.json`](../_data/finding_governance.json)

Carries explicit project-level legacy baseline and finding-specific exception authority; Fortress currently has neither active baseline residue nor exceptions.

### [`information_flow_policy.json`](../_data/information_flow_policy.json)

Declares the project-wide ordered integrity and confidentiality facet vocabulary without assigning classifications to undeclared sources or sinks.

### [`project.json`](../_data/project.json)

Declares only the root observation exclusions that are operational input rather than architectural intent, including Cargo's disposable workspace-target materialization.

### [`rust_toolchain.toml`](../_data/rust_toolchain.toml)

Pins the minimum stable Rust toolchain that supports the canonical Cargo lockfile strategy.
