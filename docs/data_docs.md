# Root Data

The root Module owns declarations that describe Fortress as one governed
repository: the Cargo workspace and toolchain inputs, project and architecture
graphs, the complete feature/requirement registry, the truthful certification
scaffold, and any active change record.

`Cargo.toml` and `cargo_config.toml` are authored inputs. Cargo 1.97 or newer is
required because stable `resolver.lockfile-path` support lets the generated
lockfile remain root Info. Cargo package manifests are narrower Module Data.

The project declaration pins the mutable draft standard manifest, points to all
declared model inputs, and excludes only `.git` from governed observation.
Declarations encode authority but do not supersede the Module README or the
normative standard records they reference.
