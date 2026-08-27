# Root Data

The root Module owns declarations that describe Fortress as one governed
repository: the Cargo workspace and toolchain inputs, project and architecture
graphs, the complete feature/requirement registry, and the truthful certification
scaffold. An active change record is root Data only while work is in progress;
completed change history remains recoverable from Git.

`Cargo.toml` and `cargo_config.toml` are authored inputs. Cargo 1.97 or newer is
required because stable `resolver.lockfile-path` support lets the generated
lockfile remain root Info. Cargo package manifests are narrower Module Data.

The project declaration pins the mutable draft standard manifest, points to all
declared model inputs, and excludes only `.git` from governed observation.
Declarations encode authority but do not supersede the Module README or the
normative standard records they reference.
