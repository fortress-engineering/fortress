# Fortress

Fortress is an executable engineering control plane for software repositories.
It turns declared engineering architecture, contracts, ownership, and quality
policy into deterministic evidence about an exact repository state. The current
implementation provides Snapshot Governance; it does not yet provide complete
certification, temporal workflow execution, onboarding, deployment, or release
orchestration.

Fortress is in development toward the Fortress Engineering Standard 1.0.0. The
applicable edition is `1.0.0-draft.1`, which remains mutable. This repository is
**NOT CERTIFIED**. Passing tests and a passing snapshot audit are development
evidence, not certification or attestation.

## Authority and engineering doctrine

The root and Module `README.md` files are the canonical prose contracts for the
responsibilities they describe. Machine-readable draft standard rules define
normative rule meaning. Project declarations state what Fortress claims about
itself; observations state repository facts; findings are derived evidence.
Schemas constrain serialization but do not override product or standard
meaning. Implementation, tests, generated output, and historical Git content do
not silently become normative authority.

When a convention is selected, Fortress prioritizes meaningful engineering
strategy, then consistency and entropy reduction, then least adoption friction
among materially equivalent choices. Cross-language consistency is preferred
where it is not harmful; ecosystem divergence needs a concrete reason. An
arbitrary tie-breaker may be identified honestly as arbitrary.

Fortress-controlled stable IDs retain their normative uppercase hyphenated
syntax. Filesystem identifiers follow the recursive grammar described below.
Released standards are immutable and content-addressed; draft records are not.
Mandatory applicable rules are hard gates. Exceptions must be narrow, governed,
and visible rather than becoming broad bypasses.

## Recursive repository grammar

The repository root is the root Module. Every Module has a mandatory
`README.md`, directly owns files through `code/`, `data/`, `info/`, and `docs/`,
and places architectural children only as Modules beneath `mods/`. Attribute
directories are flat. A Module must have `code/` or child Modules; an atomic
Module must have `code/`. No empty canonical directory is retained for symmetry.

Documentation is bidirectional: `code/`, `data/`, and `info/` exist exactly when
`docs/code_docs.md`, `docs/data_docs.md`, and `docs/info_docs.md` respectively
exist. There is no `docs_docs.md`, `mods_docs.md`, arbitrary documentation file,
or documentation subdirectory.

Fortress-controlled filenames and direct Module names use one to three
lowercase ASCII alphanumeric words separated by single underscores. An optional
`_vN` suffix identifies a genuine system-relevant version and is not a substitute
for Git history. Ecosystem-controlled `Cargo.toml` is authored Data and
Cargo-maintained `Cargo.lock` is derived Info.

The functional Module tree is:

```text
/
├── README.md
├── data/
├── info/
├── docs/
└── mods/
    ├── engine/
    │   └── mods/
    │       ├── standard_registry/
    │       ├── project_model/
    │       ├── repository_observation/
    │       ├── architecture_evaluation/
    │       └── snapshot_governance/
    ├── cli/
    └── testing/
```

At the root, `.gitignore`, `.github/`, `CONTRIBUTING.md`, `GOVERNANCE.md`, and
`SECURITY.md` are retained only as GitHub-recognized repository integration and
community-health surfaces. No `LICENSE` exists because license selection remains
owner-gated; the absence of a license does not grant use, modification, or
redistribution rights.

## Implemented behavior

The Engine loads stable identities, the pinned draft standard, typed project and
architecture declarations, deterministic repository observations, feature and
requirement contracts, and Rust test facts. Snapshot construction performs two
complete canonical observation passes and rejects changed path sets, sizes, or
digests. Its semantic identity excludes wall-clock timestamps and absolute
filesystem paths.

Snapshot evaluation currently implements:

- `ARCH-DEPENDENCY-001` — acyclic declared component dependencies;
- `ARCH-OWNERSHIP-001` — exactly one declared owner for every governed file;
- `TEST-TRACEABILITY-001` — active requirement and Rust behavioral-test
  traceability;
- `REPO-MODULE-001` — the canonical recursive Module and filename grammar.

An applicable rule without an evaluator is reported as `UNSUPPORTED`, never
PASS. Findings use one deterministic content-addressed representation and never
redefine their governing rule.

The supported command surface is:

```text
fortress --version
fortress help
fortress help <implemented-command>
fortress audit [path] [--format human|json]
```

`fortress audit` succeeds only when all actually evaluated mandatory snapshot
rules have no findings. It reports invalid declarations, unstable snapshots,
violations, and unsupported capabilities truthfully. Its JSON is deterministic
development output and is not a certification result.

## Rust and Cargo operation

Cargo 1.97.1 or newer is required because stable
`resolver.lockfile-path` support permits `info/Cargo.lock`. Workspace and package
manifests are Module Data; source and integration targets use explicit paths.
Set `CARGO_RESOLVER_LOCKFILE_PATH` to the absolute `info/Cargo.lock` path and
`CARGO_TARGET_DIR` outside the repository, then run:

```text
cargo --config data/cargo_config.toml fmt --manifest-path data/Cargo.toml --all --check
cargo --config data/cargo_config.toml clippy --manifest-path data/Cargo.toml --workspace --all-targets --all-features -- -D warnings
cargo --config data/cargo_config.toml test --manifest-path data/Cargo.toml --workspace --all-targets --all-features
cargo --config data/cargo_config.toml doc --manifest-path data/Cargo.toml --workspace --all-features --no-deps
cargo --config data/cargo_config.toml run --manifest-path data/Cargo.toml -p fortress-cli -- audit . --format json
```

Build output is transient and must not be written into the governed tree.

## Trust boundary and deferred architecture

Observation rejects symlinks and unsafe exclusions, and snapshot stabilization
detects ordinary mutation between complete passes. It does not lock the
filesystem, defeat a malicious host, or detect a mutation that is reverted to
identical content between observations.

Future certification remains a content-addressed evidence DAG with explicit
trust and freshness; passing an audit does not activate it. Persistent jobs,
provider adapters, change-ticket state machines, onboarding convergence,
standard upgrades, deployment, and attestation remain intentionally deferred.
They must be introduced as real Modules only when their contracts and
implementation exist.

## Development authority

Implementation work occurs on `dev`. `main` is owner-controlled and must not be
modified, merged, rebased, reset, force-pushed, tagged from, or otherwise
changed by development automation. Do not publish packages, releases, or
deployments without separate authorization. Do not weaken warnings-denied Rust
gates or create false certification evidence to obtain green results.

Repository changes should preserve exclusive Module ownership, update standard,
schema, project, feature, requirement, test, and documentation contracts where
meaning changes, and use atomic Conventional Commits.

## Organization surfaces

- [Fortress Engineering organization](https://github.com/fortress-engineering)
- [Public website repository](https://github.com/fortress-engineering/website)
- [Organization community defaults](https://github.com/fortress-engineering/.github)
