# Fortress

Fortress is an executable engineering control plane for software repositories.
It models the codebase as a governed system, unifies development and operational
tooling, enforces architectural and quality standards, manages resumable project
workflows, and produces content-addressed certification from development through
release.

Fortress turns engineering architecture from an informal design intention into
a certifiable property of the repository.

## Development status

Fortress is in bootstrap development toward the **Fortress Engineering Standard
1.0.0**. The standard and implementation are not yet stable, and this repository
does not claim Fortress certification. Implemented checks and ordinary test
results are development evidence, not certification attestations.

## Authority

Start with [docs/README.md](docs/README.md) for the permanent authority hierarchy.
In summary:

- [product definition](docs/product/definition.md) and
  [engineering philosophy](docs/standard/philosophy.md) control product meaning;
- draft and released standard bundles control normative standard meaning within
  their declared status and edition;
- architecture, contract, certification, temporal, and onboarding documents
  control their respective system designs;
- schemas encode serialized contracts but do not override higher authority;
- implementation, tests, conformance results, and generated evidence never
  silently become normative product or standard meaning.

## Repository responsibilities

- `docs/` — permanent product, standard-design, architecture, governance,
  certification, onboarding, decision, and history authorities.
- `standard/` — machine-readable draft and immutable released standard bundles.
- `schemas/` — versioned serialized contracts.
- `crates/` — canonical Rust implementation.
- `.fortress/` — Fortress's truthful self-model, temporal records, commands, and
  certification declarations.
- `conformance/` — specification-authored rule fixtures and expected findings.
- `tests/` — repository-level implementation test support, distinct from
  conformance authority.
- `.github/` — low-cost hosted validation that reflects implemented checks only.

Potential `analyzers/`, `adapters/`, and `examples/` roots remain reserved in the
[repository architecture](docs/architecture/repository.md) until real content
justifies creating them.

## Current capabilities

The Rust implementation now provides deterministic repository observation,
stabilized content-addressed snapshots, shared normalized findings, declared
dependency/ownership/placement evaluation, Rust requirement/test traceability,
and a real repository audit command. These are development audit capabilities,
not Fortress certification.

The deliberately narrow command surface is:

```text
fortress --version
fortress help
fortress help <implemented-command>
fortress audit [path] [--format human|json]
```

Build and exercise it from the repository root:

```text
cargo build --workspace
cargo run -p fortress-cli -- --version
cargo run -p fortress-cli -- help
cargo run -p fortress-cli -- audit --format json
```

Audit succeeds only when every implemented applicable mandatory snapshot rule
passes. Unsupported standard rules are reported explicitly and are never shown
as passes. Unlisted commands are unsupported and return a non-success status.
See the [CLI capability record](docs/development/cli.md).

## Organization surfaces

- [Fortress Engineering organization](https://github.com/fortress-engineering)
- [Public website repository](https://github.com/fortress-engineering/website)
- [Organization community defaults](https://github.com/fortress-engineering/.github)

## Branch authority

Implementation work occurs on `dev`. The owner controls `main`; automation must
not commit to, merge into, rebase, reset, force-push, tag from, or otherwise
modify `main`. Publishing packages, releases, or deployments requires separate
authorization.

## License status

No license has been selected for this repository. The absence of a `LICENSE`
file is intentional and does not grant permission to use, modify, or
redistribute its contents. See the recorded
[owner decision](docs/decisions/0001-license-selection.md).
