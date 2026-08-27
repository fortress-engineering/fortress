# Fortress agent navigation

## Controlling authority

Read [docs/README.md](docs/README.md) before changing product meaning,
architecture, schemas, contracts, conformance, or governance. Follow the
specific controlling document linked there and the active `.fortress/` change
record for the work.

Authority flows from constitutional product meaning to the standard,
architecture and governance, versioned schemas and ratified project contracts,
then implementation. Conformance fixtures, implementation tests, generated
configuration, and certification evidence are subordinate evidence; they must
never silently become normative truth.

## Repository and Git rules

- Inspect the remote, branch, status, recent history, and untracked files before
  editing.
- Perform implementation work only on `dev`; never modify, merge into, rebase,
  reset, force-push, or tag from `main`.
- Preserve unrelated work and published history.
- Validate and commit each atomic unit separately, then push it promptly.
- Never bypass a failed gate or publish packages, releases, or deployments
  without separate authorization.

## Engineering rules

Use Rust for the canonical implementation. Keep CLI presentation outside core
standard and project-model logic. Forbid unsafe code unless a future governed
exception supplies a concrete safety case. Do not add empty crates or roots,
generic dumping grounds, green placeholder commands, fake certification PASS
artifacts, anonymous debt markers, or ungoverned generated output.

Every implemented rule needs a stable identity plus appropriate positive,
negative, and boundary conformance evidence. Apply new general capabilities to
Fortress itself through explicit change records and truthful validation.
