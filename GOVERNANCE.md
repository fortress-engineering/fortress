# Fortress repository governance

**Status:** Repository governance authority
**Authority class:** Temporal governance

## Authority

The Fortress product and standard hierarchy is defined in
[docs/README.md](docs/README.md). The owner retains final authority over
constitutional meaning, protected `main`, stable standards, releases, public
compatibility promises, licensing, publishing, and irreversible external
service commitments.

## Branch model

- `main` is owner-controlled. Autonomous implementation work must not commit to,
  merge into, rebase, reset, force-push, tag from, or otherwise modify it.
- `dev` is the integration branch for authorized autonomous implementation and
  may receive validated direct commits and pushes.
- Task branches may be used under later project policy, but they do not weaken
  the same validation and authority rules.
- Published history is never rewritten. Failed gates are repaired, not bypassed.

Repository documentation expresses the intended protection model; actual GitHub
rulesets require separate owner configuration and must not be claimed as
enforced until verified through the provider.

## Decision process

Routine reversible work follows the active temporal change record. Changes to
standard meaning, architecture, public contracts, certification semantics,
security/trust boundaries, and release policy require evidence, alternatives,
impact analysis, explicit authorization at the governing level, and preserved
history.

## Licensing and releases

License selection remains blocked on [owner decision 0001](docs/decisions/0001-license-selection.md).
No package, standard edition, certification claim, release, tag, or deployment
may be published without separate authorization and all applicable gates.
