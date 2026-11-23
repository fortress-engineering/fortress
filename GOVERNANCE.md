# Fortress repository governance

**Status:** Repository governance authority
**Authority class:** Temporal governance

## Authority

The Fortress product and standard hierarchy is defined in the root
[Module contract](README.md) and the recursively nested Module contracts. The
owner retains final authority over
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

License selection remains owner-gated. No package, standard edition,
certification claim, release, tag, or deployment
may be published without separate authorization and all applicable gates.

## Multilingual release qualification

External technical qualification of the existing product establishes the
starting point for language expansion. Before the Standard release candidate
can be stabilized, Fortress must qualify the applicable capabilities of each
required language and the relationships supported across language boundaries.
An external campaign must then exercise the installed multilingual candidate
against independent real projects.

The external campaign also retains the independent adoption requirement.
Consenting maintainers must author project-specific policies and exercise them
through sustained changes and a supported edition upgrade. The campaign
independently adjudicates blocking findings. Candidate sharing and recruitment
require separate authorization.
