# Contributing to Fortress

**Status:** Repository contribution policy
**Authority class:** Operational governance

Read [AGENTS.md](AGENTS.md) and the [authority map](docs/README.md) before
changing Fortress. The organization-wide contribution and conduct defaults live
in [`fortress-engineering/.github`](https://github.com/fortress-engineering/.github).

## Change discipline

- Work on `dev` or an explicitly authorized task branch; never write directly
  to owner-controlled `main`.
- Keep every commit atomically meaningful and use a clear Conventional Commit
  subject.
- Update the governing contract or architecture declaration before or with a
  behavior change.
- Record substantial work in a `CHG-*` temporal record as soon as the current
  schema can represent it.
- Add appropriate positive, negative, boundary, integration, and conformance
  evidence. Tests do not redefine the standard.
- Document public behavior, errors, invariants, and architecture impact.
- Run the smallest applicable checks before each commit and the complete current
  self-governance suite before declaring a unit complete.
- Do not suppress warnings, weaken rules, fabricate evidence, or add untracked
  generated policy to obtain a passing result.

## Owner decisions

Stop only dependent work when a product or architecture choice is genuinely
underdetermined, a public compatibility promise or license is required, an
irreversible provider commitment is needed, credentials or publishing are
required, or trustworthy validation would require bypassing a gate. Record the
question, evidence, alternatives, recommendation, and exact decision needed;
continue independent work.
