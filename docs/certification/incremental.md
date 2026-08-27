# 09 — Content-Addressed Incremental Certification

**Status:** Normative incremental-certification architecture
**Authority class:** Certification

## Principle

Certification validity is a property of an exact dependency closure.

A certification does not become stale because “the repository changed.” It becomes stale only when something in its invalidation closure changes or an upstream certification becomes invalid.

> **Certification should be an attested property of a precisely fingerprinted dependency closure, not something CI blindly recomputes after every commit.**

## Dependency closure

A certification unit may depend on:

- files;
- entities;
- feature contracts;
- requirements;
- schemas;
- documentation;
- generated artifacts;
- lockfiles;
- tool configuration;
- toolchain versions;
- external semantic datasets;
- upstream certifications.

The closure must be explainable.

## Merkle-style fingerprints

Fortress should compose digests hierarchically:

```text
file digests
   ↓
entity digests
   ↓
feature/component digests
   ↓
certification input digest
   ↓
profile/release digest
```

SHA-256 is the initial recommended canonical algorithm.

The algorithm and canonical serialization are versioned parts of the evidence format.

## Fingerprint inputs

Fingerprinting must include all inputs capable of changing the certified result, including source content, contracts, relevant normative docs, standard edition digest, Fortress version when behavior matters, analyzer/tool versions, configuration, environment identity where relevant, and external datasets such as timezone databases when semantically significant.

Wall-clock timestamps must not invalidate deterministic semantic evidence unless explicitly required by provenance.

## `fortress affected`

`fortress affected` computes:

1. changed artifacts;
2. owning entities;
3. forward/reverse graph closure;
4. affected tests/docs/public surfaces;
5. affected certification units;
6. invalidation reasons.

It distinguishes directly changed, transitively affected, and reusable scopes.

## Affected certification

`fortress certify --affected` reruns only units that are stale, missing, failed and explicitly retried, or transitively required by an affected aggregate certification.

Current trusted PASS units remain reusable.

## Full certification

`fortress certify --all` executes the entire required graph according to the full profile rather than relying on cache reuse.

Uses include release preparation, integrity audits, standard upgrades, Fortress engine upgrades, toolchain changes, and invalidation debugging.

## Rebaseline

`fortress certify --all --rebaseline` creates a complete trusted baseline only after the full required graph passes.

The baseline records standard identity, project graph digest, certification DAG digest, toolchains, evidence digests, and aggregate state.

## Documentation invalidation

Docs participate in the same graph.

If `DOC-X` documents `PF-X`, changing the feature may invalidate the docs certification.

If a normative document is itself an input to a feature contract, changing it may invalidate implementation and conformance certifications.

Relationships determine invalidation, not file extension.

## CI model

Hosted CI should primarily verify existing trusted evidence.

Typical cheap CI:

1. checkout;
2. validate standard/project schemas;
3. verify attestation signatures;
4. recompute cheap dependency fingerprints;
5. compare them with certification artifacts;
6. run cheap structural hard gates;
7. return PASS, FAIL, or STALE.

### Current FAIL

CI fails immediately instead of spending cloud resources to reconfirm a known current failure.

### PASS with fingerprint mismatch

CI fails as STALE and instructs the contributor to rerun affected certification.

### PASS with matching fingerprint

CI accepts expensive certification evidence when trust requirements are satisfied.

## Trust requirement

A user-editable JSON field saying `status: pass` is not proof.

Protected certification requires attestation binding the certification definition, inputs, toolchain, standard, result, and evidence digests.

## Trust levels

Recommended levels:

- **Untrusted local** — useful to the author but insufficient for protected release gates.
- **Trusted development** — produced by an approved local/self-hosted identity.
- **Release grade** — complete release profile with required provenance.

Projects define which trust level satisfies which branch/release gate.

## Periodic full validation

Incremental invalidation itself must be tested.

Projects should periodically run full certification and compare with incremental expectations.

If full certification finds a failure that `--affected` incorrectly reused, this is a high-severity dependency-model defect.

## Cache correctness over cache hit rate

Fortress must prefer invalidating too much over silently reusing invalid proof.

Optimization may reduce excessive invalidation only while preserving correctness.

## Explainability

For every stale unit, Fortress should report the changed input, previous/current digests, dependency path causing invalidation, and downstream certifications affected.

## Goal

Local or self-hosted environments perform expensive proof work once.

CI cheaply verifies that the proof remains applicable.

This makes unusually strict certification economically practical without lowering the standard.
