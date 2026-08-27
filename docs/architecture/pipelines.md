# 14 — Pipeline and Deployment Governance

**Status:** Normative pipeline architecture
**Authority class:** Operational architecture

## Principle

A repository cannot be considered rigorously governed if its source code is contract-driven while its build, release, or deployment pipeline is an ungoverned collection of YAML files and shell commands.

Fortress therefore treats pipelines as part of the engineering system.

## Canonical pipeline model

Fortress should define provider-independent pipeline DAGs containing:

- stable pipeline/job IDs;
- dependencies;
- inputs/outputs;
- certification prerequisites;
- environments;
- secrets requirements;
- artifacts;
- retry semantics;
- approval gates;
- executor/provider requirements;
- rollback/verification where applicable.

Example conceptual release flow:

```text
Build
  ↓
Unit Certification
  ↓
Package
  ↓
Integration Certification
  ↓
Release Certification
  ↓
Publish
  ↓
Deployment Verification
```

## YAML and provider files

GitHub Actions, GitLab CI, Azure Pipelines, or other YAML files are provider-specific execution projections or audited integrations, not automatically the normative source of pipeline meaning.

A project may initially adopt existing CI files, but Fortress should eventually know the canonical job graph and verify that provider configuration does not bypass required gates.

## GitHub integration

The first provider integration SHOULD support GitHub Actions because GitHub is the primary target for initial Fortress adoption.

Potential user operations include:

```text
fortress ci run <pipeline-or-job>
fortress ci status
fortress ci watch <job>
fortress ci logs <job>
fortress ci cancel <job>
```

Provider operations map into Fortress jobs.

## Local execution

Where pipeline steps are portable, Fortress should allow the same canonical task to execute locally:

```text
fortress pipeline run release --local
```

Provider-specific infrastructure steps may remain remote-only and must say so explicitly.

## Provider independence

Core pipeline contracts MUST NOT embed GitHub-specific semantics as universal Fortress concepts.

GitHub is an adapter.

Future adapters may target GitLab, Azure DevOps, Buildkite, Jenkins, or other systems without changing canonical pipeline meaning.

## Certification-aware pipelines

A pipeline may depend on certification artifacts instead of rerunning expensive work.

For example, hosted CI can verify current trusted local security certification rather than automatically rerunning an eight-hour audit.

A pipeline may never bypass mandatory certification simply because provider YAML was manually changed.

## Pipeline contracts as fingerprint inputs

Changes to:

- pipeline definitions;
- deployment environment configuration;
- secret contracts;
- provider adapters;
- release commands;

must invalidate affected pipeline/release certifications according to dependency relationships.

## Secrets

Fortress pipeline contracts may declare secret identities and purposes but MUST NOT commit plaintext secret values.

Providers resolve secret material according to the trust model.

## Deployments

Deployment contracts should support, where applicable:

- target environment;
- package/artifact digest;
- prerequisites;
- migration order;
- health/readiness verification;
- rollback contract;
- post-deployment evidence.

Deployment success is not inferred merely from a provider job exiting zero.

## Generated provider workflows

Fortress MAY generate provider configuration from canonical pipeline contracts where deterministic projection is feasible.

If generated, the provider file is non-normative and `fortress configure --check` or equivalent verifies drift.

If not generated, Fortress audits it against the canonical pipeline graph.

## Pipeline history

Release and deployment pipeline executions contribute to temporal engineering history and certification evidence.

Fortress should be able to answer which exact pipeline and evidence produced a release.

## Goal

Fortress should make the deployment pipeline as explicit and certifiable as the source architecture, preventing the delivery system from becoming the ungoverned exception to an otherwise strict repository.
