# Bootstrap packet disposition

**Status:** Completed historical record
**Authority class:** Bootstrap history
**Change:** `CHG-BOOTSTRAP-0001`

## Source and integrity

The supplied source was the extracted `fortress-bootstrap-design/` directory.
No original ZIP archive was present, so no archive digest exists and none is
invented. `SHA256SUMS.txt` listed 27 files; every listed file matched its
declared SHA-256 digest before implementation and again before disposal.

The SHA-256 digest of the exact supplied `SHA256SUMS.txt` inventory is:

```text
sha256:99a4404aa9a139d458c8921312903511c135159fc18c6512de7673477c55ed91
```

All 27 listed file digests plus the inventory digest are preserved in
`.fortress/changes/archive/2026/CHG-BOOTSTRAP-0001.json`. That change record is
the canonical machine-readable bootstrap provenance. This document records
human-readable disposition; neither record preserves a redundant full packet.

## Artifact matrix

| Temporary artifact | Disposition | Permanent target or rationale |
| --- | --- | --- |
| `README.md` | Intentionally discarded | Usage procedure was executed; permanent navigation is `docs/README.md` and historical execution is `CHG-BOOTSTRAP-0001`. |
| `MANIFEST.yaml` | Encoded and discarded | Authority precedence is in `docs/README.md`; all artifact mappings are recorded here and in `CHG-BOOTSTRAP-0001`. |
| `SHA256SUMS.txt` | Archived by digest, then discarded | Its digest and every listed entry are preserved in `CHG-BOOTSTRAP-0001`; keeping the inventory beside absent temporary files would create a misleading active packet. |
| `00-product-definition.md` | Promoted with transformation | `docs/product/definition.md`; temporary status changed to permanent product authority. |
| `01-engineering-philosophy.md` | Promoted with transformation | `docs/standard/philosophy.md`; temporary status changed and the separately sourced entropy/convention doctrine added with explicit provenance. |
| `02-standard-model.md` | Promoted with transformation and encoded | `docs/standard/model.md`, `standard/drafts/1.0.0/manifest.json`, and versioned standard/rule schemas. |
| `03-system-architecture.md` | Promoted with transformation | `docs/architecture/system.md`; current Rust boundaries implement the first core/presentation separation. |
| `04-repository-architecture.md` | Implemented and promoted | `docs/architecture/repository.md`; required roots contain real content and optional roots remain absent. |
| `05-contract-model.md` | Promoted with transformation and encoded | `docs/architecture/contracts.md` plus initial project, feature, architecture, command, change, and certification schemas. |
| `06-rule-system.md` | Promoted with transformation and encoded | `docs/standard/rules.md`, rule schema, draft `STD-ID-001`, core evaluator, and conformance fixtures. |
| `07-archetype-system.md` | Promoted with transformation and encoded | `docs/standard/archetypes.md`; initial compositional project archetypes are declared in `.fortress/project.json`. |
| `08-certification-model.md` | Promoted with transformation and encoded | `docs/certification/model.md`, certification schema, and truthful `NOT CERTIFIED` scaffold. |
| `09-incremental-certification.md` | Promoted with transformation | `docs/certification/incremental.md`; fingerprinting and attestation remain explicitly deferred. |
| `10-temporal-governance.md` | Promoted with transformation and encoded | `docs/governance/temporal.md`, change schema, and archived `CHG-BOOTSTRAP-0001`. |
| `11-onboarding-governance.md` | Promoted with transformation | `docs/onboarding/governance.md`; onboarding implementation remains deferred. |
| `12-command-runtime.md` | Promoted with transformation and encoded | `docs/architecture/command-runtime.md`, command schema/registry, and real help/version CLI. |
| `13-job-and-process-model.md` | Promoted with transformation | `docs/architecture/jobs.md`; persistent jobs remain deferred rather than stubbed. |
| `14-pipeline-governance.md` | Promoted with transformation and partially implemented | `docs/architecture/pipelines.md` and truthful low-cost CI; canonical pipeline/provider runtime remains deferred. |
| `15-language-and-tool-adapters.md` | Promoted with transformation | `docs/architecture/adapters.md`; analyzer and adapter roots remain absent until implementation exists. |
| `16-extension-model.md` | Promoted with transformation | `docs/architecture/extensions.md`; no speculative extension host was created. |
| `17-documentation-standard.md` | Promoted with transformation and applied | `docs/standard/documentation.md`; Rust source and substantive public symbols use rustdoc with warnings denied. |
| `18-testing-and-conformance.md` | Promoted with transformation and partially encoded | `docs/standard/testing.md`, separate `tests/` and `conformance/` boundaries, stable test IDs, and `STD-ID-001` fixtures. |
| `19-security-and-trust-model.md` | Promoted with transformation | `docs/architecture/trust.md`; false PASS and unattested evidence are prohibited in the self-model and CI documentation. |
| `20-versioning-and-upgrades.md` | Promoted with transformation and partially encoded | `docs/standard/versioning.md`; CLI `0.1.0`, schema family `v1`, and standard `1.0.0-draft.1` remain distinct. |
| `21-self-application.md` | Promoted with transformation and applied | `docs/governance/self-application.md` and the initial `.fortress/` declared model. |
| `22-1.0-scope.md` | Promoted with transformation | `docs/product/1.0-scope.md`; deferred capabilities remain explicit and no stable 1.0 claim is made. |
| `23-brand-and-public-identity.md` | Promoted with transformation and applied | `docs/product/brand.md`, repository/organization text, and website charter; no production logo asset was fabricated. |
| `24-bootstrap-acceptance-criteria.md` | Executed and archived | `docs/history/bootstrap-acceptance.md` preserves the gate and its execution result. |

## Disposal

After this matrix, the archived change record, and acceptance evidence existed
and validated, the untracked temporary `fortress-bootstrap-design/` directory
was removed from the active repository root. Permanent authority does not depend
on it. No full historical copy was committed.
