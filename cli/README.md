# CLI

## Purpose

The CLI exists to expose implemented Fortress operations through deterministic terminal and machine-readable interfaces without moving provider-independent semantics into presentation code.

## Responsibility

Own command registration, argument validation, process exit behavior, human rendering, and schema-versioned JSON rendering for version, help, raw repository audit, progressive finding checks, explicit baseline/exception mutation, Module ownership inspection, semantic inspection, and exact-snapshot local certification.

Status, doctor, query, explain, author and `serve --stdio` are thin adapters over the single Snapshot Governance inspection facade. Human and JSON render the same result fields; the versioned protocol is independent of any editor, host or transport framework.

## Scope

### Includes

The native process boundary, built-in command registry, CLI package and command declarations, supported audit, finding listing/checking, baseline creation, guarded baseline prune, exception list/create/retire, declared/logical/analysis-only Module inspection, semantic-analysis formats, local certification formats, and explicit failure behavior for malformed or unsupported input. Prune refuses to retire entries from absence alone until comparable subject, authority, and coverage evidence is available.

### Excludes

Core standard or rule semantics, cryptographic attestation, hosted-provider execution, persistent jobs, and commands without real implementation.

## Relationships

### [Engine](../engine/README.md)

**Types:** `depends_on`

Invokes the Engine for command discovery, end-to-end Snapshot Governance audit behavior, deterministic CCG, Intended BFG, and Realized BFG inspection, snapshot-bound Program Semantic Model inspection, and function-domain, state/effect, information-flow, and environmental analysis inspection.

### [Certification](../engine/certification/README.md)

**Types:** `depends_on`

Runs the canonical unfiltered Rust suite locally, constructs current execution evidence, and emits deterministic Evidence Graph, Certification, and Verified BFG artifacts without delegating long verification to hosted CI.

## Guarantees

Unsupported commands and options return non-success; audit succeeds only when every evaluated mandatory rule passes; non-applicable rules are reported separately from PASS; progressive check may accept visible baselined or explicitly excepted residue without labeling it PASS; baseline never grows during ordinary validation; semantic inspection renders authored ALLOW entries as authorizations rather than conformance results and preserves existing coverage/uncertainty boundaries; `certify` returns success only for a truthful full-profile PASS based on current local execution; JSON and human output remain deterministic; no command labels static realization as executed evidence or a digest stamp as an authenticated signature.

Portable evidence commands consume already-retained products:

```text
fortress bundle export . --output portable-evidence --predicate-type https://OWNER/assurance/v1
fortress bundle export . --state captured-state.json --output portable-state --predicate-type https://OWNER/assurance/v1
fortress sarif . --generation sha256:EXACT_GENERATION --output findings.sarif
fortress sarif --audit retained-audit.json --output diagnostics.sarif
fortress bundle verify portable-evidence --predicate-type https://OWNER/assurance/v1 --format human
fortress bundle verify portable-state --predicate-type https://OWNER/assurance/v1 --current-state independently-captured-state.json
python -I -B testing/_code/verify_bundle.py portable-evidence --predicate-type https://OWNER/assurance/v1
```

Choose an owner-controlled predicate URI explicitly; no public namespace or issuer is assumed. `--generation` and `--selection` are exact alternatives, and `--state` admits an explicitly captured StateView3. Ambiguity, missing historical metadata and unsupported versions are errors or incomplete results, never latest-PASS fallbacks. Independently supplied `--expected-subject`, `--expected-context`, `--expected-authority` and `--expected-profile` distinguish reference agreement from unknown current freshness. Integrity verification does not authenticate a producer or prove execution, semantics or authorization. SARIF is a lossy finding/diagnostic view, with no assurance gate authority.

Capture state files outside the observed repository to avoid changing the subject while capturing it. `--current-state` compares independently supplied original references without running capture or analysis; it is mutually exclusive with individual expected references. `sarif --audit` projects explicit retained diagnostics; optional matching declaration and authority files add claims and rule metadata. Missing declarations never imply passing claims. Output destinations must be new; commands do not overwrite evidence or repair inputs.
