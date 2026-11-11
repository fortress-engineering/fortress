# CLI

## Purpose

The CLI exists to expose implemented Fortress operations through deterministic terminal and machine-readable interfaces without moving provider-independent semantics into presentation code.

## Responsibility

Own command registration, argument validation, process exit behavior, human rendering, and schema-versioned JSON rendering for version, help, raw repository audit, progressive finding checks, reviewable baseline/exception proposals, Module ownership inspection, semantic inspection, and exact-snapshot local certification.

Status, doctor, query, explain, author and `serve --stdio` are thin adapters over the single Snapshot Governance inspection facade. Human and JSON render the same result fields; the versioned protocol is independent of any editor, host or transport framework.

## Scope

### Includes

The native process boundary, built-in command registry, CLI package and command declarations, supported audit, finding listing/checking, baseline capture/create/review/prune proposals, exception list/review/create/retire proposals, declared/logical/analysis-only Module inspection, semantic-analysis formats, local certification formats, and explicit failure behavior for malformed or unsupported input. Prune refuses to retire entries from absence alone until comparable subject, authority, and coverage evidence is available.

**Declared information-flow inspection**

`fortress information-flow [path] --format human|json` reports the same versioned analysis with independent applicability, findings and uncertainty. `fortress flow-author --schema` prints operation-policy guidance. A readable preview can use `fortress flow-author . --source sample::credential --sink sample::log --facet FLOW-CONFIDENTIALITY --level SECRET --bound PUBLIC --format json`; existing finite facets are required. The canonical proposal includes the current context and policy preimage; it remains UNAPPROVED.

`serve --stdio --flow-authoring` explicitly preloads an immutable PSM/policy authoring context for typed RPC v3 flow_author requests. Ordinary serve does not prepare one and returns UNAVAILABLE for this method. Preparation is read-only and does not execute project code. Later queries perform no hidden semantic analysis. A declared declassifier or endorsement is a visible assumption, never automatic proof of implementation or external approval.

### Excludes

Core standard or rule semantics, cryptographic attestation, hosted-provider execution, persistent jobs, and commands without real implementation.

## Relationships

### [Engine](../engine/README.md)

**Types:** `depends_on`

Invokes the Engine for command discovery, end-to-end Snapshot Governance audit behavior, deterministic CCG, Intended BFG, and Realized BFG inspection, snapshot-bound Program Semantic Model inspection, and function-domain, state/effect, information-flow, and environmental analysis inspection.

### [Certification](../engine/certification/README.md)

**Types:** `depends_on`

Runs the canonical unfiltered Rust suite locally, constructs current execution evidence, and emits deterministic Evidence Graph, Certification, and Verified BFG artifacts without delegating long verification to hosted CI.

### [Migration Governance](../engine/migration_governance/README.md)

**Types:** `depends_on`

Provides versioned explicit preview, application and recovery contracts without introducing a CLI grant validator.

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

Protected authority inspection uses `authority capture`, `authority preview --from snapshot --to snapshot --base-selection file`, and `authority inspect --decision file`. Preview has no external authorization mechanism or write mediation. Explicit selection is required; owner-approved public defaults are not inferred.

`explain <decision-digest> --decision <receipt>` and `serve --stdio --decision <receipt>`
preload up to sixteen immutable decision receipts into the existing paged explanation
service. The existing v1/v2 protocol, request IDs, cancellation and bounded cursors
are unchanged. Reading a receipt performs no grant verification or semantic analysis;
recorded approval and host-coverage claims remain unverified provenance.

A successful preview exit means the report was rendered. It does not authorize
application, publication or installation; those require the independently trusted
host context and all reported decision premises.

Finding lifecycle operations produce read-only proposals and reviews:

```text
fortress baseline capture .
fortress baseline create . --format json
fortress baseline review . --from original-state.json --to current --format json
fortress baseline prune . --from original-state.json --to current --finding sha256:EXACT_FINDING --format json
fortress exceptions create EX-APP-0001 sha256:EXACT_FINDING --authority owner-reference --rationale "Scoped reason" --review-at 100 --expires-at 200 . --format json
fortress exceptions review . --to current --assessment-time 100 --format json
fortress exceptions retire EX-APP-0001 --rationale "Explicit retirement reason" . --format json
```

Retain the captured original comparison input and proposal outside the governed source tree so saving a report does not change the compared subject. New baseline proposals bind original eligible findings and refuse replacement. Prune proposals select only supported comparable retirements and retain every unresolved entry. Review distinguishes PRESENT, RESOLVED, SUBJECT_REMOVED, NOT_OBSERVED, POLICY_RETIRED, SCOPE_EXCLUDED, AUTHORITY_INCOMPARABLE and IDENTITY_AMBIGUOUS. Explicit review time is a nonnegative exact integer; missing time never implies an unexpired exception.

These commands do not write active governance. The installed CLI cannot synthesize a grant; `--apply` reports AUTHORIZATION_REQUIRED. A trusted host must consume the protected exact-postimage interface. Legacy entries without original anchors require explicit reviewed migration rather than manufactured proof. An exception proposal, local file or approval URL remains an unverified reference and does not suppress a current violation.

Retained retirement records can be inspected without comparison or analysis using `fortress explain sha256:EXACT_RETIREMENT_RECORD --retirement retirement-records.json` or `fortress serve --stdio --retirement retirement-records.json`. Existing protocol versions 1 and 2 and bounded evidence paging are unchanged. Recorded outcome and authorization provenance remain visibly unverified at this inspection boundary.

Readable checkpoint proposals use the explicitly prepared immutable authoring context:

```text
fortress behavior-author --schema
fortress behavior-author ./workflow --feature AF-WORKFLOW-0001 --checkpoint CHK-START=sample::entry --checkpoint CHK-AUTH=sample::authorize --checkpoint CHK-MUTATE=sample::mutate --checkpoint CHK-END=sample::entry --return CHK-END --format json
fortress serve --stdio ./workflow --behavior-authoring
```

Protocol v4 adds typed behavior_author parameters (feature, checkpoints, optional returns). Versions 1–3 reject that newer method and retain existing meanings. Preparation is explicit; requests over the loaded context do not start analysis. Schema guidance does not prepare source. The preview is PROPOSED and does not accept, write or authorize a declaration. Entry/return selectors are unique qualified names or canonical symbol IDs; ambiguity is an error. Canonical v3 contracts bind the exact context and require normal Module-owned intent and coverage validation. Requirement-to-test bindings and execution evidence remain separate.


Migration preview and inspection are read-only by default:

```text
fortress migrate preview --root ./project --operations /outside/project/operations.json --format json
fortress migrate preview --root ./project --operations /outside/project/operations.json --export
fortress migrate inspect --plan /outside/project/plan.json --format human
fortress migrate apply --root ./project --plan /outside/project/plan.json --storage-root /same-volume/external/ops --format json
fortress migrate recover --root ./project --plan /outside/project/plan.json --transaction EXACT_TRANSACTION --direction rollback --storage-root /same-volume/external/ops --format json
fortress migrate inspect --receipt ./project/__fortress/records/migrations/EXACT_DIGEST.json --format json
```

Operations are a bounded array of `CREATE_FILE`, `REPLACE_FILE`, `MOVE_PATH`, or `DELETE_OWNED_FILE` records. Exact byte arrays and readable repository-relative paths require no manually extracted hashes. See the [Migration Governance guidance](../engine/migration_governance/README.md) and its operations example. Preview produces MigrationPlan v1 with canonical operation ordering, exact source/state references, validation facts, transition and authorization requirements. Human output renders the same retained plan. `--export` is an explicit write of the reviewed proposal to the registered proposals family; it does not apply source operations.

Application is explicit, rechecks the complete reviewed target and current preimages, and reports an owned transaction reference after allocation. Recovery requires that exact plan, external storage and transaction. `resume` rechecks authorization; `rollback` verifies original bytes and preserves independent edits as conflicts. Neither mode runs project build scripts. A completed receipt is historical application evidence, not certification or present freshness; undoing a completed migration requires another reviewed plan.

The installed CLI supports unprotected initially ungoverned edits, exact no-ops and the separately reviewed initial-bootstrap boundary. It has no production external grant validator. For governed application, an embedding must supply `CanonicalMigrationAuthority` with the trusted original policy and the existing independently authenticated validator. `--base-selection` is allowed only for preview, and repository-authored JSON can never configure an application grant. Finding-governance maintenance additionally requires the existing RATCHET owner's process-local `GovernanceProposal`; retirement proofs remain bound to their original pre-maintenance state. Existing `migrate-identities` previews now use identity-migration v2 with a physical source reference; its trusted-host application routes through the same writer. CONTROL layouts 1–5 and historical generation manifests remain readable; current publication uses layout/generation v6.

External storage must be on the repository's native volume and outside the repository. The existing `FORTRESS_EXECUTION_STORAGE_DIR` default is reused; a cross-volume default is rejected before source mutation. Journals, locks, staging, original bytes and recovery material stay under OPS and are retained after interruption. Incomplete migration state blocks fresh native and Python current-source certification; historical/offline inspection remains available. Version 1 qualifies cooperative process-crash recovery over regular files and safe hard-link support. It does not promise filesystem-wide atomicity, arbitrary power-loss ordering, hostile-writer exclusion, ACL preservation or recursive directory transactions.

For finding-governance identity normalization, a trusted embedding supplies the existing identity owner's process-local plan as `identity_plan`; lifecycle admission checks exact source and edits, preserves baseline/history structure, and forbids rewritten current anchors. It remains separate from authorization. The generic CLI accepts neither serialized identity plans as grants nor arbitrary governance replacement as normalization. Retired identity-preview v1 output must be regenerated from the exact repository before use.
