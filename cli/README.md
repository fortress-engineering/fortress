# CLI

## Purpose

The CLI exists to expose implemented Fortress operations through deterministic terminal and machine-readable interfaces without moving provider-independent semantics into presentation code.

## Responsibility

Own command registration, argument validation, process exit behavior, human rendering, and schema-versioned JSON rendering for version, help, raw repository audit, progressive finding checks, reviewable baseline/exception proposals, Module ownership inspection, semantic inspection, and exact-snapshot local certification.

Status, doctor, query, explain, author and `serve --stdio` are thin adapters over the single Snapshot Governance inspection facade. Human and JSON render the same result fields; the versioned protocol is independent of any editor, host or transport framework.

See the [local extension guide](_data/extension_guide.txt) for explicit layout inspection, evidence adapter selection, trusted local collection, and the two independently executable conformance kits.

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

### [Agent Integration](agent_integration/README.md)

**Types:** `depends_on`

Supplies local MCP framing, the client adapter, and process supervision shared by trusted integrations.

## Guarantees

See [local development installation](./_data/install_guide.txt) for verified portable archives, the VS Code extension, and offline assurance verification.

The [overlay command](./_docs/code_docs.md) evaluates exact immutable proposals and inspects post-write agreement without applying source changes. RPC v5 exposes complete preloaded proposal fields with bounded paging. Hypothetical outcomes remain PROPOSED, never actual certification or permission; CLI records cannot recreate external grants or execution proof.

`fortress query findings . --format json` pages retained finding records and their recorded enforcement. Protocol v5 advertises this optional query through `finding_inventory`. Existing editions and query kinds keep their prior wire meaning. The inventory supplies a matching source file digest only when the selected subject equals the newly observed source. A missing digest leaves source navigation unverified.

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

For newly governing policy, supply an existing migration-operation array containing exact preimages and proposed authority bytes. Keep the operation, review, and report files outside the governed source tree.

```text
fortress baseline admission . --operations policy-operations.json --format json
fortress baseline admission . --operations policy-operations.json --projection target-state --format json
fortress baseline admission . --operations policy-operations.json --history original-states.json --review review.json --base-selection base-policy.json --format json
fortress explain sha256:ASSESSMENT_REF . --proposal admission-assessment.json --format json
```

Each review uses the assessment's `assessment_ref`, the exact finding identity,
one of `ACCEPT_EXISTING`, `REMEDIATE`, `REJECT`, `DEFER`, or
`UNRESOLVED`, and a rationale. Acceptance also needs an external grant
citation. Missing and expired time-bound reviews cannot authorize changes.
The installed CLI returns a proposal. The migration interface requires
independent original-history selection and authenticated grants for the exact
reviewed operations. Ordinary inspection, audit, and certification preserve
raw violations and cannot infer authorization from a retained review.

Retain the exact `target-state` projection separately for later comparable
retirement. `baseline prune --from <target-state-file> --to current --finding <id>`
uses the same retirement proof rules for an admitted identity. Retirement
preserves the original record and prevents a later occurrence from receiving
that historical treatment. Mixed implementation and governing changes are
ineligible for automatic admission. Changes in Standard meaning, evaluator,
visibility, or incomplete scope remain unresolved when the existing comparison
cannot isolate the new requirement.

Readable checkpoint proposals use the explicitly prepared immutable authoring context:

```text
fortress behavior-author --schema
fortress behavior-author ./workflow --feature AF-WORKFLOW-0001 --checkpoint CHK-START=sample::entry --checkpoint CHK-AUTH=sample::authorize --checkpoint CHK-MUTATE=sample::mutate --checkpoint CHK-END=sample::entry --return CHK-END --format json
fortress serve --stdio ./workflow --behavior-authoring
```

Protocol v4 adds typed behavior_author parameters (feature, checkpoints, optional returns). Versions 1â€“3 reject that newer method and retain existing meanings. Preparation is explicit; requests over the loaded context do not start analysis. Schema guidance does not prepare source. The preview is PROPOSED and does not accept, write or authorize a declaration. Entry/return selectors are unique qualified names or canonical symbol IDs; ambiguity is an error. Canonical v3 contracts bind the exact context and require normal Module-owned intent and coverage validation. Requirement-to-test bindings and execution evidence remain separate.


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

The installed CLI supports unprotected initially ungoverned edits, exact no-ops and the separately reviewed initial-bootstrap boundary. It has no production external grant validator. For governed application, an embedding must supply `CanonicalMigrationAuthority` with the trusted original policy and the existing independently authenticated validator. `--base-selection` is allowed only for preview, and repository-authored JSON can never configure an application grant. Finding-governance maintenance additionally requires the existing RATCHET owner's process-local `GovernanceProposal`; retirement proofs remain bound to their original pre-maintenance state. Existing `migrate-identities` previews now use identity-migration v2 with a physical source reference; its trusted-host application routes through the same writer. CONTROL layouts 1â€“5 and historical generation manifests remain readable; current publication uses layout/generation v6.

External storage must be on the repository's native volume and outside the repository. The existing `FORTRESS_EXECUTION_STORAGE_DIR` default is reused; a cross-volume default is rejected before source mutation. Journals, locks, staging, original bytes and recovery material stay under OPS and are retained after interruption. Incomplete migration state blocks fresh native and Python current-source certification; historical/offline inspection remains available. Version 1 qualifies cooperative process-crash recovery over regular files and safe hard-link support. It does not promise filesystem-wide atomicity, arbitrary power-loss ordering, hostile-writer exclusion, ACL preservation or recursive directory transactions.

For finding-governance identity normalization, a trusted embedding supplies the existing identity owner's process-local plan as `identity_plan`; lifecycle admission checks exact source and edits, preserves baseline/history structure, and forbids rewritten current anchors. It remains separate from authorization. The generic CLI accepts neither serialized identity plans as grants nor arbitrary governance replacement as normalization. Retired identity-preview v1 output must be regenerated from the exact repository before use.

Explicit static projection construction uses a new external output directory:

```text
fortress projections ./project --output-dir /outside/project/new-projections --format json
```

The parent must exist and the destination must be new, ordinary and outside the repository. Completion publishes a versioned manifest after all canonical static members and source reobservation. Human output renders the same result. This command performs source analysis without Cargo tests, project build scripts or providers. It issues no certificate and authenticates no producer. Phase measurements are diagnostics on stderr during certification; canonical certificate bytes retain their existing meaning. Restoration checks the selected certificate and independent cold projection sets before accepting local materialization.

Maintainers can review exact upgrade compatibility, migration plans and recovery through the existing command and host interfaces. [Upgrade workflow](_docs/code_docs.md#upgrade_commandrs)

## Explicit Go compiler observations

An independently pinned scalar-body collector can also observe a bounded Go
body without project code execution. Its registration uses
`urn:fortress:host:v1:go-body-registration` with the existing version,
executable path, executable SHA-256 and toolchain fields. Build the collector
outside the observed project with the reviewed Go compiler and the two exact
files documented by [Program Semantics](../engine/program_semantics/README.md),
collector.go and go_body.go.

```text
fortress psm --observe-go-body PROJECT HOST_REGISTRATION DIRECTORY PACKAGE_PATH go1.22 linux amd64
```

The receipt identifies exact original source, authority, target and native
producer. Supported free functions have named bool or int64 inputs and one
unnamed bool or int64 result, and use the documented bounded local scalar
statements. Other functions have source-bound unavailable outcomes. Package
invalidity, unsupported dependencies and resource limits are distinct. The
observation reports conservative return value domains for admitted scalar
inputs. Inspect the aligned `value_domains` alongside `functions`.
An inferred integer range uses exact inclusive decimal strings, even at the
full int64 endpoints. Unavailable bodies or inferences have an explicit reason.
Execution, effects, conformance and certification remain separate.

Ordinary PSM remains the existing Rust-backed model. The Go observation
command uses an independently selected native helper and emits a separate
versioned report.

~~~text
fortress psm --observe-go PROJECT HOST_REGISTRATION DIRECTORY PACKAGE_PATH go1.22 linux amd64
~~~

Use a host-owned registration outside the project. Declare the absolute
collector executable, its exact SHA-256, and the expected Go toolchain. Use a
complete closed package directory with no external imports. The target OS is
explicit. A directory of . selects the project root.

The registration schema is urn:fortress:host:v1:go-collector-registration with
schema_version 1 and the executable, executable_sha256 and toolchain fields.
The host verifies the executable immediately before launch, isolates its
environment and bounds the exchange. The command reports package-local typed
declarations and supported call observations. Build selection, imported
packages, foreign bodies, dynamic dispatch and runtime effects may remain
unresolved. The report conveys no finding, certification or write authority.

### Explicit Go build selection

For filename and build-constraint selection, use the separately reviewed helper
built from collector.go and collector_build_context.go. Register the combined
executable outside the repository with its own exact digest and toolchain. The
registration uses urn:fortress:host:v2:go-build-collector-registration and
schema_version 2. It also requires the exact build_context defined by the
[registration schema](_data/go_collector_schema_v2.json).

~~~text
fortress psm --observe-go-build PROJECT HOST_REGISTRATION DIRECTORY PACKAGE_PATH go1.22 linux amd64
~~~

Select compiler gc, release_minor 22, cgo_enabled false, test_mode
PRODUCTION_ONLY, custom_tags [], and tool_tags ["amd64.v1"] for the default
registered Go 1.22 amd64 production context. Specify
REQUIRE_SEPARATE_TEST_CONTEXT to leave a matching test file explicitly
unresolved. The v2 report preserves selected and excluded source digests,
physical spans and the exact source, authority, execution and context bindings.
Use the separate v1 command and v1 registration for the legacy closed-package
projection. External imports, actual test execution and runtime behavior remain
outside the reported build-selection scope.

## Explicit Python lexical observations

Use `fortress source-artifacts --observe-python PROJECT HOST_REGISTRATION SOURCE_PATH lexical` from a trusted host. The selected path is a repository-relative `.py` file. Use `syntax` for the narrower parser-only result. The mode returns a separate machine-readable observation.

Keep the host registration, interpreter and exact reviewed worker outside the project. The supplied registration pins the interpreter executable, selected CPython runtime descriptor and grammar. The worker must match the bytes shipped with Fortress. Review the available runtime context and platform limits before launching. See [Python worker setup](_docs/code_docs.md#python_observe_commandrs).

### Closed Go module observations

Use the separate v3 [host registration](_data/go_collector_schema_v3.json) with the worker built from all three Go collector sources. The registration and executable live outside the observed repository. The qualified host runs Go 1.22.12 on Windows x64 or Go 1.22.2 on Linux x64.

~~~text
fortress psm --observe-go-module PROJECT HOST_REGISTRATION . example.test/module example.test/module/app linux amd64
~~~

The module directory is relative to the project. A dot selects the project root. The selected module path must match the captured go.mod bytes. The supported module file declares only a module and Go 1.22. Its source consists of ordinary Go library packages with explicit target selection. Dependency resolution is confined to captured directories in that module. Module and workspace indirection, vendoring, external dependencies, cgo, generated or non-Go compiler input and ambiguous module roots are outside the supported scope. The command invokes no project tools.

Optionally append four arguments giving the left package, left type name, right package and right type name. Both declarations must be in the reachable package graph. The receipt distinguishes lexical imports, static declaration associations and unresolved dispatch. It carries exact actual-source, governing authority, build context and worker identities, separately from PSM analysis and certification.

## Explicit Python scalar inspection

Run `fortress source-artifacts --observe-python-scalar PROJECT HOST_REGISTRATION`
on a Windows x64 or Linux x64 host with an independently pinned CPython 3.12 or
3.13 installation. Use the matching `python_scalar_worker.py` and
`python_lexical_worker.py` assets beside the installed `bin` directory under
`share/fortress/workers`. Select the absolute paths to both sibling files
outside the project. The installation
must keep the interpreter, libraries and assets under independent trusted
control. The registration and interpreter paths are also absolute and
external to the project.

The separate registration uses
`urn:fortress:host:v1:python-scalar-registration` and schema version 1. Supply
`interpreter`, `interpreter_sha256`, `worker`, `bootstrap`, `runtime_ref` and
`grammar`. The grammar values are `cpython3.12` and `cpython3.13`. Select the
runtime independently from the lexical worker's isolated
`--describe-runtime` descriptor. Its digest uses exact canonical descriptor
bytes without the framing LF. Under `subject`, supply `source_path`,
`source_ref`, `function` and `exact_bool_parameters`. The source path is
repository-relative and the SHA-256 pin binds the exact subject bytes.
List only independently established exact bool parameters in declaration order.
For a zero-parameter function use the empty array.

An admitted body with a conditional output bound appears as `LOWERED` and
`UPPER_BOUND_UNDER_EXACT_INPUT_ASSUMPTIONS`. A body can be lowered while an
inferred domain remains unavailable. Unsupported syntax or scope has an
explicit unavailable disposition. The observation reports unproven runtime
argument types, compile-only execution, and no assessment.

### Static Python import inspection

Use the same independently pinned CPython lexical host with
`fortress source-artifacts --observe-python PROJECT HOST_REGISTRATION SOURCE_PATH imports ROOT_SCOPE ROOT_SCOPE_SHA256`.
Keep the root-scope file outside the repository. Its independently selected
digest is SHA-256 over its canonical JSON bytes, including the exact root order.
A scope is an analysis selection, with no project authority or execution grant.

The scope uses `urn:fortress:host:v1:python-static-import-scope`, schema version 1,
an `inventory` value of `COMPLETE_SOURCE_ONLY`, and one to four explicitly
ordered `roots` relative to the repository. Roots must be disjoint and contain
only admitted ordinary Python source. An incomplete scope, wrong digest or
project-owned host input is refused. Conflicting names, unavailable roots and
unsupported root contents are reported separately from lookup absence.

The report retains the original source, evaluator context, authority and
compile-only lexical artifact. Static lookup can identify a source file or
ordered namespace portions under the selected roots. Missing results are scoped
to that admitted inventory. Empty directories, dynamic imports, runtime
package discovery and from-import member resolution remain unresolved.
