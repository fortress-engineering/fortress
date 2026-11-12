# Code

## Role

Turn implemented Engine behavior into validated native command execution and deterministic presentation.

## Execution

The native entrypoint delegates arguments to the CLI library, which resolves the command registry, validates options, invokes Engine behavior, renders the selected format, and returns a process status. Local certification runs the unfiltered Rust suite with an absolute Cargo target outside the governed repository, then emits content-addressed evidence for lightweight hosted freshness/stamp verification.

The local issuer builds the CLI and runs an exact-byte copy in owned staging, leaving its compiler target available to the complete workspace/all-target/all-feature suite. The suite executes afresh; only Cargo's source, toolchain, dependency, feature and configuration fingerprinted compilation outputs can be reused. Direct execution from inside the compiler target retains an isolated child target to avoid replacing the running Windows image. Existing target paths are resolved before the repository boundary and running-image checks.

## State

Command execution is process-local; repository audit state is loaded for one invocation and no persistent job state is created.

## Failure Semantics

Malformed input, unsupported operations, invalid repository state, or evaluated rule failure returns non-success with an explicit diagnostic; no failure becomes a certification claim.

## Files

### [`candidate_command.rs`](../_code/candidate_command.rs)

Adapts explicit overlay base/evaluate/inspect/reconcile requests to the existing Snapshot Governance service. Human and JSON projections preserve all fields. No apply method, production grant validator or execution-assertion reader is installed; explicit export retains a non-authoritative role-resolved proposal. See [candidate examples](code_docs.md).

**Hypothetical source proposals**

`fortress overlay` exposes explicit read-only analysis. It never applies source edits or accepts JSON as external approval or execution evidence.

```text
fortress overlay base --root <repository> --format json
fortress overlay evaluate --root <repository> --request <external-request.json> --format json
fortress overlay evaluate --root <repository> --request <external-request.json> --storage-root <existing-external-OPS-root> --export --format json
fortress overlay inspect --root <repository> --proposal <proposal.json> --format human
fortress overlay reconcile --root <repository> --proposal <proposal.json> --format json
```

The base command explicitly evaluates and returns `base_source_ref`, `context_ref`, `base_state_ref` and `trusted_base_authority`. Copy exact base/context references into a request. Keep request files outside the compared repository; creating or changing an input request inside its physical inventory invalidates that base. Obtain exact preimage bytes through an admitted repository view; paths alone are insufficient.

```json
{
  "schema_version": 1,
  "base_source_ref": "sha256:<exact physical base digest>",
  "context_ref": "sha256:<exact original context digest>",
  "operations": [
    {"kind":"REPLACE_FILE","path":"src/lib.rs","preimage":[47,47,32,65,10],"postimage":[47,47,32,66,10]}
  ]
}
```

This example replaces the exact bytes `// A\n` with `// B\n`; it is not a valid request until both digest placeholders and preimage match the actual base. Operation variants and limits are the existing MIGRATE vocabulary, documented by the public candidate-request schema. Repeat `--original-state <exact comparison-state reference>` up to sixteen times to preload original historical evidence for baseline retirement. The existing CONTROL history loader resolves each explicit reference; missing history is never reconstructed as verified. Optional `comparison_context` carries explicit comparison inputs and unverified citations. `--client` and `--candidate` select isolated buffer IDs. The default complete cold evaluator creates no runtime storage; supplying an existing external storage root enables qualified SESSION preparation.

For protected governance, `--base-selection` accepts the existing preview-selection schema to describe the original policy. This CLI remains an unmediated preview with NoGrantValidator. Missing authority produces an explicit authorization error beside predicted results. No base-selection JSON can construct an authenticated grant, assessor admission or CandidateWritePermit. Production trusted hosts must use the existing AUTHORITY port and their independently established execution boundary.

Both formats render the same immutable assessment fields. Every finished hypothetical result says `status: PROPOSED`, `actual_state: false`; raw conformance, enforcement, assurance and permission remain distinct. Explicit `--export` retains only a role-resolved non-authoritative proposal and reports its path. No current generation is published. Reconciliation of a retained record can establish `EXACT_MATCH_UNVERIFIED` or `DIVERGED`; it cannot restore original permission or runtime evidence from strings. Only a trusted in-process host using original-state authorization and independent current execution can request actual verification.

**Read-only RPC inspection**

```text
fortress serve <repository> --stdio --proposal <proposal.json>
```

```json
{"protocol_version":5,"request_id":"proposals","method":"candidate","state_ref":null,"context_ref":null,"parameters":{"candidate_ref":null,"page":{"limit":50}}}
```

The response lists explicitly loaded candidate `evaluation_ref` values. Request one to retrieve every original field through exact JSON pointers:

```json
{"protocol_version":5,"request_id":"details","method":"candidate","state_ref":null,"context_ref":null,"parameters":{"candidate_ref":"sha256:<loaded evaluation_ref>","page":{"limit":50,"cursor":null}}}
```

Pass the returned `next_cursor` unchanged until it is null. Paging is bound to the exact loaded proposal and service state. Responses use the existing request IDs, context/state checks, bounded frame/response sizes, structured errors, cancellation and progress protocol. Older versions explicitly reject `candidate`; later unsupported versions are rejected. No RPC method applies a proposal, executes project code, repairs state or starts expensive analysis while formatting. Evaluation is an explicit CLI or typed CandidateWorkspace operation, independent of any editor, agent host or transport framework.

### [`command.rs`](../_code/command.rs)

Defines the stable built-in command registry and rejects duplicate or unimplemented command contracts.

### [`lib.rs`](../_code/lib.rs)

Dispatches supported arguments, invokes raw audit and progressive finding checks, performs explicit baseline/exception and semantic-identity authority migration, delegates human projection to canonical presentation helpers, explains exact-snapshot affected closure, reuses only verified dependency-bound projection bytes, invokes semantic projections and local full-snapshot certification, and assigns process status without conflating conformance with enforcement.

### [`presentation.rs`](../_code/presentation.rs)

Projects canonical authority, Module, coverage, authorization, conformance, and causal evidence into deterministic human diagnostics; resolves stable symbols to qualified names when available and groups transitive reachability by distinct operation site without changing machine identity or findings.

### [`main.rs`](../_code/main.rs)

Provides the native process entrypoint and delegates all command behavior to the CLI library.

The native `declare`, `assess`, and `state-view` commands render Certification-owned canonical JSON application artifacts. They execute no verification provider and do not reuse a successful certificate as the endpoint. `state-view` reports missing or invalid authored authority without crossing the strict governed-analysis boundary. Assessment exit success is reserved for a satisfied exact application profile; local implementation qualification is a separate command and artifact.

### [`application_inputs.rs`](../_code/application_inputs.rs)

Parses explicit evidence selections and optionally injected host admission outside the physical candidate repository. No implicit policy, authentication claim, freshness marker or project execution is accepted.

### [`provider_command.rs`](../_code/provider_command.rs)

Normalizes bounded original JUnit or SARIF payloads through the Snapshot Governance import boundary. Canonical output reports unverified observations, not certification; original payload bytes remain available to the caller for retained replay.

### [`rpc.rs`](../_code/rpc.rs)

Projects the shared inspection protocol over bounded UTF-8 JSON lines. A bounded reader handles active-request cancellation while immutable queries run; lifecycle observations never grant mutation authority.

### [`inspection.rs`](../_code/inspection.rs)

Parses status, doctor, query, explain, author and serve options, performs explicit loading, and renders the same canonical result fields in human or JSON form. Optional timings report cold loading separately from warm query work without certification thresholds.

**Governance inspection workflow**

`fortress status .` separates the actual observed source and authority, selected
historical evidence, raw dimension truth, progressive residue/enforcement, profile
assessment, unknown semantics, local materialization and unauthenticated provenance.
`--format json` returns the exact same fields. `--timing` writes observational cold
loading and warm query durations to stderr; timings impose no certification gate.

`fortress doctor .` reads configuration, authority, bounded source inventory,
selected evidence, cache availability, host platform and storage metadata. It does
not execute compilers, build scripts, tests, provider commands or project hooks,
probe writeability, regenerate artifacts, clean storage or repair configuration.
Missing declared toolchains and unexecuted toolchain availability remain explicit.

Examples using readable selectors:

```text
fortress query modules . --limit 20 --format json
fortress query modules . --selector "Snapshot Governance"
fortress query policy "Snapshot Governance" .
fortress query dependents "Certification" .
fortress query routes "Snapshot Governance" . --target CAP-CERTIFICATION
fortress query relationships "Snapshot Governance" .
fortress query references "Snapshot Governance" .
fortress explain rule:STD-ID-001 . --limit 20
fortress author "Snapshot Governance" . --target filesystem.write --disposition DENY
```

Module IDs, full display-name paths separated by `::`, unique display names and
canonical Module paths are supported. Ambiguity returns all canonical candidates;
select one explicitly. Consumers require providers: dependents queries retain that
direction. Route rows distinguish `DECLARED_PERMITTED` exact capability requirements
from `OBSERVED` implementation records. A path never creates transitive permission.
Authoring previews are `PROPOSED`, bind the contract preimage, and print validated
canonical contract bytes. They never write authority or accept their own proposals.

`fortress explain <finding-or-claim-or-obligation-or-defeater-id> .` links governing
rule text, rationale, failure prevention, recorded scope, reasons, uncertainty,
support/counterevidence, provenance and remediation. Pass `--state <existing-file>`
when a complete already-generated StateView is available. Historical generations
that omitted the complete obligation/evidence-admission metadata disclose that gap;
no evaluator runs to fill it. Minimal support is stated only for a matching recorded
single-premise conclusion. Other proof alternatives remain visible without an
invented minimality claim. Missing evidence is an unresolved dependency, never proof.

**Protocol v1 and downstream integration**

`fortress serve --stdio .` loads once, then accepts strict UTF-8 JSON lines. The core
request, response and method DTOs are independent of stdio, IDE, MCP, LSP and agent
frameworks. Future IDE and host integrations consume these DTOs unchanged; resident
sessions can supply immutable inputs to the same `QueryService::new` constructor.
No future transition, mutation or host-authorization method is implied by this API.

```json
{"protocol_version":1,"request_id":"discover","method":"status","state_ref":null,"context_ref":null,"parameters":{}}
```

Copy the response's `state_ref` and, where present, `context_ref` into later requests.
These identify the loaded query input, including its selected evidence and observed
availability. A different identity returns `STATE_MISMATCH`. Context describes the
recorded evaluation; it is not a claim that the current host matches that context.

```json
{"protocol_version":1,"request_id":"modules","method":"query","state_ref":null,"context_ref":null,"parameters":{"kind":"modules","page":{"limit":20,"cursor":null}}}
{"protocol_version":1,"request_id":"stop","method":"cancel","state_ref":null,"context_ref":null,"parameters":{"request_id":"modules"}}
{"protocol_version":1,"request_id":"poll","method":"progress","state_ref":null,"context_ref":null,"parameters":{"request_id":"modules"}}
```

`protocol` enumerates methods and operational limits. `status` and `doctor` take
empty parameter objects; `query`, `explain`, `author`, `cancel` and `progress` have
strict typed parameters in the registered request schema. Unsupported versions and
methods return structured errors, with no optimistic fallback. Active request IDs
must be unique. Cancellation is cooperative and handled by a bounded input reader
while a query runs; a completed request is not retroactively cancelled. Progress
reports `QUEUED_OR_RUNNING` or `NOT_ACTIVE`, never a fabricated completion percentage.

The adapter admits sixteen active requests and applies bounded queue backpressure.
Frames are limited to 65,536 bytes, responses to 1,048,576 bytes, pages to 200 rows,
and the immutable index to 100,000 records and 64 MiB of serialized row data. Cold
loading admits at most 128 MiB of source, 50,000 source entries, 32 MiB per evidence
file and 128 MiB aggregate retained evidence. These are resource-safety limits, not
performance qualification thresholds. Oversized or malformed frames recover at the
next newline. An oversized answer returns `RESOURCE_LIMIT`; callers can reduce a
page size. No partial answer is silently presented as complete.

Paged results carry exact total, offset, rows and a query/state-bound continuation.
Continue until `next_cursor` is null. Page size can change without losing records;
a continuation from another query or loaded state is rejected. Evidence nodes and
provenance partitions are separate rows, preserving shared paths without expanding
proof expressions into exponential alternatives. Human rendering traverses the same
response fields; no format-specific evaluator or alternative permission logic exists.

Current limits: toolchain execution and producer authentication are not performed by
inspection; omitted raw payloads and historical proof metadata remain unavailable.
Only existing declared direct capability edges and supplied observed routes are
reported; arbitrary inferred route alternatives and global proof minimization are
not asserted. Read safety uses bounded optimistic filesystem observation and rejects
linked evidence paths; it is not a filesystem lock against a malicious host.

Every response envelope carries `actual_source_ref` (observed at loading),
`selected_source_ref` and `source_freshness`. A stale selected result never
establishes current conformance, even when a caller reads only a single policy or
explanation page. Later source edits require explicit loading of a new immutable
input; querying an existing handle never runs hidden analysis.

The stdio adapter cancels active work and returns if output closes. A stream owner
must close input during shutdown so the single blocked read-only reader can release
its immutable handle; the native process can exit on output failure.

### [`transition_command.rs`](../_code/transition_command.rs)

Read-only explicit state capture and comparison over the same typed query service; no approval or historical evaluator executes.

**Exact state comparison**

`fortress transition capture .` writes a bounded canonical comparison-state to
stdout. Save captures outside the compared repository so an output file cannot
change that repository's subject. Capture explicitly evaluates installed owners,
without running project scripts or an old evaluator. Comparison of supplied files
is read-only and uses the one State Governance comparator.

```text
fortress transition capture . > ../before-state.json
fortress transition capture . > ../after-state.json
fortress transition --from ../before-state.json --to ../after-state.json . --format json
fortress transition --from generation:sha256:299aa181a09dac32ff9b36c2c5134c7060586b60b48d60cd05d866eb0dec7050 --to current .
```

The final example deliberately retains NOT_COMPARABLE dimensions when a generation
lacks the necessary historical source/authority or complete StateView metadata.
It preserves the original declaration and assessment; historical PASS never becomes
current proof. `current` is an explicit bounded capture, not a latest-green lookup.
There is no transition database or automatic durable publication.

Input identities, four axes, semantic truth, coverage, evidence/assurance and finding
dispositions remain independent. A verdict change is never labelled a regression,
improvement or code fix. Finite policy implication requires the same vocabulary,
quantifier, scope, context and interpretation. Guarantee implication supports only
ALL of unchanged exact requirement definitions; prose changes are noncomparable.
Adding or removing a property is reported separately from strengthening a promise.
Missing findings remain not observed or incomparable; retirement observations cannot
edit baselines. Authorization references always remain NOT_VALIDATED citations.

`--limit` and `--cursor` page every delta and incomparability until next_cursor is
null. The analysis_ref binds the entire result independently of page size. A cursor
from another state/context is rejected. Atomic oversized rows return RESOURCE_LIMIT;
the full bounded native compare_states API remains available. No data is silently
truncated. Input and result documents admit 32 MiB, 50,000 total comparison records,
eight merge parents and four counterfactual cells. Loading admits sixteen states
and 128 MiB aggregate state bytes. Prepared comparisons are retained in a bounded
process-local cache of at most four results and 64 MiB. Paging a retained result
only projects immutable records; eviction never changes its content address. These
are safety quotas, not speed guarantees.

**Protocol v2 comparison and future consumers**

Protocol v1 schema files and result meanings remain unchanged. Protocol v2 adds
`transition`; existing methods are also available under v2. Begin with explicit
preloading, then use the small `protocol` inventory to select exact state references:

```text
fortress serve --stdio . --comparison-state ../before-state.json --comparison-state ../after-state.json
```

```json
{"protocol_version":2,"request_id":"inventory","method":"protocol","parameters":{}}
{"protocol_version":2,"request_id":"comparison","method":"transition","parameters":{"from_state_ref":"sha256:<advertised-before>","to_state_ref":"sha256:<advertised-after>","page":{"limit":20}}}
```

Comparison requests never load files, execute endpoint analysis, repair state or
validate grants. `comparison_context` accepts explicit evaluated common-authority
cells and authorization citations. Large already-loaded cells can instead be named
in `counterfactual_state_refs`. Software identity is projected from complete SUBJECT
roles; governing identity binds complete INTENT, AUTHORITY and GOVERNANCE roles plus
Standard, profiles, evaluator, scope and context. Original full-source and declaration
authority references remain intact. A controlled cell must carry its original
StateView and complete owner assets to support the contrast. Bind all projected
subjects and governing identities exactly; missing cells
stay incomparable, duplicate or wrong-subject cells fail, and no cell implies a
physical cause or authenticated approval. The pure compare_merge API labels base
and each parent independently, without choosing a causal parent.

AUTHORITY, RATCHET, MIGRATE, OVERLAY and UPGRADE must consume the same versioned
TransitionAnalysis, completeness records and Finding Model retirement observations.
They must rerun state_transitions, transitions, query, schema and source-ownership
integration gates if these interfaces change. This capability implements no agent
admission, migration/upgrade workflow or deployment rollback policy.

### [`portable_command.rs`](../_code/portable_command.rs)

Thin `bundle export`, `bundle verify` and `sarif` adapters. Export requires an explicit new destination and predicate URI. Verification streams the embedded independent standard-library Python consumer to an isolated interpreter; it never imports or executes candidate project code. Human and JSON output render the same verification record, including uncertainty, unavailable dependencies and errors.

### [`sarif.rs`](../_code/sarif.rs)

SARIF 2.1.0 maps supported violations to fail, scoped absence to pass, uncertainty to open, nonapplicability to notApplicable and authorization-only records to informational. A normalized FAIL finding justifies warning as the existence of a problem; no serious/minor severity or blocking eligibility is inferred from integrity tiers. Native identities, raw findings, claim scope, governance, provenance and original coordinates remain properties. Ordered observed call paths use codeFlows. Baselines and exceptions do not erase raw contradictions or become SARIF permission. Empty results never mean all claims passed. Microsoft SARIF Viewer 3.4.5 maps open to warning and pass/nonapplicability/informational to note; the versioned loss report discloses that presentation cannot enforce Fortress assurance or freshness.

### [`authority_command.rs`](../_code/authority_command.rs)

Read-only protected-authority composition and explanation; repository assertions cannot supply a trusted validator.

### [`finding_command.rs`](../_code/finding_command.rs)

Thin read-only baseline capture/create/review/prune and exception list/review/create/retire adapters with strict selectors, explicit assessment time, matching human/JSON projections and structured errors; no proposal is automatically applied.

### [`flow_command.rs`](../_code/flow_command.rs)

Implements flow-author as explicit immutable source preparation followed by the shared RPC v3 flow_author facade. Schema-only guidance performs no analysis. JSON and human output render the same response, and proposals never write policy. Information-flow analysis also supports the shared field-preserving human renderer.

### [`behavior_command.rs`](../_code/behavior_command.rs)

Implements behavior-author with schema-only guidance or explicit source preparation followed by the shared protocol v4 behavior_author query. Repeated --checkpoint ID=NAME bindings and --return ID construct an unapplied exact-context proposal. Human and JSON render the same immutable response. Nothing writes or accepts behavioral authority.

### [`migration_command.rs`](../_code/migration_command.rs)

Explicit migrate preview/inspect/apply/recover dispatch using the same machine-readable contracts. JSON approval assertions cannot instantiate external grant validation; protected application requires the trusted embedding port.

### [`onboarding_command.rs`](../_code/onboarding_command.rs)

Adapts default native or explicitly selected canonical discovery, request authoring, immutable inspection, exact finding review, application and recovery. Inputs are bounded and link-safe. Discovery output is external and create-only or byte-identical; writes to a project occur exclusively through Migration Governance. No serialized grant or execution validator is installed.

**Reviewed repository adoption**

Existing repositories use native/logical governance by default. Discovery observes source, Cargo package boundaries, tests, supported semantic coverage, existing contracts and active governance; package boundaries are suggestions for review, not inferred responsibilities or permission. It executes no project build scripts. Module contracts remain application-owned beside their declared locations; metadata lives only in the registered control namespace. Native application preserves all original source and Cargo bytes and does not create canonical `_data` or `_info` directories.

```text
fortress init <repository> --project-id PF-MY-PROJECT --display-name "My Project" --output <external-review.json>
fortress init inspect <repository> --proposal <external-review.json> --format human
fortress init inspect <repository> --proposal <external-review.json> --module <readable-selector-or-stable-ID>
fortress init review <repository> --proposal <external-review.json> --finding <explicit-finding-ID> --output <external-reviewed-residue.json>
fortress init apply <repository> --proposal <external-reviewed-residue.json>
fortress status <repository> --format json
fortress doctor <repository> --format json
```

Review selects only the named eligible findings from the proposal's exact evaluated target. No `--finding` arguments means an explicit empty selection. No option silently absorbs every finding. The original unbaselined assessment remains in the immutable reviewed proposal, and raw violations remain visible independently from enforcement. Findings that lack stable eligible identities cannot enter the baseline. Application rechecks the complete reviewed source and prediction before MIGRATE writes anything. Unsupported or unavailable semantics remain uncertain; a clean enforcement disposition is not comprehensive semantic conformance.

`--request <external-request.json>` supplies typed explicit choices instead of inline identity flags. Minimal native authoring is `{"schema_version":1,"project_id":"PF-MY-PROJECT","display_name":"My Project"}`. Optional governance and assurance selections use installed readable profile IDs, resolved to exact references by the registry. Explicit logical Module choices declare stable identity, display name, application-owned contract path, parent identity and existing file/directory selectors. Duplicate ownership, identity or readable selectors require resolution; ambiguous matches never choose the first candidate. Exact authored contracts and configuration may be supplied as authority files; observed dependencies never become generated ALLOW declarations.

Strict adoption uses `--mode canonical` and all current canonical filing, direct lowercase snake_case child Modules, reserved Elements and documentation requirements. It creates only required missing documents, preserves existing files, and offers explicit exact-preimage source operations through the request when relocation or documentation replacement is needed. Remaining structural violations block readiness; a baseline cannot waive mandatory canonical structure. Conflicting, partial, dual or case-colliding governance requires an explicit repair proposal and the original trusted authorization boundary. The CLI contains no production grant validator and cannot turn an unsigned reference into permission.

```text
fortress init <repository> --project-id PF-MY-PROJECT --display-name "My Project" --mode canonical --output <external-canonical-review.json>
fortress init recover <repository> --proposal <external-review.json> --transaction <retained-transaction-reference> --recovery rollback
fortress init recover <repository> --proposal <external-review.json> --transaction <retained-transaction-reference> --recovery resume
fortress serve <repository> --stdio --proposal <external-review.json>
```

The existing protocol v5 candidate method pages the explicitly loaded embedded hypothetical assessment; formatting or querying never starts onboarding analysis. Discovery and inspect output paths must be external, link-safe, new or byte-identical. Applied reviews are retained under the registered `__fortress/proposals/onboarding/` family and verified migration receipts under `__fortress/records/migrations/`; neither becomes active authority or current execution evidence. Active journals, staging and rollback material stay in lifecycle-managed external OPS storage. Recovery preserves independently changed bytes and reports conflict rather than overwriting them. A successful resume independently reobserves and reconciles the actual target, retains the reviewed proposal, and still establishes no runtime certification. Completed rollback explicitly verifies original bytes.

Historical v1 bootstrap records retain their reader and explicit `init --legacy` adapter. Its old baseline shortcut accepts only an empty finding set; nonempty residue requires the current exact reviewed interface. This safety restriction never silently widens a baseline.

**Downstream adoption interfaces**

Admission and host integrations must preserve the exact base, context, candidate, original authority and reviewed intent identities and supply only independently validated scoped authorization through the existing trusted port. Upgrade tooling consumes the same migration plan, journal and recovery owner; it must not add another writer. Distribution tooling preserves public schemas and retained historical comparison projections without claiming authentication of unsigned records. Pilot studies consume the frozen pinned-repository protocol and distinguishes mechanical qualification from independent human adoption and original-policy reproduction. All consumers must preserve raw truth, enforcement, assurance and actual execution independently. These are integration contracts, not implementations of those capabilities.

The current shared physical SourceView and migration boundary admits bounded regular-file content: 32 MiB of complete physical source, 50,000 files and 1,024 operations. Arbitrary symbolic-link/reparse source entries are not followed or silently repaired; unsupported physical inventory is an explicit refusal. Git worktree metadata remains excluded and actual worktrees are qualified separately. The native CLI uses one joined review worker with an 8 MiB stack; these are resource-admission limits, not latency certification criteria. Canonical source relocation and first baseline admission use separate reviewed steps so newly changed implementation cannot silently become accepted historical residue.
