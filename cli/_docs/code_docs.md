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

### [`go_body_command.rs`](../_code/go_body_command.rs)

Selects an independently pinned, external bodied Go collector under a separate
registration identity and mode. Reuses the bounded verifier process, original
repository observation and registration readback. Structured body results go
to stdout without modifying project source.

Add `--flow EXACT_OCCURRENCE` to the existing Go scalar body invocation to
inspect one lowered body. Copy the exact `binding` from its original receipt.
A changed source or producer can make the occurrence unavailable. The report
retains both the original body receipt and the scoped flow disposition.

### [`go_fs_command.rs`](../_code/go_fs_command.rs)

Uses an external registration and the existing bounded local subprocess to relate
one ordinary Go file's exact statically resolved call sites to the installed
Operation Summary catalog. Source and the registration are checked before
publication. The command only reports the selected context and scoped effects.

```text
fortress psm --observe-go-filesystem PROJECT HOST_REGISTRATION DIRECTORY PACKAGE_PATH go1.22 linux amd64
```

Select the matching platform and locally reviewed worker prepared with
`INSTALLED_STDLIB_GC_NO_CGO_V1` and pinned Windows Go 1.22.12 or Linux
Go 1.22.2. A qualified static `os.WriteFile` call can expose a conditional
filesystem write effect at the source location. Control-flow reachability,
runtime execution, complete effect bounds, and missing or indirect effects
remain unresolved. The command issues no canonical finding or certificate.

### [`go_observation_command.rs`](../_code/go_observation_command.rs)

Select the original Go module and target context using the existing module
inspection arguments. Append `--authored-return FUNCTION BODY_REGISTRATION`
to compare a zero-argument Boolean callable with its original requirement.
Supply both registrations outside the repository with independent executable
and runtime pins. Keep the authored document in its declared logical Module
data directory outside the selected closed Go module prefix. The runtime
produces a bounded static comparison with independently reported body and
declaration provenance.


Runs the explicitly selected, digest-pinned Go collector with the shared bounded subprocess supervisor. Returns the independent native observation projection after source and authority revalidation.

For declaration-only test inspection, build the reviewed helper from
`collector.go`, `collector_build_context.go` and `go_test_observer.go` and place its executable
and [test registration](../_data/go_test_registration_v1.json) outside the observed repository.
The registration pins Go 1.22.12 on Windows x64 or Go 1.22.2 on Linux x64 and
uses `REQUIRE_SEPARATE_TEST_CONTEXT` with an explicit target and tag selection.

```text
fortress psm --observe-go-tests PROJECT HOST_REGISTRATION DIRECTORY PACKAGE_PATH go1.22 linux amd64
```

The observer sees one closed directory without ancestor module or workspace
inputs. It reports direct standard test signatures, `TestMain` hooks and
unsupported or invalid shapes. Package compilation, runner eligibility,
benchmark and fuzz declarations, examples, subtests, third-party frameworks,
coverage and verification remain outside this observation.

**Explicit Go compiler observations**

An independently pinned scalar-body collector can also observe a bounded Go
body without project code execution. Its registration uses
`urn:fortress:host:v1:go-body-registration` with the existing version,
executable path, executable SHA-256 and toolchain fields. Build the collector
outside the observed project with the reviewed Go compiler and the two exact
files documented by [Program Semantics](../../engine/program_semantics/README.md),
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

**Explicit Go build selection**

For filename and build-constraint selection, use the separately reviewed helper
built from collector.go and collector_build_context.go. Register the combined
executable outside the repository with its own exact digest and toolchain. The
registration uses urn:fortress:host:v2:go-build-collector-registration and
schema_version 2. It also requires the exact build_context defined by the
[registration schema](../_data/go_collector_schema_v2.json).

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

**Closed Go module observations**

Use the separate v3 [host registration](../_data/go_collector_schema_v3.json) with the worker built from all three Go collector sources. The registration and executable live outside the observed repository. The qualified host runs Go 1.22.12 on Windows x64 or Go 1.22.2 on Linux x64.

~~~text
fortress psm --observe-go-module PROJECT HOST_REGISTRATION . example.test/module example.test/module/app linux amd64
~~~

The module directory is relative to the project. A dot selects the project root. The selected module path must match the captured go.mod bytes. The supported module file declares only a module and Go 1.22. Its source consists of ordinary Go library packages with explicit target selection. Dependency resolution is confined to captured directories in that module. Module and workspace indirection, vendoring, external dependencies, cgo, generated or non-Go compiler input and ambiguous module roots are outside the supported scope. The command invokes no project tools.

Optionally append four arguments giving the left package, left type name, right package and right type name. Both declarations must be in the reachable package graph. The receipt distinguishes lexical imports, static declaration associations and unresolved dispatch. It carries exact actual-source, governing authority, build context and worker identities, separately from PSM analysis and certification.

**Inspect original Go Module dependencies**

Use the existing pinned Go v3 collector with the trailing `--dependencies`
option:

```text
fortress psm --observe-go-module PROJECT HOST_REGISTRATION . example.org/component example.org/component/api linux amd64 --dependencies
```

The report embeds the original native receipt and relates each admitted import
to the exact selected files of its target package. Where the original governing
configuration supplies unambiguous owners for both ends, the report shows a
directed source relationship between those Modules. Ownership diagnostics and
unresolved or unavailable native inputs remain visible. A source relationship
provides observational evidence for review. Runtime behavior, authorization,
and assessment have separate inputs.

### [`layout_command.rs`](../_code/layout_command.rs)

Reads explicit digest-pinned native profile selections and supplies bounded repository observations to the Project Model projection.

### [`provider_collection.rs`](../_code/provider_collection.rs)

Validates external host registration, invokes one owned bounded collector at a time and prepares the existing evidence envelope without admission or project mutation.

### [`package_install.py`](../_code/package_install.py)

Verifies portable development archives against independently supplied manifest digests. Installs exact inventories into immutable application slots and removes only verified owned files. The installer does not write project authority or execute the package contents.

The optional native Go distribution attachment uses the established v1 package manifest's bounded build metadata. The installer cross-checks recognized worker and notice identities against the exact file inventory, verifies each native executable header, and sets executable permissions only on admitted application members. Body and test commands select separate exact external registrations and staged executables. Installation does not create a registration.

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

`baseline admission` takes explicit immutable operations and optional original history. With a review it previews the exact governed postimage and, with an explicit base selection, the shared migration plan. The installed CLI supplies no production grant or trusted history attestation. `explain --proposal` and the same stdio query project loaded proposals or the registered current admission records without running an analyzer.

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

Offline verification uses `FORTRESS_VERIFIER_PYTHON` when explicitly configured in the trusted host environment; it must name an absolute installed interpreter outside both input trees. Otherwise only absolute host PATH directories are searched, without shell execution or candidate-local executables. Python runs with `-I -B` and the installed consumer on stdin. Each output pipe is limited to 1 MiB and the invocation to 180 seconds. These are operational safety budgets, not responsiveness certification thresholds. This adapter does not sandbox an untrusted interpreter or supervise arbitrary descendant trees; its reviewed consumer never spawns them.

### [`diagnostics.rs`](../_code/diagnostics.rs)

Streams CLI diagnostics through bounded UTF-8 admission and escapes terminal, carriage-return and direction controls, including when a multibyte character spans writes. Machine-readable stdout is untouched. The adapter preserves trusted line framing and escapes incomplete/invalid diagnostic bytes rather than executing them as terminal controls.

### [`projection_command.rs`](../_code/projection_command.rs)

`fortress projections [path] --output-dir new-external-directory --format json` explicitly constructs one complete canonical static stack. The destination parent must exist and be ordinary; the final directory must be new and outside source. Existing paths, traversal, unsafe ancestors and observable directory or member replacement are refused. Retained native handles validate completed files, and `manifest.json` is written last. Interrupted output is incomplete and may be discarded only by its established owner. The operation is not a transaction over repository authority and does not claim protection against an actively hostile operating system or filesystem-wide atomicity.

The versioned diagnostic manifest identifies the certification-source domain, exact member hashes and sizes, completion and separate producer costs. `STATIC_PROJECTIONS_ONLY`, `NOT_RUN`, `NOT_ISSUED` and `UNVERIFIED` distinguish materialization from execution, certification and authenticity. The command never runs Cargo, build scripts or repository providers. Human rendering and JSON serialize the same result; machine errors remain explicit. Issuance prints separate unfiltered-suite and producer-phase diagnostics on stderr while leaving canonical stdout and certificate products unchanged.

### [`upgrade_command.rs`](../_code/upgrade_command.rs)

Read-only adapter for version capability discovery, current edition inspection and exact preview. Pass the existing reviewed migration plan to a trusted host for independent validation. The CLI accepts no approval certificate or serialized grant.

**Upgrade a governed project**

Run `fortress upgrade inspect --root PROJECT --format json` to read the exact Standard pin, physical source, canonical state and original authority. Run `fortress upgrade compatibility --from SCHEMA --to SCHEMA` to see the two exact registered capabilities. An installed runtime reader can inspect its own declared shape. Separate readable editions may be incomparable. An unregistered shape, absent reader or undeclared reverse conversion is unsupported.

| Original | Proposed | Supported workflow |
| --- | --- | --- |
| Configuration v2 or v3 at the registered control role | Configuration v4 with original native selection | Generate an exact replacement with `upgrade preview`. It preserves logical bindings and exclusions and makes the existing native default explicit. |
| Qualified draft Standard pin | Distinct draft edition with identical rule documents | Supply explicit exact operations for the manifest and the authored root contract's edition pin. The installed evaluator continues to bind the same rule documents. |
| Exact current profile selections | Another installed, resolver-compatible selection | Supply an explicit configuration replacement. Review the original and target claims, evidence and assessment. |
| A Standard with changed rule documents | Another pinned edition | Compare exact rule bytes and governing relationships. A writer plan is withheld when the installed evaluator cannot establish the new rule meaning. |
| Legacy Rust symbols or pre-anchor finding references | Exact owner-confirmed current identities | Use the existing `identity-migrate` preview and its owner-produced migration plan. Ambiguous or anchored historical references stay original. |
| Historical registered CONTROL layout and locator inputs | Current installed layout | Inspect through the original reader where supported. Retained generations are never rewritten or selected as evidence of a new state. |

Prepare an editions JSON object with `from_bundle` and `to_bundle`, each containing the exact `standard_id`, `edition` and `release_digest` returned by discovery or independently bound to the qualified offline documents. To convert only the configuration shape, use the same edition pin on both sides and omit `--operations`. For an existing-owner identity or contract schema preview, supply --transform identity and leave out the operations file. To preview reviewed edits, supply existing MigrationOperation JSON through `--operations`. Give `--base-selection` the existing original-policy preview format used by `migrate preview`. A preview policy file cannot confer authorization. Set `preview_admission` to `true` in the editions selection to explicitly evaluate the same operations for eligibility under the existing admission model. Mixed changes and previously governed findings retain their respective limitations.

```sh
fortress upgrade inspect --root ./project --format json
fortress upgrade compatibility --from urn:fortress:schema:v3:project-configuration --to urn:fortress:schema:v4:project-configuration
fortress upgrade preview --root ./project --editions editions.json --base-selection original-policy.json --format json
```

Review the proposal's exact operations, historical declaration, four comparison axes, independent profile assessments and authorization requirements. A scoped trusted embedding passes the exact proposed plan to `TrustedMediator` for independent, one-use authorization and MIGRATE application. Use the existing recovery transaction ref after an interruption. Verify the resulting receipt and observe the resulting repository separately. Run new certification for the target source and authority when current assurance is required. Historical evidence remains available under its original immutable generation. There is no stable Standard publication or profile default change in this workflow.

The reproducible `native_edition_upgrade_reuses_review_and_preserves_original_source` integration test demonstrates permission refusal followed by an exact independently reviewed write through the controlled host boundary.

### [`python_observe_command.rs`](../_code/python_observe_command.rs)

The explicit Python mode accepts host-owned registration and worker files outside the candidate repository. Independently select the installed CPython image and its protected runtime-library dependencies. Run the same reviewed worker with the selected interpreter's `-I -S -B --describe-runtime` entry to inspect the runtime descriptor before trusting it. The invocation is `PYTHON -I -S -B WORKER --describe-runtime`. The runtime reference is the SHA-256 of the canonical descriptor without its terminal newline. File digests use the original bytes. The trusted registration fields are recorded in [CLI data documentation](data_docs.md).

The one-process exchange releases exact source only after the bounded worker emits the expected readiness frame. Linux checks 96 MiB address-space and one second CPU limits. Windows verifies a 96 MiB nested Job commit limit and one active process, with the parent's five-second wall deadline. Hard Windows CPU enforcement remains unavailable in the tested nested configuration. Dependency custody stays with the independently selected host. The worker does not evaluate, import or build the project.

Use the same external lexical registration for explicit test declaration
inspection. Roots are repository-relative directories, or `.` for the whole
repository. The declared default naming profile uses `test_*.py` and
`*_test.py` filenames and the `test` function prefix. Each selected file
uses the existing five-second compile-only exchange. The command never starts
pytest or imports project source. Configuration and hook markers remain
uninterpreted, and importability, dynamic or class-based collection,
execution and coverage stay unestablished. The default naming behavior
was checked on Windows with pytest 9.0.1 and on Linux with pytest 7.4.4.

```text
fortress source-artifacts --observe-python-tests PROJECT HOST_REGISTRATION tests
```

Readiness failure and changed tool or source bytes yield explicit unavailable errors. Successful output carries the exact original source and authority, selected grammar, and scoped lexical observations. Runtime import and call targets, effects and execution remain unresolved. This path contributes no current findings, assessment, grant or certificate. Default source-artifact and PSM behavior stays on the existing paths.

The explicit static import mode reuses this same lexical worker and readiness
frame. It checks an independently pinned external ordered root scope before
dispatch, then rechecks the external scope and host assets after the exchange.
Snapshot Governance supplies the actual-state result and scoped limitations.

**Explicit Python lexical observations**

Use `fortress source-artifacts --observe-python PROJECT HOST_REGISTRATION SOURCE_PATH lexical` from a trusted host. The selected path is a repository-relative `.py` file. Use `syntax` for the narrower parser-only result. The mode returns a separate machine-readable observation.

Keep the host registration, interpreter and exact reviewed worker outside the project. The supplied registration pins the interpreter executable, selected CPython runtime descriptor and grammar. The worker must match the bytes shipped with Fortress. Review the available runtime context and platform limits before launching. See [Python worker setup](code_docs.md#python_observe_commandrs).

**Static Python import inspection**

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

**Static Python dependency evidence**

Use the same invocation with `dependencies` in place of `imports` to join
unique authored Module ownership to exact Python file origins under the
selected roots. The versioned result embeds the original lexical/import
receipt and retains separate source, observation and ownership identities.
Coordinates are zero-based byte offsets in the captured source, including
UTF-8 and original line endings. A from-import row describes its base
without resolving its named member. Namespace, missing, unowned and
ambiguous endpoints remain visible. The resulting edges express scoped
source evidence. Runtime behavior, dependency absence, enforcement,
assurance and certification are outside this inspection.

### [`python_scalar_command.rs`](../_code/python_scalar_command.rs)

Implements explicit scalar inspection using a separately registered external
CPython interpreter and exact embedded worker and bootstrap bytes. The
compile-only process receives an immutable request after an exact scalar
readiness frame on the existing verifier supervisor. The command rechecks
host inputs, consumes Snapshot Governance's revalidated result, and serializes
a scoped native body or limitation. Inference remains a separate conditional
output bound.

**Explicit Python scalar inspection**

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

For direct data movement in a Python scalar body, add `--flow` to the
explicit scalar invocation. The original scalar receipt remains available in
the returned envelope. Condition inputs are listed separately from the
unsupported control-influence analysis.

For comparison with an original authored Boolean return requirement, run
`fortress source-artifacts --observe-python-scalar PROJECT HOST_REGISTRATION --contract MODULE ROOT_SCOPE ROOT_SCOPE_SHA256`.
Supply the absolute external root-scope file and independently pinned canonical
digest used for [static import scope selection](#python_observe_commandrs).
`MODULE` selects one top-level lexical module. The registration supplies the
function name and pins its exact path and bytes. Use an empty
`exact_bool_parameters` array. Fortress checks the registration against the
original resolved subject before sending any source to the worker.

The displayed requirement comes from the original Module's captured
`native_function_contracts.json`. Missing, conflicting or unsupported
requirements remain explicit. The result reports a compile-only, bounded
comparison and preserves uncertainty about runtime imports, execution and
certification.

### [`native_return_command.rs`](../_code/native_return_command.rs)

Serializes the same typed original native return observation for both language
commands. It retains the exact source and governing authority even if the
subject is unavailable. Each linked comparison preserves its separate native
scope, exact declared owner, original intent, and static return bound.
