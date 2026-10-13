# Code

## Role

Realize the Module responsibility through directly owned provider-independent implementation.

## Execution

Callers invoke the public typed boundary; the Code validates inputs, performs its deterministic processing sequence, and returns a complete result or typed failure.

## State

Ordinary execution owns process-local analysis. An explicit resident coordinator additionally owns a leased runtime workspace, a dedicated parser/cache worker and immutable generation handles. Reader pins retain their resource permits independently; operational registry/journal state remains external to watched source and canonical semantic identities.

## Failure Semantics

Invalid inputs and inability to fulfill the responsibility return explicit typed errors or canonical findings at the owning boundary.

## Files

### [`bootstrap.rs`](../_code/bootstrap.rs)

Performs read-only repository discovery, compiles exact-source-bound reviewed authority proposals from explicit owner choices, and transactionally applies only canonical minimal governance with optional one-time delegation to finding-baseline authority.

### [`audit.rs`](../_code/audit.rs)

Orchestrates declaration loading, stabilized snapshot construction, shared CCG, Intended BFG, implementation observation, PSM, semantic-domain, state/effect, Module semantic-conformance, information-flow, environmental, Behavioral Realization, and Reference Resolution analysis, rule execution, and deterministic audit v5 rendering that leads with raw conformance, progressive enforcement where applicable, foundational authority state, and explicit unavailable-evaluation reasons while keeping normative findings, non-normative architecture diagnostics, and unsupported analysis distinct.

### [`contract.rs`](../_code/contract.rs)

Projects CCG compilation, supported logical coherency, and README synchronization into canonical CONTRACT-COHERENCY-001 findings.

### [`control_migration.py`](../_code/control_migration.py)

Performs the narrow one-time move of registered active authority and archives exact legacy output bytes as an unselected historical generation while refusing dual, partial, or conflicting state.

### [`documentation.rs`](../_code/documentation.rs)

Parses canonical Markdown structurally and reconciles Module contracts, catalogs, child decomposition, and links.

### [`evaluation.rs`](../_code/evaluation.rs)

Dispatches only implemented applicable rules, including behavioral, program-domain/state/effect/information/environment, and REPO-REFERENCE-001 evaluators from shared results; consumes resolved profile applicability before dispatch; and distinguishes evaluated pass or failure, explicit profile-driven non-applicability, and unsupported capability.

### [`execution_storage.py`](../_code/execution_storage.py)

Owns machine-local heavy-job leases, disk and projection preflight, retained bounded compiler targets, per-run staging, lifecycle and publication-recovery journals, and conservative orphan cleanup for certificate issuance and materialization. Python and Rust adapters use separate ownership namespaces. Its paths and process data are operational records outside semantic identity.

Each budget sample walks the current directory entries with one explicit non-following path metadata read per entry. Windows enumeration metadata alone can contain stale hardlink sizes; an explicit stat observes current contents. No byte total survives between samples, and hardlink paths remain charged separately. Directory metadata is checked again before descent; symbolic links and Windows reparse points, including the root, are refused. Disappearing compiler objects and directories are tolerated so the next fresh sample observes their replacement. The scan preserves budget limits, monitoring cadence and error propagation while avoiding repeated path and metadata queries.

### [`identity_migration.rs`](../_code/identity_migration.rs)

Plans exact-snapshot legacy Rust symbol and semantic-finding reference migrations, rejects ambiguous or missing mappings, and applies only explicitly reviewed dependency-bound authority rewrites with rollback on write failure.

### [`ownership.rs`](../_code/ownership.rs)

Reconciles observed governed files with exact declared architectural ownership.

### [`placement.rs`](../_code/placement.rs)

Projects the canonical Project Model filing analysis into REPO-MODULE-001 findings covering recursive Modules, closed Elements, Code flatness/mechanical exceptions, bounded Data/Info structure, companion docs, and path naming.

### [`quality_certificate.py`](../_code/quality_certificate.py)

Certification operations use the pinned `1.97.1` toolchain, `_data/cargo_config.toml`, `_info/Cargo.lock` and the complete `fortress-complete-local-v1` profile. Run `python engine/snapshot_governance/_code/quality_certificate.py issue .` after freezing the final candidate, then `verify .` for that same candidate. Hosted qualification checks the exact pushed revision's filing architecture and local certificate. A source, executable, toolchain, configuration, Standard, authority or dependency change invalidates any measurement or evidence whose complete binding included that input. Earlier generations remain evidence for their recorded subjects.

The issuer's closed set has 28 gates. Fourteen validate BFG, CCG, Certification, Environmental Analysis, Evidence Graph, Information Flow, PSM, Realized BFG, References, Semantic Analysis, Semantic Conformance, Source Artifacts, State/Effect Analysis and Verified BFG against their registered artifact requirements. The other fourteen are `AUDIT_JSON_DETERMINISM`, `CLIPPY`, `DERIVED_ARTIFACT_STORAGE`, `EXECUTION_STORAGE`, `FORMAT`, `FULL_PROFILE_CERTIFICATION`, `PROJECT_FILING_SYSTEM`, `RUSTDOC`, `SCHEMA_AND_STANDARD`, `SCHEMA_ARTIFACTS`, `SELF_AUDIT`, `SELF_MODEL`, `SOURCE_ARCHITECTURE` and `WORKSPACE_TESTS`. Formatting and linting cover the workspace; full suite execution includes all targets and features. The single exact-snapshot certification stack consumes actual suite evidence and provides all required products. Fast development checks and benchmark comparisons cannot satisfy these gates or manufacture current suite evidence.

Before starting a registered performance campaign, run both Python storage controls, workspace format checking and strict all-target/all-feature Clippy, then the unfiltered `behavioral_flow`, `control_plane`, filing/documentation/schema and source-architecture targets plus the changed owners' preparation and recovery targets. `behavioral_flow` exercises the selected historical generation against the independently compiled current BFG, so a stale layout, corrupt member or current-source mismatch is diagnosed before the long benchmark. These are development prerequisites: stop on a failure, repair it and freeze the resulting inputs before measurement. Run the representative `--development-probe` when runtime reuse or fallback changes; it must observe successful reuse and required fallback. Neither these checks nor a completed campaign for an earlier source can replace the final candidate's registered 300 comparisons/restorations, separate 1,000-case differential corpus and companion/smoke controls, all 28 canonical gates, exact-byte certificate verification and exact-head hosted qualification.

Issuance obtains the real CLI executable from the successful pinned Cargo build's artifact report, rejects missing, ambiguous or out-of-target artifacts, and stages an exclusive exact-byte copy with its executable permissions in the owned run. This frees the same leased compiler target for the complete unfiltered suite while the staged process runs. It caches no test result, suite evidence or semantic oracle. Compiler reuse remains subject to Cargo's complete compilation fingerprints and the issuer's exact input bracket. The staged executable is budgeted and removed through normal run cleanup; direct CLI invocation inside a compiler target retains its separate suite target.

Each started issuer command emits wall duration, issuer-process CPU and exit state in an operational timing record, including failed commands. Issuer CPU excludes children and descendants; an external owned-job measurement supplies whole-tree CPU and committed-memory peaks. These records stay outside semantic projections and PASS claims. Capture builds, test execution, analysis, documentation and schema/evidence commands separately, and include the surrounding setup, validation, publication, verification and cleanup in total certification cost.

When a captured command fails, the issuer emits its full captured stdout byte count and digest plus at most four MiB of raw tail bytes to stderr. A shortened preview is explicitly marked truncated and carries no qualification claim. The original gate failure remains an error even if diagnostic emission fails. Successful captured output remains byte-for-byte unchanged. Retain the enclosing owned-job logs to preserve the assertion and completed output that fit this bound.

Measure total certification from setup through build, every gate, registered empirical campaigns, restoration, artifact/schema processing, publication, verification and bounded cleanup. Report these costs separately from producer phase times, process CPU and sampled RSS. Conservative allocation charges, process RSS and Windows job commit peaks describe different quantities. Include source and executable digests, toolchain/dependency/configuration bindings, reference hardware, scheduling conditions, raw report digests and incomplete runs. An inner-loop speedup alone does not demonstrate an end-to-end improvement. The design target is approximately one hour on the documented reference machine; correctness and the complete acceptance contract take precedence.

Phase telemetry reads the current process through the pinned safe APIs of [`cpu-time`](https://docs.rs/cpu-time/1.0.0/cpu_time/struct.ProcessTime.html) and [`memory-stats`](https://docs.rs/memory-stats/1.2.0/memory_stats/). It avoids enumerating every running process at each phase. Whole-process CPU includes concurrent threads and excludes children; a counter failure is disclosed as absent. Memory samples are endpoints, not phase peaks or heap-allocation counts. Windows reports working set and pagefile usage; Unix reports RSS and virtual address size, with approximate fast `/proc/self/statm` sampling on Linux. Collector wall time is recorded separately and excluded from producer phase time; total campaign time includes it. Counters never enter canonical projections, semantic digests or reuse proofs.

Session records dependency-index construction and coverage validation, completed-generation accounting, invalidation and generation assembly after the owner phases. These records expose work between owner production and the public API return. They remain operational diagnostics; full API and total campaign timing also include capture, publication and harness work outside these phase boundaries.

Executes the complete pinned local quality-gate profile under the leased storage supervisor, consumes one exact-snapshot certification stack, validates every emitted artifact against its advertised registered schema, checks the shared Project Model artifact registry, stages generation members with durable preimages, and publishes the selection index last. Reading and updating share one closed selection-index validator: all context keys and generation digests must be canonical, keys must be strictly increasing, and unrelated contexts remain preserved. It reconstructs bounded subject-addressed projections, cleans only idle Python-owned subject cache entries, distinguishes missing, stale, invalid, and current local bytes, and verifies PASS, source freshness, evidence digests, and the tamper stamp while retaining UNVERIFIED issuer authenticity. Generator determinism remains proved by governed tests.

### [`runtime_storage.rs`](../_code/runtime_storage.rs)

Provides the installed Rust runtime with the same machine-local resource-policy, lease, journal, staging, publication-intent, and conservative recovery boundary as the Python pre-build supervisor.

An explicit exact-journal reconciliation port can record an interrupted validating or published run as failed while retaining markerless empty directories. It requires both existing leases, a reviewed journal digest, stable ordinary directory identities and exactly empty residue. An immutable bounded record preserves original bytes and publication intent before the failed/released journal postimage is committed. It removes no resources, creates no historical ownership markers or admission registration, and makes no claim that the interrupted publication or process cleanup completed. Normal acquisition and marked-resource cleanup remain separate operations.

### [`rust_test_analyzer.rs`](../_code/rust_test_analyzer.rs)

Uses structured Rust syntax parsing to emit deterministic snapshot-bound behavioral test facts.

### [`snapshot.rs`](../_code/snapshot.rs)

Builds two-pass stabilized content-addressed repository snapshots and rejects mutation between observations.

### [`traceability.rs`](../_code/traceability.rs)

Projects CCG requirement/test identity findings and deterministic coverage counts without rebuilding verification topology.

### [`testing_boundary.rs`](../_code/testing_boundary.rs)

Projects CCG recursive Testing-child, exact parent Feature subject, role, and Rust evidence-placement findings.

### [`heavy_admission.rs`](../_code/heavy_admission.rs)

Identifies repositories through canonical/native physical directory handles and provides cross-adapter heavy-execution exclusion using a fixed external native registry. Windows uses the native SystemRoot Temp directory and Unix uses `/tmp`; `TEMP`, `TMP` and `TMPDIR` never select it. Linked or reparse registry components are rejected. Quiescent migration holds both native locks and preserves historical target/journal references and old records; adapter ownership namespaces remain separate.

### [`heavy_admission.py`](../_code/heavy_admission.py)

Implements the Python adapter of the same native physical-directory admission registry and locking protocol, allowing issuance and Rust runtime evaluation to exclude competing heavy owners without placing operational state inside watched source or semantic identity.

### [`resident_worker.rs`](../_code/resident_worker.rs)

Owns the dedicated parser/cache worker and its thread lifetime. Syntax and reusable preparations remain thread-private; only completed owned models cross to the coordinator. Neutral retained-input preflight is invoked before tokenization in each participating frontend, records actual request/retained input counters and sticky epoch exhaustion, and preserves charges until thread join. An exhausted retained epoch is joined before a fresh cold retry. Candidate preparation is isolated and promoted only by the appropriate accepted lifecycle. The conservative parser allocation permit is 64 times the input-admission limit, not a hard RSS guarantee.

Successful cold-program requests retain at most eight exact SourceView digest and parser-admission demand pairs within the fixed worker executable, root, suite and limits. A request may reuse domain or effect preparation while completely rebuilding the program; its successful measured parser demand is still eligible. No partial prepared-program request trains a demand. When a matching request needs cold program preparation and its known demand cannot fit the existing epoch, the worker joins that epoch before executing the full cold producer. This operational hint returns no semantic results, raises no admission limit and trains only after success. Prepared program requests and unseen identities retain actual admission and exhaustion/retry behavior. Rotation reports the precise preflight reason and preserves actual tokenization counters; no discarded work is invented. A separate 4 KiB conservative metadata charge covers the bounded hints and remains reserved with the worker until join.

Retention admits independent complete owner preparations within the existing aggregate byte and unit limits. When a limit is exceeded, it drops the largest owner allocation by the limiting dimension until the remainder fits, preserving each retained owner's full conservative charge and proof checks. A missing owner receives no preparation and reconstructs through its full producer; the request remains explicitly `FullReevaluationRequired` even when another owner safely reuses work. Before-eviction diagnostics disclose all produced charges. Explicit eviction, parser-epoch rotation and cold evaluation still remove or ignore every owner, so partial retention cannot cache away an independent cold oracle.

### [`session.rs`](../_code/session.rs)

Exposes open, exact refresh, current immutable acquisition, isolated candidate evaluation, cancellation, preparation eviction and close through the production evaluator. Actual refresh performs full input and control-availability revalidation before atomic immutable-head publication; watcher paths are hints. Candidate changes use exact preimages, cannot expose previously excluded undiscovered files, perform no physical writes and never publish as actual state. Reader handles retain generation charges across refresh, close and reopening. Source, inventory, semantic cardinality, generation/candidate, preparation and parser limits are operational. Source and history discovery bound total entries and aggregate relative-path bytes before queue retention; history directories must belong to the registered control grammar. The availability path quota is a checked `max_entries * 512`, with overflow and exhausted admission returning typed resource failures. Capture reserves relative-path copies separately from inventory metadata and native root prefixes; finished generations retain an additional charge for availability metadata. Defaults include a 64 MiB parser epoch and 16 GiB conservative session accounting; parser epochs have a one GiB hard admission ceiling. `evict_preparation` reports typed failure and worker join is the parser-lifetime release boundary. Canonical semantic artifacts exclude runtime paths and counters.

Source Architecture binds the exact immutable PSM through its canonical digest API. Its per-instance memo contains the SHA-256 of the same two-space UTF-8 JSON plus LF, so the composition layer does not serialize the full model again solely to compute that digest. This reuses no model or digest across different instances or source identities.

The shared `audit.rs` preparation seam captures one exact immutable source view, verifies third-read byte sizes and digests against stabilized observations, loads Project and Standard authority from those same bytes, and assembles snapshots and documentation without candidate filesystem reads. The private `read_observed_file` boundary performs one bounded filesystem document read and verifies its observed size and digest; the authored environment operation binds this per-document result. Cold and resident evaluation use the same full production stack. Eleven semantic projections are always produced; the three certification products are produced only when a caller supplies actual unchanged `RustSuiteExecution` evidence. Its freshness and pass state are preserved, including stale evidence; absence never creates a fake suite or certificate.
