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

### [`candidate.rs`](../_code/candidate.rs)

Composes exact immutable hypothetical evaluation, isolated client buffers, original-authority previews, pre-write validation and read-only actual reconciliation. Reuses SESSION, canonical Snapshot evaluation, State Governance, AUTHORITY and MIGRATE operations; never implements source mutation or transaction recovery. See [candidate evaluation](code_docs.md).

**Exact hypothetical evaluation**

Snapshot Governance owns OVERLAY composition. `candidate::CandidateWorkspace` captures the complete bounded physical source inventory before interpreting candidate exclusions. Its immutable base identifies exact repository-relative bytes, canonical context and original governing authority. `CandidateRequest` uses the existing MIGRATE operation vocabulary: exact-preimage replacement, creation, owned deletion and file relocation. The existing operation graph validates portable paths, ownership, overlap, case-fold collisions and simultaneous move permutations. OVERLAY neither lowers a second executable graph nor writes source.

Every finished `HypotheticalEvaluation` is `PROPOSED` with `actual_state: false`. It includes original and predicted canonical comparison states, exact physical inventory references, exact operations, four-axis transition analysis, original-authority authorization requirements or explicit authorization errors, existing-owner validation facts and materialization dependencies. Complete unchanged base bytes and the original evaluator are explicitly required for independent replay; actual execution is explicitly absent. Raw findings, finding-governance disposition, profile assurance and authorization remain independent. Existing owner-produced raw findings and Finding Model NEW/BASELINED/REINTRODUCED lifecycle/disposition accompany the transition deltas. The narrow additive State Governance assess_original_findings interface shares the existing retirement classifier; supported RESOLVED records retain their actual proof dependencies. Source exclusion, lost evaluability, ambiguous identity, changed policy and missing evidence retain the State Governance/RATCHET outcomes; disappearance is never invented remediation. Behavioral consequences and defeaters remain the existing owners' conclusions.

`candidate_digest` is the existing CandidateChangeSet v2 identity over complete base bytes, ordered normalized operations, comparison context, target authority and candidate bytes. `evaluation_ref` identifies the complete semantic assessment except operational evaluation mode and fallback explanations. Client IDs, cache availability, wall-clock times, machine-local paths and generation counters do not change these identities. Explicit export addresses the complete JCS record bytes separately, including its operational provenance. Changing a reported work mode cannot create new semantic support.

**Canonical evaluation and isolation**

`open_cold` performs complete canonical evaluation without storage. `open` optionally uses an existing SESSION workspace and its dependency-qualified owner preparation. Resident generations retain the same canonical comparison projection as complete evaluation. Their source projection must exactly equal the candidate's entire canonically admitted inventory before reuse. Metadata, authority or dependency changes without complete reuse proof yield `FULL_REEVALUATION_REQUIRED`; completed full evaluation still returns ordinary semantic results. An unsupported optimization is an operational fallback, never a fabricated semantic UNKNOWN. Unsupported source semantics retain their actual UNKNOWN/UNSUPPORTED/NOT_EVALUABLE outcomes.

Historical baseline retirement requires the exact immutable original endpoint referenced by its anchor. Attach at most sixteen original states with with_original_states before retaining candidates, or supply explicit --original-state references through the CLI. Only an exact anchor.from_state identity selects history; no favorable alternative is chosen. Current-base counterfactual cells are not transferred into a historical comparison. That comparison may reuse the original owner's existing unchanged-subject cell through MIGRATE's shared helper; otherwise the required historical cell remains unavailable. The original request context remains intact in the proposal. Missing or unavailable original state remains unresolved. Historical authority and assessments are embedded unchanged, bounded to 64 MiB, and never reexecuted under a historical evaluator.

The physical inventory covers excluded ordinary inputs as well as active authority. Canonical analysis still honors the declared source scope. The physical inventory and operation differences are therefore distinct from the four-axis comparator's semantic input projections. Matching excluded bytes does not prove semantic coverage of those bytes. A candidate configuration cannot hide its own physical changes or select a new trusted base policy.

Buffers are isolated by `(client_id, candidate_id)`; retaining an existing key is refused. The initial admission supports sixteen candidates, 128 MiB per public record and 256 MiB retained record bytes, in addition to existing MIGRATE input/operation bounds and SESSION source, dependency, generation, parser and conservative allocation limits. These are resource limits, not latency certification requirements or process-RSS promises. Release buffers explicitly; reader pins retain their own charges. Failed, cancelled and stale work never publishes an actual SESSION head or CONTROL generation. Hosts may use SESSION's existing independent cancellation control while analysis runs.

Complete cold evaluation and resident endpoint assembly run the same canonical adapter in a joined request worker, releasing its thread-local syntax storage before the call returns. SESSION's separately admitted reusable parser worker retains its existing bounded epoch lifecycle. No new parser or semantic evaluation algorithm is introduced.

**Original authority and write boundary**

Pass the existing `CanonicalMigrationAuthority` with independently trusted original policy and the existing external `GrantValidator` port. The union of original and proposed protected roles is evaluated by AUTHORITY. Candidate policies, local approvals, commit/PR strings, unsigned receipts and fixture grants cannot authorize their own relaxation. Assessor changes retain original-policy qualification requirements. Finding maintenance requires the existing RATCHET owner's opaque proof; identity normalization requires its existing owner-produced plan. Authorization errors remain visible beside predicted semantic outcomes.

`authorize_before_write` reobserves complete physical inputs, checks the canonical original endpoint again, and obtains the existing process-local ApplicationAuthorization. It returns a non-deserializable CandidateWritePermit bound to this exact assessment and requirements. This is a pre-write check, **not** a writer lease or permission to bypass MIGRATE. A host must close its own concurrency boundary. MIGRATE remains the single owner of source application, exclusive leases, same-volume staging, write-ahead journals, cancellation/recovery, independent post-write validation and verified receipts. Retained proposals do not reconstruct write permits.

**Post-write reconciliation**

After an independently authorized external writer finishes, `reconcile` independently observes the physical inventory and all authoritative bytes, invokes complete canonical evaluation and compares exact context/authority/results and validation facts. It then rechecks original requirements through AUTHORITY. Independently supplied current execution enters through the trusted ActualExecutionEvidence host port, reusing existing RustSuiteExecution validation and canonical Certification. No implementation reads execution assertions from candidate JSON. Failed, filtered, stale, missing or insufficient execution cannot promote a prediction. Current Certification must PASS, owner validation must be supported, and the final physical observation must remain exact before `VERIFIED_ACTUAL` is returned.

`DIVERGED` invalidates the prediction. `EXACT_MATCH_UNVERIFIED` establishes static agreement while retaining missing authorization or execution. Only `VERIFIED_ACTUAL` has `actual_state: true`; this is a read-only reconciliation observation referencing actual Certification, not a migration receipt or instruction to publish. Actual publication remains behind existing source-bound certification and CONTROL boundaries. Active MIGRATE journals block fresh observation. Subsequent edits invalidate freshness. This capability does not provide filesystem-wide atomicity, hostile-host isolation or externally authenticated producer identity.

`inspect_post_write` can inspect an unsigned retained proposal without reconstructing unavailable original bytes, authority, permits or execution. It can return exact static agreement only. It never produces VERIFIED_ACTUAL.

**Public interfaces and consumers**

The public v1 request, hypothetical-evaluation and candidate-reconciliation schemas live in this Module's Data. The request reuses the existing MIGRATE operations and current State Governance v2 context representation; existing schemas retain their original digests. CONTROL layout/generation v7 adds a registered, nonrecursive hypothetical-proposal family. Explicit proposal export uses the common immutable-record writer, under the role-resolved `proposals/candidates` family. Runtime caches, candidate buffers and staging remain external; neither proposal nor historical reconciliation becomes active authority.

EXPLAIN/RPC v5 adds `candidate` over explicitly loaded immutable results. Every original field is accessible through complete bounded JSON-pointer pages, including countervailing evidence and uncertainty. Preload refuses complete field indexes exceeding the existing 100,000-record/64-MiB query admission; it never silently truncates them. Query formatting performs no source observation or semantic analysis. Protocol versions 1–4 remain supported and reject this new method. The CLI Module TF-CLI-0001 Code documentation provides the corresponding invocation and RPC examples.

Each loaded description also identifies the complete JCS record as record_ref. Query state and cursors bind that exact record, including operational provenance, even when prepared and cold records share one semantic evaluation_ref. A cursor cannot cross records with different cache/fallback descriptions.

ONBOARD and UPGRADE must use MIGRATE for writes and this exact candidate/actual boundary for previews. IDE and HOSTS must isolate client buffers, carry exact base/context/candidate identities, enforce their own interception/authorization boundary and invalidate stale predictions. ADMISSION must retain original authority and historical finding meaning; a favorable proposed assessment is not admission, retirement proof, execution evidence or a certificate. Consumers must rerun exact-byte, original-authority, differential, cancellation, paging and post-write divergence controls when these interfaces change. No subsequent package is implemented here.

**Qualification and diagnostic protocol**

The focused corpus pairs 1,000 immutable prepared and full-cold candidates across literal/control changes, unresolved calls, unsupported configuration, incidental locations, metadata, new declarations, relocations, owned deletion and binary/loop inputs. It compares complete canonical endpoint bytes and semantic assessment identities, retains a bounded external JSONL report, and preserves the physical base. Existing SESSION's broader retained 1,000-case whole-artifact corpus remains mandatory. Adversarial controls separately cover malformed records, conflicting operations, client isolation, stale bases, missing/forged approval mechanisms, absent execution, incompatible protocol versions, complete paging and nonrecursive immutable export. Timing fields are uncontrolled-host diagnostics; there is no numerical speedup or latency pass/fail criterion. Host-port fixtures are simulation evidence, not proof of production authentication or actual fixture execution.

**Lossless comparison projection**

Candidate records use State Governance comparison-projection v1 for base, predicted and historical endpoints. The public projection validates current StateView v3 directly while retaining exact native comparison identities, including historical native v1 frames. Concatenating canonical_native_chunks as UTF-8 reproduces the canonical native input; SHA-256 must equal state_ref. Public view/assets/source/provenance fields must exactly match that input. Native standalone schema conformance is explicitly not asserted: earlier native comparison v1 inputs can contain later owner-validated StateViews not described by their original standalone schema. The new envelope makes that compatibility boundary explicit without changing or rewriting historical records, downgrading v3 meaning or inventing evidence. The existing native owner validates and compares inputs; this projection is a lossless representation, not another evaluator.

For HypotheticalEvaluation v1, evaluation_ref hashes JCS of the complete serialized assessment after removing evaluation_ref, evaluation_mode and fallback_reasons. candidate_digest retains the existing CandidateChangeSet v2 algorithm. A retained proposal filename hashes its entire exact JCS record bytes, including operational provenance. Reconciliation hashes JCS with reconciliation_ref set to the empty string. None of these digests authenticates a producer or grants permission.

**Current wire compatibility**

Current comparison captures use comparison-state v2, explicitly admitting the already supported StateView v3. Authority snapshots and reviewed governance proposals use v2, and migration plans use v2 for current original-authority counterfactual contexts. Readers preserve native v1 input identities and historical plan/receipt meaning; expired reviews and changed exact evaluator/state bindings require deliberate regeneration rather than automatic acceptance. Older standalone comparison v1 schemas remain byte-identical. Their native owner reader historically admitted later StateViews, so lossless projections explicitly distinguish native owner validation from standalone legacy-schema conformance. Current v2 writers are separately checked against the advertised public schema.

The independently usable Python bundle verifier and its byte-identical installed CLI copy admit CONTROL generations through v7 and authority layouts v5–v7. Older supported editions retain their original digests and meaning; unsupported future editions still fail explicitly. This compatibility support establishes neither actual freshness nor producer authentication.

Canonical native chunks greedily use the largest UTF-8 prefix of at most 2,048 bytes ending at a code-point boundary. Chunk order is meaningful, no Unicode normalization is applied, and the public reader rejects alternate chunk partitions or owner projections that differ from the exact native input.

The existing Affected Analysis producer projects declared affected Modules, dependency units and projections from the same finished canonical models. Its report is distinct from actual work reuse: evaluation_mode and fallback_reasons report the operational decision. Ungoverned endpoints without a declared dependency snapshot report affected_analysis as null; no complete Module closure is invented. Architectural, behavioral, coverage and uncertainty conclusions remain the existing canonical endpoint and four-axis comparison facts.

### [`query_candidate.rs`](../_code/query_candidate.rs)

Projects explicitly preloaded PROPOSED results into complete bounded JSON-pointer pages without initiating semantic evaluation or treating predictions as actual evidence.

### [`bootstrap.rs`](../_code/bootstrap.rs)

Retains version-one read-only discovery and minimal application compatibility. The current native/canonical review model is composed by bootstrap_plan.rs through the existing hypothetical evaluator and migration owner. Legacy baseline creation refuses nonempty residue; current admission always requires explicit exact-target selection.

### [`audit.rs`](../_code/audit.rs)

**Declared flow composition**

Audit supplies existing profile scopes and registered global policy to Information Flow. Certification receives owner-produced sink conclusions without evaluating them; EXPLAIN indexes their canonical defeaters and coverage. Query v3 adds flow_author over explicitly preloaded immutable PSM/policy context. The shared human renderer preserves every machine field. No query formatting path initiates semantic analysis or accepts a proposal.

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

The issuer's closed set has 34 gates. Seventeen validate BFG, CCG, Certification, Conformance Declaration, Environmental Analysis, Evidence Graph, Information Flow, Profile Assessment, PSM, Realized BFG, References, Semantic Analysis, Semantic Conformance, Semantic Qualification, Source Artifacts, State/Effect Analysis and Verified BFG against their registered artifact requirements. The other seventeen are `AUDIT_JSON_DETERMINISM`, `CLIPPY`, `DERIVED_ARTIFACT_STORAGE`, `EXECUTION_STORAGE`, `FORMAT`, `FULL_PROFILE_CERTIFICATION`, `PROJECT_FILING_SYSTEM`, `PROVIDER_EVIDENCE`, `RUSTDOC`, `SCHEMA_AND_STANDARD`, `SCHEMA_ARTIFACTS`, `SECURITY_BOUNDARIES`, `SELF_AUDIT`, `SELF_MODEL`, `SEMANTIC_QUALIFICATION`, `SOURCE_ARCHITECTURE` and `WORKSPACE_TESTS`. Formatting and linting cover the workspace; full suite execution includes all targets and features. The single exact-snapshot certification stack consumes actual suite evidence and provides all required products. Fast development checks and benchmark comparisons cannot satisfy these gates or manufacture current suite evidence.

Before recovery or heavy execution, the issuer checks that required gate identities are sorted, unique and cover every installed artifact. Before publication, the issuer and verifier use the same complete gate-manifest validation: exactly one canonical PASS record with a nonempty command for every required gate. Missing, extra, duplicate, unsorted or failed records refuse publication and acceptance. These early integrity checks preserve full mandatory coverage.

The early SELF_MODEL gate also runs the actual root documentation and recursive-grammar checks, including exact inventory counts and catalog bijections, reference-resolution boundaries, semantic-conformance corpus compatibility and CLI integration before the expensive unfiltered suite. The same tests remain mandatory in that full suite; ordering catches structural, publication or snapshot-binding failures earlier without reusing a passing test result for changed source.

Semantic qualification invokes the test-owned native qualification package and its independent pure reference library through their declared package surfaces. The issuer supplies independently observed source and toolchain identities and reserves external OPS retention for first observations, failures and deterministic replays. The test-owned scorer binds current inputs and outcome bytes through the typed Standard Registry reader; the issuer publishes only compact passing metadata. Explicit accepted research primitive bounds condition cross-effect negatives, with the default partial-summary uncertainty and assumption references retained. They are not certified Standard-library bounds, default promotion, application execution evidence, human review or population accuracy claims.

Source identity integrity keeps two existing digest domains distinct. The local quality fingerprint hashes path/NUL/decimal-length/NUL/content-SHA256/LF; native Certification hashes big-endian u64 UTF-8 path length, path bytes, content length and original content. A single observed-byte pass computes both without a second semantic evaluator. Application publication and replay compare native subject references with the independently computed native digest and bracket the same input set with the frozen local fingerprint; they never compare these different domains as interchangeable hashes.

Before starting an optional registered performance campaign, run both Python storage controls, workspace format checking and strict all-target/all-feature Clippy, then the unfiltered `behavioral_flow`, `control_plane`, filing/documentation/schema and source-architecture targets plus the changed owners' preparation and recovery targets. `behavioral_flow` exercises the selected historical generation against the independently compiled current BFG, so a stale layout, corrupt member or current-source mismatch is diagnosed before measurement. Stop on a prerequisite failure, repair it and freeze the resulting inputs before measurement. A representative `--development-probe` can inspect reuse and required fallback. These experimental runs cannot replace the final candidate's mandatory 1,000-case differential corpus, Session correctness and restoration controls, all 34 canonical gates, exact-byte certificate verification and exact-head hosted qualification. The optional 300-sample performance campaign, numerical speedups and extensive measurement repetitions are not canonical certification prerequisites.

Issuance obtains the real CLI executable from the successful pinned Cargo build's artifact report, rejects missing, ambiguous or out-of-target artifacts, and stages an exclusive exact-byte copy with its executable permissions in the owned run. This frees the same leased compiler target for the complete unfiltered suite while the staged process runs. It caches no test result, suite evidence or semantic oracle. Compiler reuse remains subject to Cargo's complete compilation fingerprints and the issuer's exact input bracket. The staged executable is budgeted and removed through normal run cleanup; direct CLI invocation inside a compiler target retains its separate suite target.

Each started issuer command emits wall duration, issuer-process CPU and exit state in an operational timing record, including failed commands. Issuer CPU excludes children and descendants; an external owned-job measurement supplies whole-tree CPU and committed-memory peaks. These records stay outside semantic projections and PASS claims. Capture builds, test execution, analysis, documentation and schema/evidence commands separately, and include the surrounding setup, validation, publication, verification and cleanup in total certification cost.

When a captured command fails, the issuer emits its full captured stdout byte count and digest plus at most four MiB of raw tail bytes to stderr. A shortened preview is explicitly marked truncated and carries no qualification claim. The original gate failure remains an error even if diagnostic emission fails. Successful captured output remains byte-for-byte unchanged. Retain the enclosing owned-job logs to preserve the assertion and completed output that fit this bound.

Measure total certification from setup through build, every gate, registered empirical campaigns, restoration, artifact/schema processing, publication, verification and bounded cleanup. Report these costs separately from producer phase times, process CPU and sampled RSS. Conservative allocation charges, process RSS and Windows job commit peaks describe different quantities. Include source and executable digests, toolchain/dependency/configuration bindings, reference hardware, scheduling conditions, raw report digests and incomplete runs. An inner-loop speedup alone does not demonstrate an end-to-end improvement. The design target is approximately one hour on the documented reference machine; correctness and the complete acceptance contract take precedence.

For algorithm performance experiments, freeze the proposed source, contracts and documentation before measurement. Compare independent baseline and candidate executables on identical evaluation inputs, include construction and evidence costs separately, and require full canonical artifacts, findings and provenance to agree. Record methodology, machine conditions, identities, variance and limitations in private research records. Performance measurements are experimental observations, not certification gates: neither numerical speedup thresholds nor extensive benchmark repetitions are required for canonical certification. Correctness, equivalence, determinism, resource safety and exact-source qualification remain mandatory. Any later relevant input change requires identifying which observations still apply. Keep historical, incomplete and incompatible studies with their original subjects and statuses; historical timings do not qualify new source.

Phase telemetry reads the current process through the pinned safe APIs of [`cpu-time`](https://docs.rs/cpu-time/1.0.0/cpu_time/struct.ProcessTime.html) and [`memory-stats`](https://docs.rs/memory-stats/1.2.0/memory_stats/). It avoids enumerating every running process at each phase. Whole-process CPU includes concurrent threads and excludes children; a counter failure is disclosed as absent. Memory samples are endpoints, not phase peaks or heap-allocation counts. Windows reports working set and pagefile usage; Unix reports RSS and virtual address size, with approximate fast `/proc/self/statm` sampling on Linux. Collector wall time is recorded separately and excluded from producer phase time; total campaign time includes it. Counters never enter canonical projections, semantic digests or reuse proofs.

For bounded development comparisons, predeclare the workload and a modest run count appropriate to this shared development machine. Bind source bytes, compiler, dependencies, target, features, flags, lockfile and executables; retain interrupted and rejected attempts. Account for independent fresh cold evaluation, unchanged refresh, body changes, baseline restoration, construction, memory and total wall time where exercised, and disclose unmeasured workloads. Scratch admission and missing-owner refusal require correctness controls; formerly unresolved target addition must rebuild current facts and restore cold-equivalent baseline output. Use one owned heavy campaign; coordinate shared-machine activity without terminating foreign processes. Keep partial records incomplete and prove owned process closure, journal state, restoration and lease release before a fresh start. These experimental observations do not replace or add performance conditions to authoritative correctness certification.

The accepted source at `2defcfe996872de99ed0e3fbcf3da2b71c6f2956` required 36,676.272 seconds for complete local qualification (10 hours 11 minutes), including 32,060.399 seconds in the registered benchmark and 3,723.827 seconds in the canonical issuer. The benchmark registry mixes 100 actual-repository cases with 200 synthetic fixture cases. Aggregate phase averages therefore do not describe a complete-repository evaluation's latency. Fresh matched complete-repository measurements of bounded StateEffect field aggregation showed a 10.0535% median whole-producer reduction (1.657 seconds) and a 3.1295% median seven-stage Session-path reduction (17.781 seconds); all five pairs improved both metrics and all complete compared outputs matched. These development measurements include index construction and restoration, but exclude authoritative suite/certificate generation. They do not establish a full-certification speedup or a one-hour result. The measured common preparation, other analyses, independent cold comparisons and restoration remain substantial work; future changes require their own complete-input and correctness evidence.

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

### [`application_assessment.py`](../_code/application_assessment.py)

The application issuer builds the actual source-bound CLI, captures its canonical StateView and publishes only structurally usable application artifacts through existing RunWorkspace publication intents/preimages. It preserves all unrelated selections, publishes immutable members before the current index, rechecks source/tool/index preimages, and supports exact fresh replay without latest-green fallback. Negative and unknown reports are publishable; no canonical Rust suite is invented or required for application reporting. Use `python -B engine/snapshot_governance/_code/application_assessment.py issue|verify <repository>` with existing bounded storage/retention settings. The native `fortress declare`, `assess`, and `state-view` commands render the same Certification-owned artifacts. `state-view` succeeds when reporting succeeds; `assess` withholds a successful exit for unapproved endpoints.

Current full implementation qualification additionally validates and binds both new application artifacts from its existing single semantic stack. Its application assessment need not be favorable for truthful reporting, and the original full correctness suite remains mandatory. The seven read-only snapshot_evaluation assertions share one fresh immutable audit fixture; independent cold, determinism and mutation controls retain fresh executions.

Ordinary publication errors now reconcile approved write intent before deleting staging/preimages. A matching old pointer rolls back exact owned writes; a complete matching new pointer is preserved. Foreign target changes retain the recovery workspace. Atomic replacement uses exclusive nonce-owned, fsynced staging and preserves unrelated pending files. Historical certificate integrity can be read explicitly; current qualification requires the current edition.

### [`evidence_ingest.rs`](../_code/evidence_ingest.rs)

Read-only bounded import replay retains exact raw bytes and refuses substituted content or linked paths. Registered execution requires a matching explicit physical-project grant before callback, exact pre/post source/context and binary identities, tracked child closure and completed storage lifecycle before a fresh receipt exists.

### [`junit_ingest.rs`](../_code/junit_ingest.rs)

Streaming XML1.0 native-test subset with explicit unavailable package, process and attempt facts, bounded depth/events/rows/metadata, no DTD or namespaces, and limitations for unsupported report extensions. Duplicate or mixed terminal elements are rejected; inconsistent aggregate counts withhold complete-run support.

### [`sarif_ingest.rs`](../_code/sarif_ingest.rs)

Bounded typed SARIF2.1 single-run and single-invocation observations. Successful invocation and findings remain distinct; missing results, rules, invocation or unresolved external properties never establish absence. Imported analysis never becomes ExecutedTest evidence.

`quality_certificate.py` stages both registered executables, invokes the test-owned correctness qualifier and replay, and publishes compact metadata in its separate production group. `execution_storage.py` reserves bounded external retained evidence under the active existing lease; journals record the allocation, and compiler/staging cleanup never prunes observations. Unknown history counts toward the budget and is retained on refusal.

### [`query.rs`](../_code/query.rs)

Owns the single immutable inspection index, state/context identity, selector ambiguity, route permission classification, bounded pages and cancellation. Loaded queries perform no semantic evaluation or state writes.

### [`query_protocol.rs`](../_code/query_protocol.rs)

Defines protocol v1 envelopes, strict typed method parameters, structured errors, exact canonical JSON and complete human rendering shared by CLI, future IDE and host adapters.

### [`query_load.rs`](../_code/query_load.rs)

Explicitly observes bounded source/authority and loads selected CONTROL generations through registered roles. Reports missing, stale, unavailable, integrity and authentication states independently, without artifact generation or repair.

### [`query_explanation.rs`](../_code/query_explanation.rs)

Links recorded claims, findings, obligations, defeaters, proof nodes and provenance into paged explanations. Minimal support is asserted only for recorded matching single-premise conclusions; schema-informed canonical policy previews remain unapproved proposals.

The query facade contract is protocol v1 (`query_request_schema_v1.json` and
`query_response_schema_v1.json`), with an exact immutable input identity and JCS
response bytes. Consumers in Flow, Behavior, onboarding, Security, performance,
IDE and host integrations must use this result contract and rerun the query/schema
and adapter controls if it changes. Query loading is an explicit source/authority
observation boundary; warm inspection never triggers semantic evaluation. Existing
StateView, declaration, assessment and proof versions retain their original meaning.

### [`transition_load.rs`](../_code/transition_load.rs)

Explicit bounded current capture and CONTROL generation/file loading. Source and authority assets use existing producer identities, policy compilation and reference facts; no historical evaluator executes and no compared state is modified. Missing historical metadata remains unavailable.

### [`query_transition.rs`](../_code/query_transition.rs)

Protocol v2 compares two explicitly preloaded states through State Governance and pages every result and incomparability. Warm requests never discover files or invoke a semantic evaluator.

### [`portable_load.rs`](../_code/portable_load.rs)

Loads an exact registered CONTROL generation, an unambiguous current selection, or an explicitly supplied StateView3. It verifies original member identities and uses registered provider roles for the selected evidence closure. It never scans for newest files, invokes analysis to format export, executes project scripts, repairs caches or overwrites an output directory. Existing historical inputs remain unchanged. Explicit export writes only a new checked directory; offline verification reads supplied portable bytes independently.

### [`authority_load.rs`](../_code/authority_load.rs)

Read-only protected-authority composition and explanation; repository assertions cannot supply a trusted validator.

### [`query_authority.rs`](../_code/query_authority.rs)

Read-only protected-authority composition and explanation; repository assertions cannot supply a trusted validator.

### [`lifecycle_load.rs`](../_code/lifecycle_load.rs)

Loads only registered active finding authority, composes read-only lifecycle reports and maintenance proposals, and admits a postimage only through an exact process-local AUTHORITY decision with opaque grants. Returned bytes do not claim write mediation.

### [`query_lifecycle.rs`](../_code/query_lifecycle.rs)

Indexes already-produced comparable retirement and current authored admission/exception history for bounded, cancellable EXPLAIN paging. It never reruns analysis, validates external permission, chooses an ambiguous historical candidate, or treats recorded resolution as current repository evidence.

Optional bounded BEHAVIOR composition resolves project/Module applicability from registered selected profiles, consumes Behavioral Realization owner claims, and carries their original findings, defeaters and limitations into declaration, assessment, EXPLAIN and portable replay. Protocol v4 authoring consumes the same explicitly admitted immutable semantic context as FLOW; it does not execute source analysis to format requests. CONTROL generation selection remains the source of retained evidence; default legacy realized output is unchanged when the optional scope is unselected.

### [`migration_adapter.rs`](../_code/migration_adapter.rs)

Composes full canonical immutable evaluation and existing trusted AUTHORITY decisions. Bootstrap and identity edits enter the single Migration Governance writer; proposed evaluations never become actual-state evidence.

### [`migration_storage.rs`](../_code/migration_storage.rs)

Retains external same-volume staging, immutable owner records, verified terminal records and native pinned identities under the shared OPS admission registry. Incomplete runs retain all originals and prevent fresh certification.


Migration retirement evaluation consumes an opaque RATCHET proposal and an exact pre-maintenance SourceView. The lifecycle owner rederives the original comparable proof and checks the governance-only postimage; it does not require evidence to hash a file containing that evidence. Generic authorized file replacement cannot bypass this owner admission. Critical assessor scope is resolved through canonical Module ownership over the complete physical inventory, including files excluded from semantic projections.

Identity governance normalization additionally consumes the existing non-deserializable IdentityMigrationPlan through lifecycle admission. Exact source and the entire replacement set must match its producer output; baseline/exception cardinality and Standard binding are preserved, and current anchored authority cannot change. This evidence cannot provide grants or prove retirement.

### [`bootstrap_plan.rs`](../_code/bootstrap_plan.rs)

Composes versioned native/logical and strict canonical onboarding from existing read-only discovery, canonical contract/profile owners, hypothetical evaluation, exact reviewed finding-baseline selection and the shared transactional migration engine. A proposal is PROPOSED, content-bound and unauthenticated. Explicit application preserves original-policy protection and independently observes the actual result; no runtime certification is inferred. Recovery delegates to the same journals and preserves independent edits.

Discovery retains declared Module capabilities and outbound relationships separately from a bounded preview of canonical PSM call relationships. The call preview includes at most 1,024 existing owner records with total and truncation indicators; it never asserts complete flow coverage or permission. Other recognized intent declarations remain explicitly unverified occurrences until evaluated by their semantic owners, and existing intent requires a repair review.

### [`bounded_io.py`](../_code/bounded_io.py)

Provides operational byte/JSON admission for the installed Python certificate and storage adapters. It retains one ordinary file identity, rejects links, checks complete bounded bytes and source drift, and rejects duplicate keys, excessive nesting, global node exhaustion and non-finite numbers before owner interpretation. It supplies no semantic or approval authority.

### [`security_qualification.py`](../_code/security_qualification.py)

Composes a versioned exact-source boundary qualification record only after the existing canonical issuer validates its complete executed gate manifest. Its public reader checks digest, source and an independently supplied required-gate list. The record remains unsigned, unauthenticated and confined to tested surfaces and host versions; it cannot prove execution to an untrusting consumer or authorize a protected change. OPS retains the compact record, source-bound control report and ownership marker outside production source. See [the threat model](code_docs.md) for risk dispositions and downstream requalification requirements.

**Untrusted-input threat model**

This review covers repository observation, source and contract decoding, CONTROL,
immutable projections, imported verification, offline portable evidence, stdio,
candidate evaluation, onboarding, and Migration Governance. It introduces no
security-policy evaluator, issuer authentication, or general-purpose sandbox.

An attacker may control every repository byte, filename, authored assertion,
imported report, archive member, proposed change, and repository-local cache.
Those inputs cannot select trusted approvers, authenticate execution, or authorize
changes to their own governing base. The installed assessor, trusted host tool
selection, operating system, and private operational storage are outside that
attacker's authority. A privileged hostile operating system is unsupported.

**Boundary matrix**

| Input and resource | Required boundary | Failure meaning |
| --- | --- | --- |
| Repository files, links, case aliases and special objects | Ordinary-object checks, physical identity, bounded complete inventories, exact reobservation | Reject unsupported objects, drift, collisions or exhausted observation; no partial PASS |
| JSON contracts, profiles, configuration and records | Byte, depth, token/node and duplicate-key admission before typed owner decoding | Explicit invalid input or RESOURCE_LIMIT; never silently truncate |
| Rust source and test inventory | Bounded source-unit admission before existing frontends; no macro or build execution | Unsupported/exhausted source remains unevaluable |
| XML and SARIF reports | Bounded events, attributes and records; no DTD, external resource retrieval or inferred execution | Imported observations remain distinct from authenticated provider evidence |
| ZIP assurance bundles | Bound central-directory allocation before ZIP decoding; qualified compression only; retain one container; never extract | Unsupported archive, resource exhaustion, digest or graph failure cannot confer assurance |
| Evidence DAGs, descriptors, current pointers and caches | Exact content, subject, context, authority, schema and dependency bindings | Missing, stale, corrupt or ambiguous evidence remains non-favorable |
| External executables | Trusted host selection outside candidate control, absolute tool identity and bounded supervision | No project-controlled search-path executable on read-only operations |
| Candidate policy, grant references and receipts | Original-state AUTHORITY port and exact proposal binding | Local assertions and unsigned records are not validated grants |
| Migration paths, staging and recovery | Existing leases, same-volume ownership, journaled pre/postimages and independent final reconciliation | Preserve independent edits; hold certification during incomplete migration |
| Local stdio clients | Version negotiation, typed parameters, bounded frames/pages, cancellation | No network listener, web origin or editor-specific authority is implied |

**Supported concurrency and durability**

Cooperative Fortress writers use the established physical-identity lease. External
edits are checked at capture, mutation and publication boundaries. Observed drift
or an unknown object is rejected. This is not a claim to detect every transient
change by an adversary able to swap filesystem objects between system calls.
Abrupt termination of a standalone verifier parent requires host process-tree supervision; ordinary failure cleanup owns only the reviewed consumer child, which never spawns descendants. Migration recovery qualifies process crashes and verified known images. It does
not promise cross-file atomicity, arbitrary power-loss durability, or rollback
success without byte verification.

**Review and requalification**

Every discovered boundary defect requires an owning-Module repair and retained
reproducer. Qualification binds exact source and tested interfaces; it is not
issuer authentication or proof that all possible attacks were enumerated.
PERF, ADMISSION, IDE, HOSTS, DISTRIBUTE, EXTEND and RELEASE must rerun these controls
when changing adapters, quotas, process admission, schema retrieval, storage,
grant provenance or physical-path behavior. Stress costs are observations;
explicit resource-safety limits remain enforced requirements.

**Enforced admission and protected resources**

The protected resources are host files outside the selected repository, current
source and authority bytes, immutable historical evidence, external grants,
execution-local staging and rollback material, retained memory and disk, process
handles, and the truthfulness of current certification. Host-installed code and
tool selection must be protected independently from repository contributors.
Changing the assessor cannot supply its own original-policy approval. Registered execution authorizes an operation and bounds its supervision; it does not restrict arbitrary syscalls. Hostile project code requires independently supplied host isolation, which Fortress does not implement or claim. Documented
GitHub protection is not evidence that provider rules are actually enforced.

| Boundary | Operational limits and supported behavior |
| --- | --- |
| Ordinary inventory | 100,000 files, 200,000 entries, 1 GiB hashed content, 32 MiB aggregate path bytes, depth 128; explicit caller budgets may be smaller |
| Manifest inventory | The same entry/path/file/content/depth admission, with explicit barriers for unsupported objects; no link traversal |
| Shared Rust JSON wire | 512 MiB, 16 million global tokens including keys, depth 96, 32 MiB encoded single token; typed owners retain narrower limits |
| Python operational records | The same bounded, reparse-rejecting ordinary inventory and 1 GiB aggregate source admission; bounded ordinary reads up to 512 MiB for large projections; selection/manifest/certificate/journal records have narrower 4 MiB admission; metadata and handle identities are rechecked |
| Rust/TOML source frontends | 4 MiB per source unit; TOML retains its dependency recursion guard without the unbounded feature. Rust has depth 128, comment nesting 128, 256 operators or recursive keywords between structural boundaries, 512 angle openers per uninterrupted syntax region and angle depth 128; arrows do not close generic accounting and const blocks retain their enclosing angle depth, while independently closed declarations renew the region. Early Rust rejection invalidates an enabled resident parser epoch, preserves the typed resource failure and cannot publish a generation; conservative admission may reject otherwise valid large/complex Rust |
| Canonical Markdown | 4 MiB input, one million events, emitted nesting 128, 32 MiB conservative retained allocation units; exhaustion produces an explicit documentation finding or reader error |
| Offline JSON consumer | 32 MiB per artifact, depth 64, two million global tokens; strict duplicates, finite numbers and public JCS rules |
| ZIP container | 128 MiB compressed/expanded total, 130 members, 128 KiB central metadata, 32 MiB per member, expansion ratio at most 1,000; only single-disk non-ZIP64 stored/deflated ZIP, without prefixes; never extracted |
| XML provider | Existing 64-level, million-event, 256-attribute, 65,536-byte attribute admission; no DTD or external entity retrieval |
| Query stdio | Existing 65,536-byte request, 1 MiB response and 200-record page bounds, typed parameters and cancellation; formatting loaded results never starts source analysis |
| Embedded verifier | Absolute host interpreter with bounded 256 MiB pre/post content and native identity checks, isolated Python, 180-second execution budget and 1 MiB per output pipe; failure kills and reaps the owned child |

These are operational allocation/count budgets, not claims about exact allocator
RSS, worst-case latency or a general operating-system sandbox. Existing SESSION,
provider, candidate and migration budgets continue to apply. Resource rejection
is never partial success. Outer trusted hosts must retain their own process,
volume and memory supervision, especially on machines unable to admit the
largest supported canonical projections.

Windows ordinary-file admission uses retained native volume/file identity,
reparse metadata rejection and `FILE_FLAG_OPEN_REPARSE_POINT`. Unix ordinary
file admission uses no-follow/nonblocking opens and device/inode identity;
directory admission uses no-follow directory handles. Case-colliding inventories
are rejected rather than choosing a favorable candidate. Native identity stays
machine-local and does not change portable semantic or historical digest inputs.
Windows junction and case aliases are exercised locally. Linux filesystem,
process, public-consumer, storage, transaction recovery, candidate/onboarding,
authority, provider and read-only query controls run on the exact hosted revision.
Hosted job deadlines are execution budgets; no latency, speedup or stress timing
is a certification criterion. Other platforms,
filesystems without qualified native identities, arbitrary network/device roots,
and hostile unmediated filesystem writers are not advertised as qualified.

**Defect disposition and regression evidence**

| Reviewed issue | Disposition and owning regression |
| --- | --- |
| JSON/ZIP admission after library allocation | Repaired before decoding; `security_controls.py` decoder spies and global/depth budgets; strict wire mutation and admission tests |
| ZIP inventory and member reads from separately opened containers | Repaired with one retained handle and before/after identity, size and modification checks; resize and single-open controls |
| Reparse repository roots and weak read identity | Repaired in Repository Observation; native same-file checks reused by OPS, MIGRATE, providers, queries and Snapshot Governance; `security_boundaries` retained-identity and junction controls |
| Operational unbounded JSON/file reads | Repaired in certificate and storage adapters through `bounded_io.py`, including explicit reparse-root and bounded inventory admission; duplicate, nesting, non-finite, preallocation and record tests; unchanged storage/recovery corpus remains mandatory |
| Recursive Rust input and expanding Markdown | Preflight resource admission before existing frontends, bounded Markdown event/retention handling; literal/comment/type/operator controls and explicit resource failures |
| Terminal/direction controls in findings and inspection fields | Escaped at readable field rendering and streaming CLI diagnostics, covering all 12 Unicode 18.0 Bidi_Control characters including Arabic Letter Mark; machine values and source identities remain unchanged. Both presentation regressions exercise the complete set from the [Unicode property list](https://www.unicode.org/Public/18.0.0/ucd/PropList.txt) |
| Repository-local interpreter and unbounded child output/wait | Absolute host selection checks physical directory ancestry, embedded isolated consumer, bounded pipes/deadline and owned-child cleanup; CLI shadow/output/deadline controls |
| RUSTSEC-2026-0414 and RUSTSEC-2026-0433 | Applicable high-severity `Options::all()` wikilink defects repaired by pinning pulldown-cmark 0.13.6; exact sibling-event and nested-image regressions; scanner rerun retained separately |
| Yanked yoke-derive 0.8.3 | Lockfile moved to 0.8.4; dependency scanner observation is diagnostic and not authenticated provider execution evidence |
| Wrong-subject/replayed imports and forged approvals | Existing provider normalization, exact execution freshness, AUTHORITY and candidate/migration adversarial tests remain mandatory; parsing never authenticates execution |
| Hidden source/output, forged selection, cache and descriptor tamper | Existing CONTROL, artifact-storage, source-fingerprint and resident-cache controls remain mandatory; historical generations are retained and never automatically current |
| Transaction crashes, cancellation and independent edits | Existing every-write-boundary crash, journal tamper, conflict-preserving rollback/resume, incomplete-application certification barrier and candidate post-write divergence tests remain mandatory |

The independent public controls include deterministic single-byte JSON mutation,
malformed ZIP end records, unsupported compression, path/case attacks and resource
admission before decoder allocation. This bounded mutation corpus is targeted
fuzzing, not evidence of exhaustive language or operating-system coverage.

The dependency review uses the installed cargo-audit scanner and a retained
RustSec database revision; it does not introduce a vulnerability scanner or
promote scanner parsing into authenticated execution. The upstream advisories
are [RUSTSEC-2026-0414](https://rustsec.org/advisories/RUSTSEC-2026-0414.html)
and [RUSTSEC-2026-0433](https://rustsec.org/advisories/RUSTSEC-2026-0433.html).
Host executable selection follows the documented absolute-path boundary of
[Rust Command](https://doc.rust-lang.org/std/process/struct.Command.html).
Windows native identifiers use the existing qualified WinAPI adapter rather
than unstable Rust MetadataExt file-index APIs.

**Qualification record and downstream integration**

The canonical issuer preserves every existing gate and adds SECURITY_BOUNDARIES while retaining the registered `fortress-complete-local-v1` selection family. Historical certificates remain claims about their recorded source and gate manifest; they do not assert the new `security_qualification` v1 controls. Current source verification requires the complete 34-gate manifest. No parallel selection context, certificate-format reinterpretation or historical rewrite is introduced.
After all 34 gates pass against unchanged exact source, it emits
`security_qualification` v1 into an exclusively owned OPS retained-evidence
allocation. The record names its quality-certificate source-fingerprint domain (distinct from native semantic subject identity), required gates, actual host versions,
control-report digest, threat-model digest and unsupported threats. Its identity
is SHA-256 over sorted compact ASCII JSON excluding `record_id`; this schema
admits no floating-point values. The public reader requires a separately supplied
exact source and complete required-gate list. Integrity verification cannot prove
that tests actually ran, establish issuer authenticity, confer a grant, or make
a historical record current. A record created before final generation publication
is insufficient without the corresponding successful exact-source certificate
and verified publication.

No new authoritative store or registry is introduced. Historical CONTROL
selection and portable assurance semantics are unchanged. Status, doctor,
read-only comparison, imported-bundle verification and ordinary unprotected
inspection do not need external grants. Explicit test/provider execution remains
registered and host-authorized; discovery never runs Cargo, build scripts,
procedural macros, repository providers or configuration-defined commands.

PERF may change implementation strategies only after proving identical canonical
outputs and retaining all resource controls. ADMISSION, IDE and HOSTS must carry
original authority, source/context and grant provenance, preserve cancellation,
respect stdio quotas, and prevent project-controlled executable selection.
DISTRIBUTE and RELEASE must package the reviewed consumer and admission helpers,
keep integrity distinct from authenticity and requalify the actual delivered
adapters. EXTEND must admit each new parser/provider through these controls.
None may substitute an unsigned qualification record for provider enforcement,
external approval, execution freshness or actual-state certification.
