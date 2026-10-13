# Code

## Role

Exercise the Module responsibility through directly owned verification logic without becoming normative authority.

## Execution

Cargo invokes each explicit test target; the code loads direct fixtures or the governed repository, performs deterministic assertions, and terminates with process success or failure.

## State

Verification is stateless apart from process-local values and isolated disposable runtime repositories where a scenario requires filesystem behavior.

## Failure Semantics

A violated assertion or fixture-loading failure fails the test target and surfaces its exact subject; verification never suppresses production errors.

## Files

### [`arch_ownership_001.rs`](../_code/arch_ownership_001.rs)

Exercises complete, orphaned, overlapping, required, and minimum ownership cases.

### [`audit.rs`](../_code/audit.rs)

Runs the complete self-audit and asserts every implemented applicable rule passes.

### [`derived_artifact_storage.py`](../_code/derived_artifact_storage.py)

Verifies the complete projection-storage registry, subject-addressed external cache boundary, prior-certificate and Cargo-lock preservation through injected gate failures, leased materialization, scoped cleanup, and distinct missing, current, stale, and invalid materialization states without executing semantic generators. Both selection readers and publishers reject competing context keys, reverse ordering, invalid unrelated digests, extra fields, and malformed entries; valid unrelated contexts, shared generations, and empty bootstrap indexes retain their defined meaning.

Issuer executable controls bind the successful CLI compiler artifact to its owned target and source owner, verify exact staged bytes and executable permissions, refuse incomplete or ambiguous reports, growth and out-of-target paths, and preserve existing staging bytes on collision. Compile and analysis failure controls preserve the prior certificate and user lock through the staged-launch boundary.

### [`execution_storage.py`](../_code/execution_storage.py)

Exercises storage preflight and budgets, exclusive heavy-job leases, preservation of user bytes on failure, crash recovery before and after publication, external-mutation conflicts, active-child uncertainty, and cleanup accounting without invoking Cargo.

Budget-scan regressions exercise disappearing compiler objects and directories, fresh growth and deletion accounting, conservative charging of hardlink paths, and non-following refusal of symbolic links and Windows reparse points at the root and inside the tree.

### [`finding_governance.rs`](../_code/finding_governance.rs)

Verifies stable finding identity, baseline creation and monotonic pruning, reintroduction, explicit exception retirement, orthogonal conformance/enforcement, and deterministic authority serialization.

### [`repo_docs_001.rs`](../_code/repo_docs_001.rs)

Executes the specification-authored canonical documentation and contract synchronization cases.

### [`repo_module_001.rs`](../_code/repo_module_001.rs)

Executes valid, invalid, and boundary recursive Module grammar fixtures.

### [`repository_snapshot.rs`](../_code/repository_snapshot.rs)

Verifies self-snapshot repeatability and binding to every declared draft rule.

### [`runtime_storage.rs`](../_code/runtime_storage.rs)

Verifies the installed Rust adapter's exclusive heavy-job lease, disk preflight, active-child retention, selected marked-target cleanup, and explicit exact-journal retirement that preserves markerless empty residue. Recovery controls cover original-byte preservation, idempotence, unexpected payloads, phase and binding conflicts, existing leases, receipt collisions and registration boundaries.

### [`repository_bootstrap.rs`](../_code/repository_bootstrap.rs)

Verifies read-only deterministic discovery, explicit owner-choice separation, proposal digest and staleness enforcement, transactional minimal authority application, source/Cargo preservation, and truthful zero-new-red baseline behavior.

### [`repository_grammar.rs`](../_code/repository_grammar.rs)

Checks Fortress's physical repository and canonical documentation at the Snapshot Governance boundary that implements those rules.

### [`snapshot_evaluation.rs`](../_code/snapshot_evaluation.rs)

Verifies truthful rule dispatch, unsupported reporting, and complete self traceability inputs.

### [`snapshot_primitives.rs`](../_code/snapshot_primitives.rs)

Verifies snapshot stabilization, finding normalization, lexical placement, Rust analysis, and exact draft bundle loading as parent-owned behavior.

### [`test_boundary_001.rs`](../_code/test_boundary_001.rs)

Exercises simple, complex, invalid, cross-level, infrastructure, and recursive parent-local TEST-BOUNDARY-001 scenarios.

### [`test_traceability_001.rs`](../_code/test_traceability_001.rs)

Exercises complete, invalid, and infrastructure-boundary requirement and Rust-test traceability.

### [`heavy_admission.rs`](../_code/heavy_admission.rs)

Verifies R18-001 through R18-009: native physical-directory exclusion and identity, Windows aliases, cross-adapter locking, preservation of unfinished foreign owners, aggregate compiler budgets, immunity to temporary-environment drift, retained-target retargeting restrictions, and fixed external registry placement.

### [`resident_session.rs`](../_code/resident_session.rs)

R19-025 also proves that known cold requests rotate before insufficient admission, execute fresh producer work with zero owner reuse and preserve complete canonical bytes. A changed exact source identity still exercises actual exhaustion and retry before it can train its own hint. The original prepared-program exhaustion control remains in place. R19-003 also establishes a previously unseen candidate demand through a successful complete program rebuild with actual domain/effect reuse, then proves that its independent cold comparison rotates before admission with zero discarded work and complete canonical equality; candidate execution preserves actual source.

Verifies R19-001 through R19-006 and R19-020 through R19-029: immutable concurrent readers, complete currentness despite missed watcher hints, cancellation/eviction, isolated candidates, pinned-generation accounting across close/reopen, admission limits, publication-time mutation and cancellation, retained availability, incomplete candidate exclusion changes, parser request limits and epoch rotation, parser charges until join, cancelled candidate cache discard, journal-failure head preservation, and total-entry directory inventory admission. R19-005 also proves that an independent candidate reader still blocks a third generation after buffer release, then compares both cold ports to complete retained bytes after the final reader drops. Its comparison quota and overflow controls reject before copying bytes without changing the current head. R19-029 also verifies typed availability path-quota overflow and rejection of unregistered empty history subtrees.

### [`resident_differential.rs`](../_code/resident_differential.rs)

Verifies R19-007 through R19-010 with the actual public resident and cold-view APIs: one thousand successful whole-bundle comparisons over the registered mutation taxonomy, unresolved-to-resolved actual refresh, delete/readd/SCC reconstruction, and eviction changing work only. R19-010 checks atomic fresh fixture claims against existing directories and files, bounded collision exhaustion, other creation errors, and exclusive raw-report creation without overwriting prior bytes. It also checks that the owner loader and complete resident API reject a canonical function contract declared under an unrelated root Module, admit it under its explicitly authored logical source owner, and preserve whole-bundle cold equality. Its fifteen separate smoke cases execute every remaining policy/profile, ownership, finding-governance, unsupported-syntax and retained-history payload variant through actual resident and cold APIs; these controls do not add to the registered thousand-case population. Fixture Module Contracts, function contracts, information-flow policy and finding governance use their owning canonical serializers, while project configuration and local assumed catalogs are validated by their owning typed models; source ownership is declared in project configuration. Each successful comparison checks all fourteen canonical members using the same exact source view and unchanged real suite record; stale certification is an expected semantic output rather than manufactured PASS. Malformed syntax, cancellation, stale-base and resource failures do not count toward the successful population.

### [`resident_benchmark.rs`](../_code/resident_benchmark.rs)

Use the default invocation for the registered 300 comparisons and 300 restorations. `--development-probe` explicitly selects two actual-root cases and one case in each of the six fixture strata; `--fixture-development-probe` selects only those six fixtures. These are development checks, never authoritative certification or replacements for the registered populations. Each development run requires observed body, domain and direct-effect reuse in the independent fixtures, and both cold ports reject owner-preparation reuse. Reports disclose the selected population and do not mark a development population as the full benchmark. The separate registered differential corpus still requires 1,000 cases across all 16 mutation classes, all fourteen canonical members, the unchanged genuine historical suite and its truthful freshness state, plus its three companion controls and fifteen policy/authority smoke cases.

The reference machine is Executioner: Intel Core i9-14900HX, 24 cores / 32 logical processors, approximately 64 GiB RAM, Windows 11 build 26200. Freeze evaluated source and bind the prebuilt executable, compiler, dependency resolution and configuration before measurement. Coordinate an uncontended window on the shared machine; do not stop another project's jobs without authorization. Use the same frozen evaluated inputs and workload for before/after runs, record the changed executable identities explicitly, and compare every canonical artifact as well as elapsed time and CPU. Build costs, fixture setup, diagnostics, byte comparisons, restoration, evidence writes and cleanup belong in the total. Phase wall/CPU records and owner preparation charges explain producer work; restoration and post-warm harness records disclose previously untimed costs. Sampled RSS and cumulative process peaks remain separate from allocation estimates and Windows job commit counters.

To cancel cooperatively, exclusively create `cancel.request` in the announced external run directory with the exact bytes `fortress-resident-benchmark-cancel-v1\n` (LF). Requests are checked at phase and existing Session publication boundaries. An in-flight owner computation returns before cancellation; normal close joins the worker and cleans its owned staging. Inspect the cleanup record, journal, owned-process closure and lease release rather than inferring cleanup from a stopped console. Completed records are retained; failure records mark the campaign incomplete and explicitly reject prefix-resume qualification. Incompatible or interrupted prefixes never count as a full pass. If forced owned-job cancellation is necessary, retain its failure and journal and use the guarded production recovery API; never delete an uncertain journal or residue merely to obtain a clean run.

Provides the standalone `resident_benchmark` Cargo example empirical companion, with no Test ID or ignored test. Its three hundred samples comprise one hundred alternating actual-root requests (fifty unchanged and fifty isolated single-body candidates), one hundred size-stratified independent-body fixture samples, and one hundred graph fixture samples. Each sample separately times the warm public API, the identical capture-through-return API after preparation eviction, and the supplied-view cold oracle. Eviction occurs outside the timed API baseline; operating-system caches are not purged. All three results must have identical eleven canonical semantic projections and exact source/context bindings. After recording warm process memory and Session usage, the client admits a complete comparison snapshot and neutral warm metrics under a separate one GiB total scratch limit, then releases the warm candidate generation before either cold port. Exact bytes and context are compared directly. The supplied-view generation is released before the same-API baseline; its reference candidate and all comparison bytes/source backing are released before the untimed actual refresh restores preparation with its work recorded.

The companion records fixed-hardware/source/report provenance, actual owner work and fallback distributions, sampled process memory and separately labeled conservative allocation charges. Diagnostic collectors have a combined 1 MiB output limit and 30-second deadline; bounded child reaping and unresolved descendant diagnostics remain separate from Session storage cleanup. Absent suite execution is disclosed, so it does not manufacture the three certification products. Reports label p50/p95/p99 with exact population counts; for fifty samples coarse p99 is the observed maximum. External execution and measurement remain separate from conformance Test evidence and the one thousand fourteen-member differential population. Registration does not claim that the companion executed or passed.

### [`resident_comparison.rs`](../_code/resident_comparison.rs)

Shares the benchmark's bounded consumer snapshot with the registered reader-pin control. Checked pre-admission counts eleven boxed canonical byte/path slices, the complete retained SourceView backing and map metadata, full context allocations and temporary comparison/record copies. Context size is counted through borrowed serialization before constructing its owned JSON value; source-manifest and availability digests retain the existing exact serialization through streaming hash writers. Scalar work, reasons and proposal allocations are separately admitted by the benchmark and reported with reconstructable capacity fields. Consumer scratch remains separate from Session model accounting; both conservative estimates are distinguished from measured process RSS. No semantic model, evaluator, production limit or artifact binding changes.
