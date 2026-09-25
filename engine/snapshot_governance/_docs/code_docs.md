# Code

## Role

Realize the Module responsibility through directly owned provider-independent implementation.

## Execution

Callers invoke the public typed boundary; the Code validates inputs, performs its deterministic processing sequence, and returns a complete result or typed failure.

## State

Execution owns only process-local state unless an explicitly documented artifact is read; no hidden persistent service state is introduced.

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

### [`identity_migration.rs`](../_code/identity_migration.rs)

Plans exact-snapshot legacy Rust symbol and semantic-finding reference migrations, rejects ambiguous or missing mappings, and applies only explicitly reviewed dependency-bound authority rewrites with rollback on write failure.

### [`ownership.rs`](../_code/ownership.rs)

Reconciles observed governed files with exact declared architectural ownership.

### [`placement.rs`](../_code/placement.rs)

Projects the canonical Project Model filing analysis into REPO-MODULE-001 findings covering recursive Modules, closed Elements, Code flatness/mechanical exceptions, bounded Data/Info structure, companion docs, and path naming.

### [`quality_certificate.py`](../_code/quality_certificate.py)

Executes the complete pinned local quality-gate profile under the leased storage supervisor, consumes one exact-snapshot certification stack, validates every emitted artifact against its advertised registered schema, checks the shared Project Model artifact registry, stages generation members with durable preimages, and publishes the selection index last. It reconstructs bounded subject-addressed projections, cleans only idle Python-owned subject cache entries, distinguishes missing, stale, invalid, and current local bytes, and verifies PASS, source freshness, evidence digests, and the tamper stamp while retaining UNVERIFIED issuer authenticity. Generator determinism remains proved by governed tests.

### [`runtime_storage.rs`](../_code/runtime_storage.rs)

Provides the installed Rust runtime with the same machine-local resource-policy, lease, journal, staging, publication-intent, and conservative recovery boundary as the Python pre-build supervisor.

### [`rust_test_analyzer.rs`](../_code/rust_test_analyzer.rs)

Uses structured Rust syntax parsing to emit deterministic snapshot-bound behavioral test facts.

### [`snapshot.rs`](../_code/snapshot.rs)

Builds two-pass stabilized content-addressed repository snapshots and rejects mutation between observations.

### [`traceability.rs`](../_code/traceability.rs)

Projects CCG requirement/test identity findings and deterministic coverage counts without rebuilding verification topology.

### [`testing_boundary.rs`](../_code/testing_boundary.rs)

Projects CCG recursive Testing-child, exact parent Feature subject, role, and Rust evidence-placement findings.
