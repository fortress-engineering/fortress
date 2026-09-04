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

### [`bootstrap.rs`](../code/bootstrap.rs)

Performs read-only repository discovery, compiles exact-source-bound reviewed authority proposals from explicit owner choices, and transactionally applies only canonical minimal governance with optional one-time delegation to finding-baseline authority.

### [`audit.rs`](../code/audit.rs)

Orchestrates declaration loading, stabilized snapshot construction, shared CCG, Intended BFG, implementation observation, PSM, semantic-domain, state/effect, Module semantic-conformance, information-flow, environmental, Behavioral Realization, and Reference Resolution analysis, rule execution, and deterministic audit v4 rendering with normative findings, non-normative architecture diagnostics, and unsupported analysis kept distinct.

### [`contract.rs`](../code/contract.rs)

Projects CCG compilation, supported logical coherency, and README synchronization into canonical CONTRACT-COHERENCY-001 findings.

### [`documentation.rs`](../code/documentation.rs)

Parses canonical Markdown structurally and reconciles Module contracts, catalogs, child decomposition, and links.

### [`evaluation.rs`](../code/evaluation.rs)

Dispatches only implemented applicable rules, including behavioral, program-domain/state/effect/information/environment, and REPO-REFERENCE-001 evaluators from shared results, and distinguishes evaluated pass or failure from unsupported capability.

### [`ownership.rs`](../code/ownership.rs)

Reconciles observed governed files with exact declared architectural ownership.

### [`placement.rs`](../code/placement.rs)

Projects the canonical Project Model filing analysis into REPO-MODULE-001 findings covering recursive Modules, closed Elements, Code flatness/mechanical exceptions, bounded Data/Info structure, companion docs, and path naming.

### [`quality_certificate.py`](../code/quality_certificate.py)

Executes the complete pinned local quality-gate profile, consumes one exact-snapshot certification stack for semantic projections, audit, and certification evidence, maintains the closed tracked-evidence/local-materialization artifact registry, deterministically reconstructs subject-addressed bulk projections, distinguishes missing, stale, invalid, and current local bytes, and performs lightweight PASS, authoritative-source freshness, tracked-evidence digest, and tamper-stamp verification while explicitly retaining UNVERIFIED issuer authenticity. Generator determinism remains proved by governed tests; routine issuance verifies exact dependency bindings and final canonical digests without repository-wide duplicate execution.

### [`rust_test_analyzer.rs`](../code/rust_test_analyzer.rs)

Uses structured Rust syntax parsing to emit deterministic snapshot-bound behavioral test facts.

### [`snapshot.rs`](../code/snapshot.rs)

Builds two-pass stabilized content-addressed repository snapshots and rejects mutation between observations.

### [`traceability.rs`](../code/traceability.rs)

Projects CCG requirement/test identity findings and deterministic coverage counts without rebuilding verification topology.

### [`testing_boundary.rs`](../code/testing_boundary.rs)

Projects CCG recursive Testing-child, exact parent Feature subject, role, and Rust evidence-placement findings.
