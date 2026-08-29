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

### [`audit.rs`](../code/audit.rs)

Orchestrates declaration loading, stabilized snapshot construction, shared CCG, Intended BFG, implementation observation, PSM, semantic-domain, state/effect, information-flow, environmental, Behavioral Realization, and Reference Resolution analysis, rule execution, and deterministic audit v2 rendering with normative findings, non-normative architecture diagnostics, and unsupported analysis kept distinct.

### [`contract.rs`](../code/contract.rs)

Projects CCG compilation, supported logical coherency, and README synchronization into canonical CONTRACT-COHERENCY-001 findings.

### [`documentation.rs`](../code/documentation.rs)

Parses canonical Markdown structurally and reconciles Module contracts, catalogs, child decomposition, and links.

### [`evaluation.rs`](../code/evaluation.rs)

Dispatches only implemented applicable rules, including behavioral, program-domain/state/effect/information/environment, and REPO-REFERENCE-001 evaluators from shared results, and distinguishes evaluated pass or failure from unsupported capability.

### [`ownership.rs`](../code/ownership.rs)

Reconciles observed governed files with exact declared architectural ownership.

### [`placement.rs`](../code/placement.rs)

Evaluates the recursive Module grammar, canonical surfaces, flat attributes, companion docs, and path naming.

### [`quality_certificate.py`](../code/quality_certificate.py)

Executes the complete pinned local quality-gate profile, including the relocation-reference projection, issues deterministic repository and artifact fingerprints after every gate passes, and performs lightweight PASS, freshness, digest, and tamper-stamp verification for hosted CI while explicitly retaining UNVERIFIED issuer authenticity.

### [`rust_test_analyzer.rs`](../code/rust_test_analyzer.rs)

Uses structured Rust syntax parsing to emit deterministic snapshot-bound behavioral test facts.

### [`snapshot.rs`](../code/snapshot.rs)

Builds two-pass stabilized content-addressed repository snapshots and rejects mutation between observations.

### [`traceability.rs`](../code/traceability.rs)

Projects CCG requirement/test identity findings and deterministic coverage counts without rebuilding verification topology.

### [`testing_boundary.rs`](../code/testing_boundary.rs)

Projects CCG recursive Testing-child, exact parent Feature subject, role, and Rust evidence-placement findings.
