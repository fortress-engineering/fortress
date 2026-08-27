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

Orchestrates declaration loading, stabilized snapshot construction, analyzers, rule execution, and deterministic audit rendering data.

### [`documentation.rs`](../code/documentation.rs)

Parses canonical Markdown structurally and reconciles Module contracts, catalogs, child decomposition, and links.

### [`evaluation.rs`](../code/evaluation.rs)

Dispatches only implemented applicable rules and distinguishes evaluated pass or failure from unsupported capability.

### [`finding.rs`](../code/finding.rs)

Defines validated content-addressed findings and their deterministic global ordering.

### [`ownership.rs`](../code/ownership.rs)

Reconciles observed governed files with exact declared architectural ownership.

### [`placement.rs`](../code/placement.rs)

Evaluates the recursive Module grammar, canonical surfaces, flat attributes, companion docs, and path naming.

### [`rust_test_analyzer.rs`](../code/rust_test_analyzer.rs)

Uses structured Rust syntax parsing to emit deterministic snapshot-bound behavioral test facts.

### [`snapshot.rs`](../code/snapshot.rs)

Builds two-pass stabilized content-addressed repository snapshots and rejects mutation between observations.

### [`traceability.rs`](../code/traceability.rs)

Reconciles active requirements and supported Rust test evidence bidirectionally.
