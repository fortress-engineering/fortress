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

### [`arch_ownership_001.rs`](../code/arch_ownership_001.rs)

Exercises complete, orphaned, overlapping, required, and minimum ownership cases.

### [`audit.rs`](../code/audit.rs)

Runs the complete self-audit and asserts every implemented applicable rule passes.

### [`repo_docs_001.rs`](../code/repo_docs_001.rs)

Executes the specification-authored canonical documentation and contract synchronization cases.

### [`repo_module_001.rs`](../code/repo_module_001.rs)

Executes valid, invalid, and boundary recursive Module grammar fixtures.

### [`repository_snapshot.rs`](../code/repository_snapshot.rs)

Verifies self-snapshot repeatability and binding to every declared draft rule.

### [`repository_grammar.rs`](../code/repository_grammar.rs)

Checks Fortress's physical repository and canonical documentation at the Snapshot Governance boundary that implements those rules.

### [`snapshot_evaluation.rs`](../code/snapshot_evaluation.rs)

Verifies truthful rule dispatch, unsupported reporting, and complete self traceability inputs.

### [`snapshot_primitives.rs`](../code/snapshot_primitives.rs)

Verifies snapshot stabilization, finding normalization, lexical placement, Rust analysis, and exact draft bundle loading as parent-owned behavior.

### [`test_boundary_001.rs`](../code/test_boundary_001.rs)

Exercises simple, complex, invalid, cross-level, infrastructure, and recursive parent-local TEST-BOUNDARY-001 scenarios.

### [`test_traceability_001.rs`](../code/test_traceability_001.rs)

Exercises complete, invalid, and infrastructure-boundary requirement and Rust-test traceability.
