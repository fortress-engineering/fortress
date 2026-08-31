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

### [`filing_system.rs`](../code/filing_system.rs)

Exercises atomic and composite Modules, root profiles, Code flatness, the closed Docs set, bounded Data/Info roles and partitions, canonical versioning, complete inventory, relocation, small-project behavior, and a 300-Module/2,000-partition scale fixture.

### [`project_model.rs`](../code/project_model.rs)

Verifies project configuration loading and rejects duplicate or unsafe observation exclusions, logical contract paths, source bindings, and unsupported schema identities.
