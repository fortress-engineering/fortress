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

### [`arch_dependency_001.rs`](../code/arch_dependency_001.rs)

Verifies valid, cyclic, and minimum architecture graphs against ARCH-DEPENDENCY-001.

### [`arch_realization_001.rs`](../code/arch_realization_001.rs)

Verifies every reconciliation state, exact transitive-bypass paths, declared-unobserved truthfulness, invalid observation failure, unsupported coverage, and deterministic conclusions for ARCH-REALIZATION-001.

### [`self_architecture.rs`](../code/self_architecture.rs)

Compiles Fortress's live CCG and verifies that the parent architecture projection remains acyclic.
