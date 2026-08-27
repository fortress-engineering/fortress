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

### [`repository_grammar.rs`](../code/repository_grammar.rs)

Checks the complete physical repository against the recursive Module grammar independently of CLI orchestration.

### [`self_model.rs`](../code/self_model.rs)

Checks root operational configuration, command registry agreement, resolved contract dependency acyclicity, and truthful non-certification state.
