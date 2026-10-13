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

### [`repository_observation.rs`](../_code/repository_observation.rs)

Materializes disposable fixture repositories and verifies deterministic observation facts and boundaries.

### [`bounded_observation.rs`](../_code/bounded_observation.rs)

Verifies R04-001 through R04-003: bounded and ordinary canonical equality for admitted inputs, source/file admission rejection before unbounded reads, and total-entry/path admission including empty-directory inventories. Resident-enabled retained-input behavior is additionally exercised through the production composition lifecycle controls.
