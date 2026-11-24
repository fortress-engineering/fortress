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

### [`native_inventory.rs`](../_code/native_inventory.rs)

Freezes complete Go and Python physical inventories under R01-004, R02-005,
R03-006, and R04-004. Checks exact UTF-8 and CRLF bytes, nested portable
paths, exclusion of a native source subtree, same-size drift and exact
restoration, and an independently known one-byte source quota excess.
Each case exercises the ordinary file boundary in a disposable repository.
The existing R03-003 link control and Snapshot Governance R24-006 and
R24-007 remain the filesystem link, reparse point, and collision controls.
