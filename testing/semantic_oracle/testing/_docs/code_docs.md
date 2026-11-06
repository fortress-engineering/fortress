# Code

## Role

Verify the independently authored reference language and policy truth table.

## Execution

Cargo invokes the explicit reference-oracle test target, which imports only the parent helper and primitive language operations.

## State

All inputs and expected values are local literals. No external resource or held-out candidate observation is consumed.

## Failure Semantics

An unexpected primitive effect, policy truth or blocking result fails the relevant requirement test.

## Files

### [`oracle.rs`](../_code/oracle.rs)

Checks literal opcode meaning and reachable effect unions, then tests authorization, invalid policy, missing subject/support, unknown effects, sufficient positives and production eligibility.
