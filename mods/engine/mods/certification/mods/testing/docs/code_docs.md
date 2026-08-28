# Code

## Role

Contains Certification conformance tests.

## Execution

Cargo invokes the explicit certification target against deterministic in-memory positive and negative fixtures.

## State

Fixtures are process-local and create no persistent evidence or mutable repository state.

## Failure Semantics

Any graph, digest, cycle, status, eligibility, binding, assertion, source-exclusion, affected-closure, or Verified BFG mismatch fails its mapped parent Requirement.

## Files

### [`certification.rs`](../code/certification.rs)

Exercises Certification v1 conformance.
