# Code

## Role

The test Code proves the Information Flow Feature requirements at the immediate parent boundary.

## Execution

Cargo invokes the explicit information_flow test target against synthetic PSM inputs and the live repository.

## State

Fixtures use temporary process-local inputs and do not persist mutable test state.

## Failure Semantics

Any policy, flow, finding, diagnostic, determinism, or freshness mismatch fails the corresponding test.

## Files

### [`information_flow.rs`](../code/information_flow.rs)

Exercises policy algebra, source/sink propagation, trusted transitions, field flow, uncertainty, rule findings, determinism, and live integration.
