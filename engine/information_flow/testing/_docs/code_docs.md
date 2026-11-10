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

### [`information_flow.rs`](../_code/information_flow.rs)

Exercises policy algebra, source/sink propagation, trusted transitions, field flow, uncertainty, rule findings, determinism, and live integration.

The assignment-and-return control also exercises two functions with identically named parameters and local bindings but different integrity labels. Each return and violation must remain attached to its complete symbol identity when binding edges use keyed candidate lookup.

### [`operation_flow.rs`](../_code/operation_flow.rs)

Tests exact operation binding, optional and Module-scoped selection, multiple facets, safe and prohibited propagation, shared-call and callback uncertainty, declared transforms, forged trust, cold/prepared equivalence, deterministic RPC/CLI projections, cancellation, version rejection and secret-literal omission. It compiles only frozen test-owned standalone source controls through the pinned Rust toolchain in an owned bounded workspace. It does not execute the repository under inspection or infer target application test execution.
