# Code

## Role

Certification Code defines content-addressed evidence nodes and DAG validation, certification aggregation, source identity, executed-suite evidence, distributed binding validation, affected closure, and Verified BFG projection.

## Execution

The implementation consumes one stabilized source identity, one already-compiled semantic artifact stack, applicable rule results, one canonical local Rust suite result, and distributed Testing bindings before building evidence nodes in dependency order.

## State

All state is process-local and deterministic. Node IDs are SHA-256 over canonical node bodies excluding their IDs, while historical validity and current-subject freshness remain distinct conclusions.

## Failure Semantics

Missing references, digest corruption, cycles, invalid bindings, unsupported authority, or noncanonical ordering return typed errors; valid negative evidence becomes FAIL, prior-subject evidence becomes STALE, insufficient evidence becomes MISSING, and status precedence is `INVALID > FAIL > STALE > MISSING > PASS`.

## Files

### [`certification.rs`](../code/certification.rs)

Implements Evidence Graph, certification, source identity, execution evidence, affected closure, and Verified BFG semantics.
