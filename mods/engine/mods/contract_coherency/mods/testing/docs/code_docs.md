# Code

## Role

Exercise the directly owned Contract Coherency compiler against specification-authored semantic ecosystems and Fortress itself.

## Execution

Cargo invokes the explicit integration-test target, which compiles deterministic in-memory or repository-backed graphs and compares exact facts, violations, provenance, bytes, and digests.

## State

Tests are stateless apart from process-local fixtures and temporary external outputs.

## Failure Semantics

Any missing fact, incorrect closure, imprecise violation, provenance gap, nondeterminism, or stale self-CCG fails the test target.

## Files

### [`contract_coherency_graph.rs`](../code/contract_coherency_graph.rs)

Provides the parent-local structural, logical, deterministic, provenance, and self-application CCG conformance suite.
