# Code

## Role

Transform exact stabilized source bytes into implementation facts that Architecture Evaluation can compare with intent without making the observation process circular.

## Execution

Callers supply a snapshot fingerprint, exact file bytes with expected size and digest, and physical Module territories. The Rust analyzer validates bytes, parses Cargo and Rust syntax, resolves supported namespaces conservatively, records reference provenance, and collapses repeated governed references into one direct Module edge.

## State

Analysis is stateless and owns only process-local ordered source indexes, namespace maps, observations, and coverage issues.

## Failure Semantics

Snapshot mismatches and invalid supported Cargo or Rust syntax return typed errors; invalid ownership and unsupported constructs remain explicit issues; unresolved supported references remain observations and never become conforming facts.

## Files

### [`observation.rs`](../code/observation.rs)

Defines the language-neutral snapshot input, source observation, evidence, normalized dependency, issue, and result contracts.

### [`rust.rs`](../code/rust.rs)

Implements structural Cargo and Rust namespace discovery, source ownership, target classification, facade-preserving resolution, and deterministic observation normalization.
