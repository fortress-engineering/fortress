# Code

## Role

Transform exact stabilized source bytes into implementation facts that Architecture Evaluation can compare with intent without making the observation process circular.

## Execution

Callers supply a snapshot fingerprint, exact file bytes with expected size and digest, and one canonically resolved ownership relation. Physical Module `code/` containment and authored logical path bindings produce declared ownership; unmatched source retains deterministic Cargo analysis ownership. The Rust analyzer consumes that relation without reinterpreting paths. Cargo observation also records mechanical library, proc-macro, binary, build-script, integration-test, benchmark, and example source roles for profile consumers without turning those roles into Module intent.

## State

Analysis is stateless and owns only process-local ordered source indexes, namespace maps, observations, and coverage issues.

## Failure Semantics

Snapshot mismatches and invalid supported Cargo or Rust syntax return typed errors; invalid ownership and unsupported constructs remain explicit issues; unresolved supported references remain observations and never become conforming facts.

## Files

### [`observation.rs`](../code/observation.rs)

Defines the language-neutral snapshot input, source observation, evidence, normalized dependency, issue, and result contracts.

### [`rust.rs`](../code/rust.rs)

Implements structural Cargo and Rust namespace discovery, source ownership, target classification, facade-preserving resolution, and deterministic observation normalization.
