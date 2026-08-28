# Code

## Role

The Code provides parent-local executable verification of Function Contract, domain lattice, abstract interpretation, fixed-point, contradiction, determinism, and self-analysis behavior.

## Execution

Cargo invokes the explicit semantic_analysis test target, which constructs snapshot-bound Rust PSM fixtures, resolves canonical contracts, executes semantic analysis, and compares exact domains, coverage states, findings, and canonical bytes.

## State

Tests use deterministic process-local fixture models and temporary values only; no persistent state is mutated.

## Failure Semantics

Any incorrect domain operation, missed supported contradiction, false proof, ownership breach, nondeterministic output, stale self artifact, or unexpected live finding fails the parent-local test target.

## Files

### [`semantic_analysis.rs`](../code/semantic_analysis.rs)

Exercises the complete Semantic Analysis Feature across contract, lattice, flow, partial-operation, uncertainty, deterministic serialization, and live Fortress cases.
