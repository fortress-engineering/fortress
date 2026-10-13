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

### [`semantic_analysis.rs`](../_code/semantic_analysis.rs)

Exercises the complete Semantic Analysis Feature across contract, lattice, flow, partial-operation, uncertainty, deterministic serialization, and live Fortress cases.

### [`semantic_preparation.rs`](../_code/semantic_preparation.rs)

Verifies R05-001 through R05-005: actual unchanged-round replay, reverse dependent rebuilding with disconnected reuse, extension through changed global stops and widening, conservative reconstruction after call/symbol changes, and bounded retention with cold-identical facts.
