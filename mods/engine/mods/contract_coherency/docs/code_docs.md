# Code

## Role

Compile authored contract and standard facts into the canonical semantic graph used by downstream Fortress evaluation.

## Execution

Callers provide stabilized repository files, the exact selected standard, and optional supported verification facts; the compiler validates local and ecosystem intent, derives fixed-point closures, records provenance, constructs coherency findings, and serializes only after deterministic completion.

## State

Compilation is stateless and owns only process-local immutable source indexes, ordered graph facts, and derivation records.

## Failure Semantics

Invalid authored facts produce sorted typed CCG violations; supported logical contradictions produce an incoherent graph without choosing a winner; serialization and digest failures return typed errors rather than partial output.

## Files

### [`contract.rs`](../code/contract.rs)

Defines canonical Module Contract v2/v3 syntax and the single repository-wide semantic compiler, preserving behavioral and semantic-policy declarations while validating only local and ecosystem declaration integrity rather than downstream conformance semantics.

### [`graph.rs`](../code/graph.rs)

Defines CCG semantic facts, derivations, logical closure, canonical serialization, digest calculation, and unsupported-semantics reporting.
