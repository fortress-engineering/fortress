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

### [`contract.rs`](../_code/contract.rs)

Defines canonical Module Contract v2/v3/v4 syntax and the single repository-wide semantic compiler. Native execution intent is explicit in v4; v2/v3 retain their original mandatory Test IDs. Behavioral, semantic-policy and verification intent remain authoring facts rather than observed execution or downstream conformance conclusions.

### [`graph.rs`](../_code/graph.rs)

Defines CCG v2 semantic facts, derivations, logical closure, canonical serialization, digest calculation, and unsupported-semantics reporting. Native verification intent has its own projection and never invents Test IDs or completes source-observed support.

The native `module_contract_schema` metadata accessor exposes the current owned
schema for readable authoring guidance. Clients consume that API rather than
including a cross-Module physical schema path; canonical validation remains owned
by `ModuleContract`.
