# Semantic Analysis

## Purpose

Establish whether value states admitted at one supported program boundary remain valid at every downstream boundary they can reach.

## Responsibility

Consume the canonical Program Semantic Model and distributed Function Contracts, propagate conservative semantic value domains through supported intra- and interprocedural flow to a deterministic fixed point, and expose supported contradictions with exact provenance and counter-domains.

## Scope

### Includes

Function Contract v3/v4 loading for value-domain obligations, static-type-relative domain validation, Boolean and integer lattices, Option and Result states, enum variants, tuple products, branch refinement, recursive fixed points, call precondition checks, postcondition proofs, modeled partial operations, impossible-state reachability, property-specific coverage, canonical summaries, findings, serialization, and digesting.

### Excludes

Rust parsing or call extraction, automatic contract inference, Function Contract state/effect/information-flow interpretation, BFG realization, heap alias analysis, concurrency, arbitrary dynamic dispatch, string-language proof, security flow proof, natural-language inference, and symbolic theorem proving.

## Relationships

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Supplies the shared normalized finding contract used to report supported PROGRAM-DOMAIN-001 contradictions without embedding rule diagnostics in the domain model.

### [Program Semantics](../program_semantics/README.md)

**Types:** `depends_on`

Supplies exact snapshot-bound executable identities, static types, calls, value transfers, and neutral control structure interpreted by this Module.

## Guarantees

Absent preconditions admit the full static type domain; uncertainty only widens possible states; supported recursive analysis converges deterministically; authored postconditions are proved rather than trusted; findings include representable abstract counter-domains; and unsupported semantics never become evidence of safety.
