# State and Effect Analysis

## Purpose

Establish whether supported program objects move through permitted modeled states and whether functions remain within their authored effect boundaries.

## Responsibility

Consume the canonical Program Semantic Model, Semantic Analysis value domains, distributed State Contracts, and Function Contract v2 obligations to derive conservative typestate transitions and transitive effect summaries with explicit uncertainty and provenance.

## Scope

### Includes

Owned nominal types, direct fields, receiver and owned-state reads and writes, conservative typestate classification, receiver transitions, resolved-call composition, SCC-aware transitive effect closure, state precondition and postcondition checks, opt-in effect policies, canonical derived Info, and normalized findings.

### Excludes

Rust parsing, a parallel value-domain lattice, arbitrary heap and alias proof, interior mutability, global state, concurrency, external-system semantics, taint, capability realization, BFG realization, symbolic execution, and certification.

## Relationships

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Supplies the normalized finding authority used for supported state and effect contradictions.

### [Program Semantics](../program_semantics/README.md)

**Types:** `depends_on`

Supplies snapshot-bound structured places, state reads, mutations, calls, symbols, and nominal type ownership without interpreting their safety.

### [Semantic Analysis](../semantic_analysis/README.md)

**Types:** `depends_on`

Supplies the canonical static-type-relative domain lattice reused by State predicates and field-domain interpretation.

## Guarantees

State and effect conclusions are deterministic and conservative; unsupported alias or external behavior widens coverage rather than implying safety; authored state postconditions are proved rather than trusted; effect policy is opt-in; and only contradictions supported by implemented semantics become findings.
