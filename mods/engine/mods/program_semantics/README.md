# Program Semantics

## Purpose

Provide a trustworthy implementation-semantic substrate beneath architectural Modules and intended Feature behavior.

## Responsibility

Analyze exact snapshot-bound source into deterministic language-neutral facts about executable symbols, typed interfaces, calls, initial value transfers, and supported cross-Module execution boundaries without treating implementation facts as authored intent.

## Scope

### Includes

Stable Cargo package and target interpretation, structural Rust syntax analysis, canonical executable identities, recursive type normalization, conservative static call resolution, call coverage states, call-graph derivations, initial value-transfer topology, neutral body/control structure for downstream reasoning, Testing classification, analyzer coherency, provenance, canonical serialization, and deterministic digesting.

### Excludes

Behavioral checkpoint realization, capability-to-symbol mapping, Function Contract interpretation, value-domain reasoning, function correctness, general effects, alias/heap flow, symbolic execution, dynamic-dispatch proof, security flow proof, and automatic contract generation.

## Relationships

### [Contract Coherency](../contract_coherency/README.md)

**Types:** `depends_on`

Supplies canonical Module identities, containment, and verification topology used to classify source ownership without importing program facts into the CCG.

### [Implementation Observation](../implementation_observation/README.md)

**Types:** `depends_on`

Supplies the exact snapshot-bound source substrate and the broader observed Module dependency projection against which cross-Module call facts are reconciled.

## Guarantees

Identical semantic inputs produce byte-identical PSM documents and digests; every fact retains deterministic source provenance; exact resolution is never assigned to unsupported or ambiguous Rust semantics; Testing and production symbols remain distinguishable; and no PSM fact is represented as architecture or behavioral intent.
