# Data

## Role

The Module owns the canonical schema that consumers use to validate persisted Program Semantic Model documents.

## Origin

The schema is specification-authored as part of the current Fortress draft implementation.

## Semantics

It defines the language-neutral, observed-implementation representation for nominal types, impl blocks, symbols, static and residual call resolution, neutral body/control structure, structured places, state reads, mutations, initial transfers, Module boundaries, graph derivations, coverage, unsupported semantics, and provenance.

## Validity

PSM documents must use the registered schema identity and version, canonical enumerations and required fields, deterministic arrays, repository-relative provenance, and no timestamps or machine paths.

## Lifecycle

The schema changes only when the supported PSM document contract changes; incompatible representations require a new schema version rather than an in-place semantic reinterpretation.

## Files

### [`go_test_schema_v1.json`](../_data/go_test_schema_v1.json)

Defines the separately versioned closed Go test declaration report. It distinguishes
selection and package roles, direct standard testing import syntax, unresolved
parameter identity, invalid declaration forms and package-level barriers.

### [`program_model_schema_v3.json`](../_data/program_model_schema_v3.json)

Defines the retained PSM v3 serialized structure for historical projection interpretation.

### [`program_model_schema_v4.json`](../_data/program_model_schema_v4.json)

Defines the retained PSM v4 structure with explicit executable-symbol execution provenance and deterministic production-capable, test-only, and unknown-provenance coverage counts.

### [`program_model_schema_v5.json`](../_data/program_model_schema_v5.json)

Retains the historical PSM v5 structure with versioned drift-tolerant semantic identities, legacy aliases, stable operation-site identities, and execution-provenance counts.

### [`program_model_schema_v6.json`](../_data/program_model_schema_v6.json)

Defines the current PSM shape with an explicit program context, a per-occurrence syntactic operation inventory, and distinct file observation, opening, parsing, and symbol coverage.

### [`rust_signature_catalog_v1.json`](../_data/rust_signature_catalog_v1.json)

Defines the closed Rust 1.97.1 external constructor and receiver-preserving builder signature set used for bounded `Command` and `OpenOptions` propagation. It contains type facts only; operational effect authority remains in State/Effect Analysis.

### [`rust_signature_schema_v1.json`](../_data/rust_signature_schema_v1.json)

Defines the closed wire shape and pinned toolchain identity for the bounded Rust signature catalog.

### [`go_observation_schema_v1.json`](../_data/go_observation_schema_v1.json)

Defines the standalone exact-source Go native observation report. Its closed dispositions and source spans preserve uncertainty, wire context and process provenance without granting semantic, policy or certification authority.


### [`go_body_schema_v1.json`](../_data/go_body_schema_v1.json)

Defines exact standalone native Go body observations and their scoped result
value domains, including source, producer, context and authority provenance.
Boolean values remain JSON booleans. Integer bounds and exclusions use
canonical signed decimal strings within int64. Unavailable package or body
results retain explicit dispositions.

### [`go_observation_schema_v2.json`](../_data/go_observation_schema_v2.json)

Defines the standalone version 2 Go build-selection projection. It binds the separately admitted target context, complete selected and excluded source inventory, physical declaration and call positions, and the original observed source and authority. No certification obligation is inferred from a matching source.

### [`go_observation_schema_v3.json`](../_data/go_observation_schema_v3.json)

Defines the actual-state, exact-source native Go module observation, its explicit build and module context, physical imports and locations, and verified observation status. Earlier single-package projections keep their historical wire contracts.

### [`go_call_schema_v1.json`](../_data/go_call_schema_v1.json)

Declares the source-bound Go call relation report. Every admitted static
target remains distinct from target body availability and evaluation.
The report references first-order identities without changing their schema.
