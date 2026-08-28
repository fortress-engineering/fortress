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

### [`program_model_schema_v3.json`](../data/program_model_schema_v3.json)

Defines the canonical PSM v3 serialized structure and its closed object grammar.
