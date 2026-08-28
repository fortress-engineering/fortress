# Data

## Role

Certification Data defines authored profile/binding authority and derived Evidence Graph, certification result, and Verified BFG representations.

## Origin

Maintainers author schemas; the Standard owns profiles; Testing Modules author bindings; Fortress derives evidence and certification artifacts.

## Semantics

Schemas preserve evidence authority class, content identity, dependency provenance, exact status algebra, and separate intended, realized, and verification dimensions.

## Validity

All schemas are canonical JSON Schema 2020-12 documents with unique registered identities.

## Lifecycle

Incompatible semantic changes advance schema versions rather than silently changing persisted evidence meaning.

## Files

### [`certification_profile_schema_v1.json`](../data/certification_profile_schema_v1.json)

Defines Certification Profile v1.

### [`certification_result_schema_v1.json`](../data/certification_result_schema_v1.json)

Defines deterministic Certification result v1.

### [`evidence_graph_schema_v1.json`](../data/evidence_graph_schema_v1.json)

Defines content-addressed Evidence Graph v1.

### [`verification_binding_schema_v1.json`](../data/verification_binding_schema_v1.json)

Defines distributed Testing-owned verification bindings.

### [`verified_bfg_schema_v1.json`](../data/verified_bfg_schema_v1.json)

Defines Verified Behavioral Flow Graph v1.
