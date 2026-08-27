# Data

## Role

Own the schemas that define authored Module Contract input and derived CCG output representations.

## Origin

Fortress maintainers author these schemas as part of the draft standard implementation boundary.

## Semantics

The Module Contract schema constrains distributed architectural intent, while the CCG schema constrains its deterministic derived semantic projection without becoming another authored authority.

## Validity

Both schemas must be valid JSON Schema 2020-12 documents with unique stable URNs, closed object shapes, explicit required fields, and references that resolve through the schema registry.

## Lifecycle

Schema identity changes only for representation-breaking changes; compatible clarification remains within the active draft and Git preserves superseded history.

## Files

### [`graph_schema_v1.json`](../data/graph_schema_v1.json)

Defines the deterministic serialized Contract Coherency Graph v1 representation.

### [`module_contract_schema_v2.json`](../data/module_contract_schema_v2.json)

Defines canonical authored Module Contract v2 syntax.
