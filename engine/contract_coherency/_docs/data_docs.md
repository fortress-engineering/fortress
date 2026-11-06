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

### [`graph_schema_v1.json`](../_data/graph_schema_v1.json)

Defines the deterministic serialized Contract Coherency Graph v1 representation.

### [`module_contract_schema_v2.json`](../_data/module_contract_schema_v2.json)

Defines canonical authored Module Contract v2 syntax.

### [`module_contract_schema_v3.json`](../_data/module_contract_schema_v3.json)

Defines Module Contract v3 by adding explicit, closed capability/effect policy while retaining v2 as the loadable undeclared-policy form.

### [`module_contract_schema_v4.json`](../_data/module_contract_schema_v4.json)

Adds explicit native verification intent for real Feature Requirements. Empty legacy Test ID lists require that new intent; v2/v3 retain their original mandatory Test ID semantics. Intent neither observes execution nor establishes success.

### [`graph_schema_v2.json`](../_data/graph_schema_v2.json)

Projects authored external verification intent separately from declared Fortress Test IDs and source-observed support. A native intent alone never completes observed or executed coverage. The historical graph v1 schema is retained unchanged.
