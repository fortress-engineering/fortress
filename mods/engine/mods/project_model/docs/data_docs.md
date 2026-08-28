# Data

## Role

Persist authored inputs and machine contracts directly consumed by this Module.

## Origin

Maintainers author these files under project, schema, standard, Cargo, or capability authority according to each element description.

## Semantics

The Data declares configuration, structure, identity, applicability, or normative input meaning used by the Module; it is not computational output.

## Validity

Consumers require valid UTF-8 where textual, correct schema or ecosystem syntax, canonical identities and paths, complete required fields, and compatible declared versions.

## Lifecycle

Maintainers update Data through reviewed semantic changes; schema versions change only when representation identity changes, while Git retains superseded history.

## Files

### [`change_schema_v1.json`](../data/change_schema_v1.json)

Defines the version-one machine representation and validation boundary for change records owned by this Module.

### [`project_schema_v2.json`](../data/project_schema_v2.json)

Defines the closed version-two operational project configuration after architectural intent moved to distributed Module contracts.
