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

### [`documentation_rule.json`](../data/documentation_rule.json)

Carries the draft normative rule record interpreted by the documentation evaluator.

### [`module_rule.json`](../data/module_rule.json)

Carries the draft normative rule record interpreted by the module evaluator.

### [`ownership_rule.json`](../data/ownership_rule.json)

Carries the draft normative rule record interpreted by the ownership evaluator.

### [`repository_snapshot_schema_v1.json`](../data/repository_snapshot_schema_v1.json)

Defines the version-one machine representation and validation boundary for repository snapshot records owned by this Module.

### [`snapshot_audit_schema_v1.json`](../data/snapshot_audit_schema_v1.json)

Defines the version-one machine representation and validation boundary for snapshot audit records owned by this Module.

### [`snapshot_finding_schema_v1.json`](../data/snapshot_finding_schema_v1.json)

Defines the version-one machine representation and validation boundary for snapshot finding records owned by this Module.

### [`traceability_rule.json`](../data/traceability_rule.json)

Carries the draft normative rule record interpreted by the traceability evaluator.
