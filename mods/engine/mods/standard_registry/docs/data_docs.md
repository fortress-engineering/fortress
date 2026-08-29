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

### [`cert_full_snapshot_v1.json`](../data/cert_full_snapshot_v1.json)

Defines the canonical mandatory `CERT-FULL-SNAPSHOT-V1` profile without project exclusions or grades.

### [`common_schema_v1.json`](../data/common_schema_v1.json)

Defines the version-one machine representation and validation boundary for common records owned by this Module.

### [`rule_schema_v1.json`](../data/rule_schema_v1.json)

Defines the version-one machine representation and validation boundary for rule records, including formal implication and conflict logic, owned by this Module.

The Standard manifest also registers `REPO-REFERENCE-001` from Reference Resolution as the normative relocation-transparency rule; the rule remains owned beside its evaluator rather than duplicated here.

### [`schema_manifest_schema_v1.json`](../data/schema_manifest_schema_v1.json)

Defines the version-one machine representation and validation boundary for schema manifest records owned by this Module.

### [`schema_manifest.json`](../data/schema_manifest.json)

Indexes every active schema by its canonical repository-relative authority path, including the component resolution index v1.

### [`standard_manifest_schema_v1.json`](../data/standard_manifest_schema_v1.json)

Defines the version-one machine representation and validation boundary for standard manifest records owned by this Module.

### [`standard_manifest.json`](../data/standard_manifest.json)

Identifies the exact draft standard edition and complete applicable rule-document set.

### [`std_id_rule.json`](../data/std_id_rule.json)

Carries the draft normative rule record interpreted by the std id evaluator.
