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

### [`filing_profile_schema_v1.json`](../data/filing_profile_schema_v1.json)

Defines the version-one closed registry shape for root entries classified as ecosystem-required or generated-allowed, ecosystem-owned Data/Info filenames, and mechanically required Code namespace structures.

### [`filing_system_profiles.json`](../data/filing_system_profiles.json)

Registers the Git, GitHub, Cargo, and Fortress-derived physical surfaces currently admitted without hard-coding those ecosystem exceptions into the universal filing engine.

### [`project_schema_v2.json`](../data/project_schema_v2.json)

Defines the closed version-two operational project configuration after architectural intent moved to distributed Module contracts.

### [`project_schema_v3.json`](../data/project_schema_v3.json)

Defines operational observation policy plus a narrow stable-ID index for logical Module contract locations and deterministic source path bindings.
