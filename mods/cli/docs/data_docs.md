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

### [`Cargo.toml`](../data/Cargo.toml)

Declares the fortress-cli package and explicit library, binary, and process-level verification targets.

### [`command_schema_v1.json`](../data/command_schema_v1.json)

Defines the version-one machine contract for command declarations.

### [`commands.json`](../data/commands.json)

Declares the exact implemented command instances exposed by the native registry.
