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

### [`Cargo.toml`](../_data/Cargo.toml)

Declares the fortress-cli package and explicit library, binary, and process-level verification targets.

### [`command_schema_v1.json`](../_data/command_schema_v1.json)

Defines the version-one machine contract for command declarations.

### [`commands.json`](../_data/commands.json)

Declares the exact implemented command instances exposed by the native registry.

### [`offline_verifier_v1.txt`](../_data/offline_verifier_v1.txt)

Embeds the exact standalone public Python consumer from Testing as an immutable CLI resource. Regenerate this byte-for-byte copy from `testing/_code/verify_bundle.py` when that consumer changes. The CLI regression gate rejects drift; the adapter executes these reviewed bytes in isolated Python, never a candidate repository script. This resource introduces no second implementation or authority.
