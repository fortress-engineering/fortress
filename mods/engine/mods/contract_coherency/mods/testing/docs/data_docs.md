# Data

## Role

Persist specification-authored ecosystems that exercise the Contract Coherency compiler across compact and deeply nested boundaries.

## Origin

Fortress maintainers author these fixtures from the Contract v2 and CCG semantic contracts; they are not generated implementation output.

## Semantics

Each fixture is a complete distributed contract ecosystem with explicit expected semantic entity counts and verification inputs.

## Validity

A fixture is valid when every contract is canonically serializable, every identity and reference is well formed, and its expected counts describe the compiled graph exactly.

## Lifecycle

Fixtures change only when supported CCG semantics or their normative conformance expectations change.

## Files

### [`contract_complex.json`](../data/contract_complex.json)

Defines a nested multi-branch ecosystem that stresses capabilities, inheritance, verification, guarantees, distributed Features, and behavioral checkpoints.

### [`contract_simple.json`](../data/contract_simple.json)

Defines a compact provider, CLI consumer, and verifier ecosystem for end-to-end contract compilation.
