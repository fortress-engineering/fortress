# Data

## Role

Persist specification-authored inputs needed to verify the parent capability at valid, invalid, and boundary conditions.

## Origin

Maintainers author these fixtures from the governing rule and requirement contracts; implementation output does not generate their expected meaning.

## Semantics

Each direct file represents a controlled conformance input or expected result consumed only by the verification code in this Module.

## Validity

A fixture is valid for consumption when its encoding, structure, stable identities, paths, and expected semantics match the scenario declared by its test.

## Lifecycle

Fixtures change deliberately with compatible rule clarification or an explicit standard-contract change and remain reviewable beside their verifier.

## Files

### [`observation_cases.json`](../_data/observation_cases.json)

Defines direct deterministic fixture cases used to verify observation behavior without a nested fixture taxonomy.

### [`native_cases.json`](../_data/native_cases.json)

Preserves two independently recorded physical inventories with five files
each. The Go tree contains a module, workspace, implementation, test source,
and empty asset. The Python tree contains a project manifest, nested package
and implementation, test source, and empty asset. The fixture retains the
frozen original byte inventory digest, per-file sizes and SHA-256 identities,
expected exact manifest and immutable view identities, and a same-size
source change for each ecosystem. CLI artifact modeling and semantic analysis
have separate qualification evidence.
