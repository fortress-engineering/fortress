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

### [`contract_complex.json`](../data/contract_complex.json)

Defines a nested multi-branch ecosystem that stresses capabilities, inheritance, verification, guarantees, distributed Features, and behavioral checkpoints.

### [`contract_simple.json`](../data/contract_simple.json)

Defines a compact provider, CLI consumer, and verifier ecosystem for end-to-end contract resolution.

### [`dependency_boundary.json`](../data/dependency_boundary.json)

Provides specification-authored boundary conformance data for dependency behavior.

### [`dependency_expected.json`](../data/dependency_expected.json)

Provides specification-authored expected conformance data for dependency behavior.

### [`dependency_invalid.json`](../data/dependency_invalid.json)

Provides specification-authored invalid conformance data for dependency behavior.

### [`dependency_valid.json`](../data/dependency_valid.json)

Provides specification-authored valid conformance data for dependency behavior.
