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

### [`observation_cases.json`](../data/observation_cases.json)

Defines direct deterministic fixture cases used to verify observation behavior without a nested fixture taxonomy.
