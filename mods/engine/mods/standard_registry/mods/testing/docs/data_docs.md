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

### [`std_id_boundary.txt`](../data/std_id_boundary.txt)

Provides the specification-authored boundary stable identity input for STD-ID-001.

### [`std_id_expected.json`](../data/std_id_expected.json)

Provides specification-authored expected conformance data for std id behavior.

### [`std_id_invalid.txt`](../data/std_id_invalid.txt)

Provides the specification-authored invalid stable identity input for STD-ID-001.

### [`std_id_valid.txt`](../data/std_id_valid.txt)

Provides the specification-authored valid stable identity input for STD-ID-001.
