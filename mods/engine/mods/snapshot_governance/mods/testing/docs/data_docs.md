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

### [`documentation_boundary.json`](../data/documentation_boundary.json)

Provides specification-authored boundary conformance data for documentation behavior.

### [`documentation_invalid.json`](../data/documentation_invalid.json)

Provides specification-authored invalid conformance data for documentation behavior.

### [`documentation_valid.json`](../data/documentation_valid.json)

Provides specification-authored valid conformance data for documentation behavior.

### [`module_boundary.json`](../data/module_boundary.json)

Provides specification-authored boundary conformance data for module behavior.

### [`module_expected.json`](../data/module_expected.json)

Provides specification-authored expected conformance data for module behavior.

### [`module_invalid.json`](../data/module_invalid.json)

Provides specification-authored invalid conformance data for module behavior.

### [`module_valid.json`](../data/module_valid.json)

Provides specification-authored valid conformance data for module behavior.

### [`ownership_boundary.json`](../data/ownership_boundary.json)

Provides specification-authored boundary conformance data for ownership behavior.

### [`ownership_expected.json`](../data/ownership_expected.json)

Provides specification-authored expected conformance data for ownership behavior.

### [`ownership_invalid.json`](../data/ownership_invalid.json)

Provides specification-authored invalid conformance data for ownership behavior.

### [`ownership_valid.json`](../data/ownership_valid.json)

Provides specification-authored valid conformance data for ownership behavior.

### [`traceability_boundary.json`](../data/traceability_boundary.json)

Provides specification-authored boundary conformance data for traceability behavior.

### [`traceability_expected.json`](../data/traceability_expected.json)

Provides specification-authored expected conformance data for traceability behavior.

### [`traceability_invalid.json`](../data/traceability_invalid.json)

Provides specification-authored invalid conformance data for traceability behavior.

### [`traceability_valid.json`](../data/traceability_valid.json)

Provides specification-authored valid conformance data for traceability behavior.

### [`testing_cases.json`](../data/testing_cases.json)

Defines deterministic negative mutations for missing, misplaced, cross-level, duplicated, and noncanonical Testing boundaries.

### [`testing_complex.json`](../data/testing_complex.json)

Defines a multi-level ecosystem where atomic, compositional, and root Features are verified only by their direct parent-local Testing Modules.

### [`testing_simple.json`](../data/testing_simple.json)

Defines a compact provider, CLI, and root utility ecosystem with exact recursive Testing ownership and legitimate unmapped infrastructure evidence.
