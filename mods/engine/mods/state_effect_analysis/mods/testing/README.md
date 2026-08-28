# Testing

## Purpose

Produce parent-local verification evidence for the state and effect semantics introduced directly by State and Effect Analysis.

## Responsibility

Exercise State Contract validation, typestate classification and transition composition, direct and transitive effects, policy contradictions, uncertainty, and canonical serialization for the immediate parent Feature.

## Scope

### Includes

Positive and negative synthetic PSM fixtures, State and Function Contract fixtures, deterministic summaries and artifacts, exact normalized findings, and live self-analysis execution.

### Excludes

Verification of Program Semantics extraction, Semantic Analysis lattice behavior, unrelated Standard rules, product Features owned by other Modules, and runtime system behavior.

## Relationships

### [Engine](../../../../README.md)

**Types:** `depends_on`

Provides the composed library surface used by this verification executable.

### [State and Effect Analysis](../../README.md)

**Types:** `depends_on`, `verifies`

Supplies the exact parent capability under test and owns the Feature whose requirements this Module verifies.

## Guarantees

Every non-infrastructure test identity maps to exactly one immediate-parent requirement; fixtures remain deterministic and contain no production contract authority.
