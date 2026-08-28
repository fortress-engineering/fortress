# Testing

## Purpose

Provide parent-local evidence for the semantic-analysis behavior introduced by Semantic Analysis.

## Responsibility

Verify Function Contract validation, value-domain operations, supported refinement and fixed-point propagation, semantic contradictions, coverage truthfulness, deterministic artifacts, and live Fortress self-analysis without claiming proof of unsupported semantic classes.

## Scope

### Includes

Positive, negative, boundary, recursive, partial-operation, ownership, counter-domain, determinism, schema, and self-application cases for AF-SEMANTIC-ANALYSIS-0001.

### Excludes

Program Semantics extraction tests, tests for ancestor or sibling Features, BFG realization, generalized symbolic execution, runtime evidence, and product capability ownership.

## Relationships

### [Engine](../../../../README.md)

**Types:** `depends_on`

Provides the public library boundary used to execute parent-local semantic-analysis verification.

### [Semantic Analysis](../../README.md)

**Types:** `depends_on`, `verifies`

Supplies the capability under test and is the immediate parent whose complete local Feature subject is verified here.

## Guarantees

Every non-infrastructure Test ID maps to exactly one Semantic Analysis requirement, fixtures assert exact semantic conclusions, and unsupported behavior remains uncertainty rather than passing evidence.
