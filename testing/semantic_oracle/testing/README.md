# Semantic Reference Oracle Testing

## Purpose

Verify the pure reference interpreter against independently authored literal controls.

## Responsibility

Check primitive instruction meaning, reachability, effect unions, policy precedence, uncertainty, nonapplicability, absent policy and production eligibility.

## Scope

### Includes

Literal integer and boolean truth-table controls without Fortress imports or held-out candidate evaluation.

### Excludes

Production evaluator authority, corpus scoring, inferred expected answers, I/O, process execution, empirical accuracy and statistical assurance.

## Relationships

### [Semantic Reference Oracle](../README.md)

**Types:** `depends_on`, `verifies`

Supplies the pure implementation and owns the Feature exercised by these local tests.

## Guarantees

Expected values are literal protocol states. A disagreement fails the test; neither production output nor observed effects rewrite the reference expectation.
