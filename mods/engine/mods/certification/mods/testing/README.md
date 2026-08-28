# Certification Testing

## Purpose

Provide parent-local evidence for Certification.

## Responsibility

Verify content addressing, DAG integrity, status algebra, suite eligibility, distributed bindings, trusted assertions, source exclusions, affected closure, and Verified BFG projection.

## Scope

### Includes

Deterministic positive and negative semantic fixtures.

### Excludes

Production certification authority and remote execution.

## Relationships

### [Engine](../../../../README.md)

**Types:** `depends_on`

Provides the composed Certification library surface exercised by this independent test target.

### [Certification](../../README.md)

**Types:** `depends_on`, `verifies`

Verifies the parent Certification Feature.

## Guarantees

Negative fixtures assert normalized outcomes rather than accepting arbitrary failures.
