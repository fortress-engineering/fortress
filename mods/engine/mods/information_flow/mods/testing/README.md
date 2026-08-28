# Testing

## Purpose

Information Flow Testing exists to prove the security-classification behavior introduced directly by its parent Module.

## Responsibility

This Module supplies parent-local evidence for policy validation, conservative propagation, sink enforcement, trusted transitions, determinism, and live analysis.

## Scope

### Includes

It includes positive and negative policy, contract, propagation, field, call, security-boundary, coverage, and freshness fixtures.

### Excludes

It excludes product capability ownership, descendant Feature verification, source parsing, and certification claims.

## Relationships

### [Engine](../../../../README.md)

**Types:** `depends_on`

Provides the composed library surface used by this verification executable.

### [Information Flow](../../README.md)

**Types:** `depends_on`, `verifies`

Provides the exact parent capability and Feature boundary exercised by this Testing Module.

## Guarantees

Fixtures remain deterministic, parent-local, explicitly mapped to one requirement each, and do not silently convert unsupported security semantics into passing evidence.
