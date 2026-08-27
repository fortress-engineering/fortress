# Architecture Evaluation Testing

## Purpose

This verification Module exists to prove only the Architecture Evaluation Feature introduced directly by its immediate parent Module.

## Responsibility

Exercise the parent architecture projection and dependency evaluator against canonical CCG facts, and map findings exclusively to parent-owned requirements.

## Scope

### Includes

Rust verification code, dependency fixtures, and the live Fortress CCG projection providing evidence for the immediate parent's local Feature.

### Excludes

Ancestor, sibling, or descendant Feature requirements; README synchronization; source dependency extraction; CCG compilation; and documentation evaluation owned elsewhere.

## Relationships

### [Architecture Evaluation](../../README.md)

**Types:** `depends_on`, `verifies`

Exercises the parent CCG architecture projection and ARCH-DEPENDENCY-001 evaluator.

## Guarantees

The suite is deterministic, CCG projections preserve canonical dependency identities, and expected findings remain specification-authored rather than generated from implementation output.
