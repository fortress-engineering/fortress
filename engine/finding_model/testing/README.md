# Finding Model Testing

## Purpose

Verify the neutral proof graph and evidence-reference boundary used by claim and certification consumers.

## Responsibility

Exercise structural proof validity, canonical set order, complete reference resolution, cycle rejection, and refusal of empty favorable support.

## Scope

### Includes

Black-box proof contract vectors with stable synthetic identities.

### Excludes

Claim truth, trust in an evidence producer, certification decisions, and historical state comparison.

## Relationships

### [Engine](../../README.md)

**Types:** `depends_on`

Supplies the composed public Rust facade exercised by these tests.

### [Finding Model](../README.md)

**Types:** `depends_on`, `verifies`

Owns the proof shape and the Feature verified by this direct Testing child.

## Guarantees

Each declared Test ID is deterministic and does not infer favorable claim judgment from structural support alone.
