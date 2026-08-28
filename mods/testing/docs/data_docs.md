# Data

## Role

Persist authored root-Testing verification bindings consumed by Certification.

## Origin

The root Testing Module authors bindings only for verification obligations owned by the root Fortress Feature.

## Semantics

Bindings map current semantic obligation identities to exact parent-local Test IDs without asserting that execution occurred or passed.

## Validity

Every obligation and Test ID must exist, remain canonically sorted, and belong to this Testing boundary.

## Lifecycle

Bindings change when current generated obligation identity or the truthful parent-local verification evidence changes.

## Files

### [`verification_bindings.json`](../data/verification_bindings.json)

Binds root Fortress audit-Feature verification obligations to its exact audit-flow test.
