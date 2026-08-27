# Code

## Role

Provide the shared canonical evidence representation used by rule evaluators without owning any evaluator's semantic judgment.

## Execution

Evaluators construct validated rule metadata, an exact occurrence, and evaluator provenance; the model validates identities and locations, serializes canonical identity material, computes SHA-256, and returns an immutable sortable finding.

## State

The model is stateless and owns only immutable process-local finding values.

## Failure Semantics

Invalid rule or entity identities, tiers, paths, spans, fields, exemptions, or serialization return typed construction errors and never produce partial findings.

## Files

### [`finding.rs`](../code/finding.rs)

Defines canonical findings, normalized occurrence and provenance inputs, content identity, deterministic ordering, and construction failures.
