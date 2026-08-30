# Code

## Role

Provide the shared canonical evidence representation used by rule evaluators without owning any evaluator's semantic judgment.

## Execution

Evaluators construct validated rule metadata, stable violation discrimination, exact occurrence evidence, and evaluator provenance; the model separates stable semantic identity from presentation, computes SHA-256, and returns an immutable sortable finding. Finding governance then performs keyed baseline and exception matching.

## State

The model is stateless and owns only immutable process-local finding values.

## Failure Semantics

Invalid rule or entity identities, tiers, paths, spans, discriminators, baseline authority, exception authority, collisions, or serialization return typed errors and never produce favorable partial governance.

## Files

### [`finding.rs`](../code/finding.rs)

Defines canonical findings, normalized occurrence and provenance inputs, content identity, deterministic ordering, and construction failures.

### [`governance.rs`](../code/governance.rs)

Defines canonical authored baseline and finding-specific exception authority, monotonic pruning with reintroduction history, lifecycle/disposition/enforcement evaluation, and deterministic serialization.
