# Code

## Role

Provide the shared canonical finding and defeater evidence representations used by rule evaluators without owning any evaluator's semantic judgment.

## Execution

Evaluators construct validated rule metadata, stable violation discrimination, exact occurrence evidence, evaluator provenance, and scoped derived limitations; the model separates stable semantic identity from presentation, computes SHA-256, and returns immutable sortable findings and defeaters. Defeating evidence prevents unsupported favorable conclusions without erasing proven violations, while limiting evidence records bounded enforcement authority. Finding governance then performs keyed baseline and exception matching independently.

## State

The model is stateless and owns only immutable process-local finding values.

## Failure Semantics

Invalid rule or entity identities, tiers, paths, spans, discriminators, baseline authority, exception authority, collisions, or serialization return typed errors and never produce favorable partial governance.

## Files

### [`finding.rs`](../_code/finding.rs)

Defines canonical findings and defeaters, normalized occurrence and provenance inputs, scoped limitation strengths and retirement conditions, content identity, deterministic ordering, and construction failures.

### [`governance.rs`](../_code/governance.rs)

Defines canonical authored baseline and finding-specific exception authority, reintroduction history, lifecycle/disposition/enforcement evaluation, and deterministic serialization. Legacy prune refuses retirement from finding absence alone until comparable subject, authority, and coverage evidence is available.

### [`proof.rs`](../_code/proof.rs)

Defines neutral evidence citations and a versioned proof graph. Structural validation rejects ungrounded or ambiguous premises, cycles, dangling references, and empty favorable support without judging claim truth.
