# Code

## Role

The Code defines Function Contract resolution, the semantic-domain lattice, the PSM-consuming abstract interpreter, fixed-point summaries, coverage states, counter-domain conclusions, and rule-facing findings.

## Execution

The loader validates distributed contracts against PSM ownership and types. The interpreter initializes every function from its authored preconditions or full static domains, evaluates supported neutral body structure, composes callee summaries, joins branches, widens loops and recursion, then performs a final deterministic proof pass.

## State

Analysis is stateless beyond process-local immutable indexes, evolving abstract environments, and fixed-point summaries derived from one PSM and one canonical Function Contract set.

## Failure Semantics

Invalid or foreign contracts fail loading. Supported domain contradictions become normalized findings. Unsupported expressions, dispatch, aliases, effects, and domain classes remain explicit partial, unknown, or unsupported coverage and conservatively retain possibilities.

## Files

### [`function_contract.rs`](../code/function_contract.rs)

Loads canonical distributed Function Contract v2 sources, enforces symbol ownership and static-type compatibility for value domains, preserves state/effect obligations for the downstream owner, and computes their input digest.

### [`domain.rs`](../code/domain.rs)

Implements deterministic value-domain subset, intersection, join, difference, bottom/top, and widening semantics.

### [`semantic.rs`](../code/semantic.rs)

Interprets PSM control/value facts, derives recursive summaries, checks contracts and partial operations, records coverage, serializes derived Info, and normalizes PROGRAM-DOMAIN-001 findings.
