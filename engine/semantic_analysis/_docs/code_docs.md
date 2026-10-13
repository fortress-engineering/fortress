# Code

## Role

The Code defines Function Contract resolution, the semantic-domain lattice, the PSM-consuming abstract interpreter, fixed-point summaries, coverage states, counter-domain conclusions, and rule-facing findings.

## Execution

The loader validates distributed contracts against PSM ownership and types. The interpreter initializes every function from its authored preconditions or full static domains, evaluates supported neutral body structure, composes callee summaries, joins branches, widens loops and recursion, then performs a final deterministic proof pass.

## State

Canonical analysis uses process-local immutable indexes, evolving environments and fixed-point summaries from one PSM and one Function Contract set. Optional preparation retains bounded exact round payloads separately from the finished immutable evaluation.

## Failure Semantics

Invalid or foreign contracts fail loading. Supported domain contradictions become normalized findings. Unsupported expressions, dispatch, aliases, effects, and domain classes remain explicit partial, unknown, or unsupported coverage and conservatively retain possibilities.

## Files

### [`function_contract.rs`](../_code/function_contract.rs)

Loads canonical distributed Function Contract v3/v4 sources, enforces symbol ownership and static-type compatibility for value domains, preserves state/effect and information-flow obligations for downstream owners, and computes their input digest.

### [`domain.rs`](../_code/domain.rs)

Implements deterministic value-domain subset, intersection, join, difference, bottom/top, and widening semantics.

### [`semantic.rs`](../_code/semantic.rs)

Interprets PSM control/value facts, derives recursive summaries, checks contracts and partial operations, records coverage, serializes derived Info, and normalizes PROGRAM-DOMAIN-001 findings. Caller-indexed call views retain every call in its original PSM order, preserving first-match resolution while avoiding repeated scans of unrelated calls.

Prepared evaluation retains exact initialized and synchronous symbol-round domains under current program context, type, contract, body, caller and reverse-dependency bindings. A changed provider invalidates every dependent trajectory. Replayed units use their original round index; missing later rounds execute the same transfer, join and widening functions through the current global stop and cap. Final summaries, checks, diagnostics, headers and findings are always rebuilt from current inputs. Configurable owner retention caps bound admitted round payloads; omitted caches cause reconstruction and never change domain meaning.
