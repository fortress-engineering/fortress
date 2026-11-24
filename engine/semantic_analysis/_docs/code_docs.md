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

The scoped native Boolean return comparison consumes an admitted
zero-argument body and an independently supplied expected value. It reuses
the existing return-domain interpreter and Boolean subset and intersection
operations. A sufficient nonempty bound establishes a match or exclusion.
Unknown control, unavailable body bounds, arguments and non-Boolean results
remain unresolved. Authored identity and original authority are resolved by
the caller before using the comparison for project inspection.

Interprets PSM control/value facts, derives recursive summaries, checks contracts and partial operations, records coverage, serializes derived Info, and normalizes PROGRAM-DOMAIN-001 findings. Caller-indexed call views retain every call in its original PSM order, preserving first-match resolution while avoiding repeated scans of unrelated calls.

An impossible-state assertion reached only through unmodeled pattern selection has an unsupported reachability check. This includes a later match arm whose selection depends on an earlier unmodeled pattern and loop entry conditioned on an unmodeled pattern. Supported reachable contradictions still generate findings. Semantic Analysis 2.0.1 records the new producer semantics under the existing artifact schema. Historical artifacts retain their original producer identity.

Prepared evaluation retains exact initialized and synchronous symbol-round domains under current program context, type, contract, body, caller and reverse-dependency bindings. A changed provider invalidates every dependent trajectory. Replayed units use their original round index; missing later rounds execute the same transfer, join and widening functions through the current global stop and cap. Final summaries, checks, diagnostics, headers and findings are always rebuilt from current inputs. Configurable owner retention caps bound admitted round payloads; omitted caches cause reconstruction and never change domain meaning.

The same statement interpreter can evaluate an explicitly admitted native
scalar body against its declared parameter premises. The returned result is a
conservative type-bound set of possible return values. Go fixed-width int64
and bounded Python literal values have distinct domain identifiers. A residual
control path or an opaque result has no inferred domain. Native bodies are
excluded from governed Rust function contracts and findings. Their evaluation
is not certification or proof of runtime execution.

### [`native_return_contract.rs`](../_code/native_return_contract.rs)

Reads the exact supported version of native Boolean return requirements. It
bounds JSON decoding and validates canonical format and distinct sorted
callable references. Snapshot Governance owns original territory selection
and exact body linkage. The reader has no source mutation capability.
