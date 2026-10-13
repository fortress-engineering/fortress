# Code

## Role

The directly owned Code validates state and effect-summary authority and derives conservative typestate and effect consequences from existing PSM and Semantic Analysis facts.

## Execution

Snapshot Governance loads distributed contracts after compiling one PSM and Semantic Analysis result, then invokes the state/effect evaluator once before standard-rule dispatch and derived artifact serialization. Standard Registry supplies the installed operation-summary catalog through its public provider. Operation-summary selection binds the resolved operation to its dependency or toolchain source, version, target, features, and type arguments before a qualified upper bound is applied.

## State

Analysis state is process-local and immutable after construction; fixed-point work maps are deterministic and no repository state is mutated.

Synchronous closure snapshots and retained trajectories share immutable effect-evidence maps, witness keys and witness records. Copying a map for an admitted change clones immutable key/record handles; it does not duplicate every existing string and call chain. Keys and records have no mutable shared access. Each retained position still receives the original complete serialized-evidence charge, with no sharing discount. A witness insertion or replacement detaches the current map before mutation; unchanged or rejected witnesses leave the prior allocation intact. Canonical summaries still contain the complete owned evidence. Ordered propagation, changed flags, provenance, the four-witness limit, uncertainty, iteration limits and conservative retention charges are unchanged. Sharing is an allocation optimization, never a dependency proof or permission to omit a round. Prepared propagation compares a borrowed transitive witness against the exact existing key and full fourteen-field evidence order before allocating a copy. Duplicate or capped witnesses preserve the same changed flag and uncertainty; admitted replacements still use the original insertion producer. The independent unprepared cold path continues to construct and insert every candidate. All edge rounds, cycles, provenance combinations, witness ordering and limits remain unchanged.

## Failure Semantics

Closure uncertainty sets are also immutable shared allocations. A repeated reason is checked before allocation or copy-on-write; a new reason detaches only the current set. Every retained position receives the existing full uncertainty charge without a sharing discount. Final summary assembly consumes each completed symbol work record and materializes its complete owned reasons, rather than cloning the record first. Cold evaluation still independently derives every seed and executes every closure round; neither sharing mechanism persists semantic results across evaluations. Cyclic fan-in and provider changes/removal are compared against the independent cold producer, and retained baseline trajectories are replayed after each branch.

Invalid authored authority, overlapping summary selectors, and serialization failures return typed errors; supported contradictions become normalized findings; unknown aliases, dynamic calls, unsupported summary contexts, and opaque external behavior remain explicit coverage uncertainty. Missing callback or destructor premises cannot become an empty effect bound.

## Files

### [`operation_effect.rs`](../_code/operation_effect.rs)

Adapts exact Program Semantics external-operation identities to the installed summary catalog without using ambiguous source method names. Observed effects are positive lower facts and do not establish an exhaustive upper bound. Qualified `OpenOptions` chains distinguish literal read, write, and read/write modes. A nonliteral or otherwise unsupported mode retains an exact `[unknown]` operation identity and `ExternalInteraction` uncertainty rather than guessing read or write behavior. Construction, execution, callback invocation, and destructor execution remain separate boundaries; unchecked unwrap is unsafe execution rather than a panic claim.

### [`state_contract.rs`](../_code/state_contract.rs)

Defines, canonicalizes, validates, and resolves distributed State Contract v1 declarations against PSM nominal types and Semantic Analysis domains.

### [`state_effect.rs`](../_code/state_effect.rs)

Defines the effect ontology and capability consequences and derives direct/transitive effects, typestate classifications, policy checks, findings, coverage, canonical serialization, and artifact digests. Summary outcomes preserve actual context observations, selected authority, catalog binding, premise and assumption references, and unresolved reasons separately from observed positive effects. Actual unit syntax supports an empty destructor premise; other normalized types remain unknown because final-segment normalization can erase nominal identity. Local callback premises remain unknown until expansion and type authority are retained. Bound possibilities remain claim-relative uncertainty and never become positive violation witnesses.

### [`summary.rs`](../_code/summary.rs)

Defines and strictly validates the versioned operation-summary catalog, canonical catalog digest, exact-context selector, authority classes, callback and destructor premises, and per-site summary outcomes. Only complete qualified bounds with matching source, version, target, feature, and type evidence support negative effect claims. Assumed authority remains disclosed, unsupported or missing premises retain explicit opacity, and selector order never resolves a conflict.

Prepared evaluation retains exact direct seeds and bounded synchronous effect-closure trajectories under current source/context, call, relevant catalog and instantiation bindings. Reverse dependency changes invalidate consumers, and missing retained rounds execute the original ordered propagation and witness-budget rules through the current closure stop. Final typestate, contract policy, headers and findings always use current inputs. Unrelated catalog edits can reuse established seeds while rebinding each outcome to the current catalog digest. Analyzer semantic version `5.0.1` rejects reserved `psm_primitive_drop:` references unless the version, complete PSM digest and syntactic Unit type ID are current and the premise is `Known([])`; ordinary caller-established premise refs and disclosed assumptions retain their existing authority rules.
