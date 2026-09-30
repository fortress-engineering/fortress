# Code

## Role

The directly owned Code validates state and effect-summary authority and derives conservative typestate and effect consequences from existing PSM and Semantic Analysis facts.

## Execution

Snapshot Governance loads distributed contracts after compiling one PSM and Semantic Analysis result, then invokes the state/effect evaluator once before standard-rule dispatch and derived artifact serialization. Standard Registry supplies the installed operation-summary catalog through its public provider. Operation-summary selection binds the resolved operation to its dependency or toolchain source, version, target, features, and type arguments before a qualified upper bound is applied.

## State

Analysis state is process-local and immutable after construction; fixed-point work maps are deterministic and no repository state is mutated.

## Failure Semantics

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
