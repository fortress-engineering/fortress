# Code

## Role

The directly owned Code validates state authority and derives conservative typestate and effect consequences from existing PSM and Semantic Analysis facts.

## Execution

Snapshot Governance loads distributed contracts after compiling one PSM and Semantic Analysis result, then invokes the state/effect evaluator once before standard-rule dispatch and derived artifact serialization.

## State

Analysis state is process-local and immutable after construction; fixed-point work maps are deterministic and no repository state is mutated.

## Failure Semantics

Invalid authored authority and serialization failures return typed errors; supported contradictions become normalized findings; unknown aliases, dynamic calls, and opaque external behavior remain explicit coverage uncertainty.

## Files

### [`state_contract.rs`](../code/state_contract.rs)

Defines, canonicalizes, validates, and resolves distributed State Contract v1 declarations against PSM nominal types and Semantic Analysis domains.

### [`state_effect.rs`](../code/state_effect.rs)

Derives direct/transitive effects, typestate classifications and transitions, policy checks, findings, coverage, canonical serialization, and artifact digests.
