# Code

## Role

The single transaction planner, source writer and recovery owner.

## Execution

Validate immutable bytes; request complete canonical evaluation and existing AUTHORITY decisions through injected ports; allocate an exclusive same-volume OPS lease; synchronize preparation and write-ahead intents; verify each mutation; independently reobserve and evaluate actual state; publish a receipt last.

## State

Plans and receipts are immutable derived records. Active journals, original bytes, staged postimages and native ownership identities remain external under OPS. Completion never requires a transition database.

## Failure Semantics

Typed errors retain the transaction reference. Unknown bytes, changed native ownership, missing evidence, incomplete journals and failed validation retain recovery material and block fresh certification. There is no implicit rollback or claim of filesystem-wide atomicity.

## Files

### [`plan.rs`](../_code/plan.rs)

Bounded exact-byte operations, deterministic move-cycle lowering, case-fold collision checks, source ownership admission and the exported Module facade.

### [`model.rs`](../_code/model.rs)

Versioned content-addressed plans, exact state/context/authority bindings, inverse expectations and evaluator/authority ports. All semantic facts come from established owners.

### [`journal.rs`](../_code/journal.rs)

Injected OPS resource capabilities, mutation/cancellation controls, synchronized preparation and append-only sequence/hash-linked operation intents and completions.

### [`paths.rs`](../_code/paths.rs)

Canonical relative paths, ordinary-file and reparse admission, case checking, exact content/native identity checks and qualified directory synchronization.

### [`apply.rs`](../_code/apply.rs)

Compare-before-replace application, exclusively staged cycles, final actual evaluation, last-publication receipts and explicit conflict-preserving resume or rollback.

### [`presentation.rs`](../_code/presentation.rs)

Formats already-evaluated facts and explicitly exports immutable reviewed plans under their registered CONTROL role. Formatting never invokes an evaluator.
