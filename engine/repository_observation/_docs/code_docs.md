# Code

## Role

Realize the Module responsibility through directly owned provider-independent implementation.

## Execution

Callers invoke the public typed boundary; the Code validates inputs, performs its deterministic processing sequence, and returns a complete result or typed failure.

## State

Execution owns only process-local state unless an explicitly documented artifact is read; no hidden persistent service state is introduced.

## Failure Semantics

Invalid inputs and inability to fulfill the responsibility return explicit typed errors or canonical findings at the owning boundary.

## Files

### [`observation.rs`](../_code/observation.rs)

Walks ordinary files, applies explicit exclusions, normalizes paths, hashes bytes, and emits the sorted observation.

### [`source_manifest.rs`](../_code/source_manifest.rs)

Inventories ordinary and unsupported entries without following links or traversing Git metadata. Link targets that would reveal machine paths are omitted.

### [`source_view.rs`](../_code/source_view.rs)

Keeps exact observed bytes in an immutable view and applies ordered, preimage-checked candidate changes to a separate hypothetical view.

### [`input_retention.rs`](../_code/input_retention.rs)

Provides crate-local thread-local retained-input admission before tokenization, with exact input byte/count counters, fixed per-input metadata accounting, sticky exhaustion and rejection of active-budget reset. The helper has no language, policy, job, model or publication authority and is inactive for ordinary callers. A dedicated caller-owned thread must end before its retained input lifetime is released.

Caller-supplied `ObservationLimits` bound ordinary files, all traversed entries including directories, source bytes and path bytes. `observe_repository_bounded` preflights metadata and aggregate inventory before hashing or allocating whole input buffers; admitted inputs use the same canonical fact producer as ordinary observation. Limits and rejection state are operational and never enter observation identity.
