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

Provides crate-local thread-local retained-input admission before tokenization, with exact input byte/count counters, fixed per-input metadata accounting, sticky exhaustion and rejection of active-budget reset. Early scalar Rust resource rejection also invalidates an enabled parser epoch without charging rejected bytes as retained allocations. The helper has no language, policy, job, model or publication authority and is inactive for ordinary callers. A dedicated caller-owned thread must end before its retained input lifetime is released.

Caller-supplied `ObservationLimits` bound ordinary files, all traversed entries including directories, source bytes and path bytes. `observe_repository_bounded` preflights metadata and aggregate inventory before hashing or allocating whole input buffers; admitted inputs use the same canonical fact producer as ordinary observation. Limits and rejection state are operational and never enter observation identity.

### [`physical.rs`](../_code/physical.rs)

Admits ordinary file handles, rejects links and reparse metadata, and checks native identity, size and modification metadata after bounded reads. Native identities remain machine-local OPS facts. Windows opens reparse objects themselves; Unix uses no-follow admission. This does not promise an atomic snapshot against a hostile operating system.

### [`rust_admission.rs`](../_code/rust_admission.rs)

Bounds source bytes, recursive delimiters, nested comments and long operator runs before the existing Rust frontends allocate recursive syntax. It skips literals for resource counting and produces no symbols, claims or competing syntax authority. Exhaustion returns an explicit resource failure. Generic-angle accounting preserves enclosing depth through const blocks and ignores return/match arrows as closers. Independently closed declarations renew the syntax-region budget, so many shallow generic functions do not consume one file-wide recursion allowance.
