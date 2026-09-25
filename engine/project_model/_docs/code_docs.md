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

### [`filing.rs`](../_code/filing.rs)

Compiles the canonical recursive Project Filing System, validates Standard-owned ecosystem registrations and bounded Data/Info grammar, and retains complete deterministic leaf inventory outside the CCG.

### [`module_index.rs`](../_code/module_index.rs)

Indexes every canonical Module exactly once from direct contract-marked ancestry, records physical parent and child edges, and maps semantic Elements to their reserved physical directories for all architectural consumers.

### [`project.rs`](../_code/project.rs)

Loads the root project configuration and validates canonical observation exclusions, relocation-transparent logical Module contract and source bindings, and exact profile, assurance, Module-scope, and coverage-floor selections without creating another manifest.

### [`evaluation_key.rs`](../_code/evaluation_key.rs)

Binds exact Standard, project, ownership, selected profile and governance identities, then combines that authority digest with source-manifest and program-context digests for one evaluation. The key contains no machine path or clock value.

### [`control_layout.rs`](../_code/control_layout.rs)

Loads the fixed root-only control registry, classifies exact active authority and immutable generation members, exposes the shared artifact dataset, and rejects unregistered control paths.
