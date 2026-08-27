# Root Info

`Cargo.lock` is the only persisted root Info element. Cargo maintains it as the
derived exact dependency resolution. It is committed for reproducibility but is
not misclassified as authored Data.

Build products are transient and must be directed outside the governed
repository with `CARGO_TARGET_DIR`. Snapshot audits and test results are emitted
to callers and are not persisted here as certification evidence.
