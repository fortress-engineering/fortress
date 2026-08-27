# Snapshot Governance Module

This Module owns the executable answer to: given one exact repository state,
project declaration, architecture graph, and draft standard, what is true and
what violates the declared engineering model?

Snapshot creation binds exact declaration bytes, explicit exclusions, two-pass
stable file facts, engine interpretation version, repository content, and the
complete snapshot fingerprint without wall-clock or absolute-path identity.
Findings preserve rule identity, tier, category, location, message,
remediation, evaluator provenance, standard edition, and deterministic order.
They are evidence about a snapshot and do not redefine a rule.

Implemented evaluators cover dependency cycles, exact file ownership,
requirement/Rust-test traceability, and the recursive Module grammar. Missing
evaluators are `UNSUPPORTED`, never PASS. An audit is deterministic development
evidence, not certification or attestation.

Two-pass equality is an optimistic stabilization protocol rather than a
filesystem lock. Reverted transient mutations and a malicious host remain
outside its content-identity guarantee.
