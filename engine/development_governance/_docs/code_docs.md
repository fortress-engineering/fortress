# Code

## Role

Pure protected-authority and decision services.

## Execution

Validate exact immutable inputs; no project code or approval service executes.

## State

Process-local prepared inputs and explicitly injected trust.

## Failure Semantics

Missing, invalid, unsupported and conflicting authority remain unresolved.

## Files

### [`authority.rs`](../_code/authority.rs)

Versioned public contracts and deterministic evaluation.

### [`decision.rs`](../_code/decision.rs)

Versioned public contracts and deterministic evaluation.

### [`application_authority.rs`](../_code/application_authority.rs)

Non-transferable application permission handles preserve existing protected decisions and grants. Narrow first-intent establishment requires no prior protected authority and creation-only exact intent; empty source changes assert no semantic success.


MIGRATE consumes process-local ApplicationAuthorization handles; public ApplicationAuthority records are provenance only. PhysicalMigrationInputs bind full physical changes separately from the canonical evaluated source subsets, so candidate exclusions cannot hide protected mutations. Original raw assessment treats NOT_APPLICABLE dimensions as neutral only when at least one applicable dimension has NO_SUPPORTED_VIOLATION and all remaining dimensions are similarly supported or not applicable; unknown, unevaluable, all-inapplicable and violating assessments remain unevaluated or failed. This does not alter any raw declaration or historical assessment.
