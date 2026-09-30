# Code

## Role

The test executable supplies parent-local evidence for each State and Effect Analysis requirement.

## Execution

Cargo runs the explicit test target against deterministic synthetic models and the live repository compiler APIs.

## State

Fixtures are process-local, use isolated temporary repositories where needed, and do not mutate governed production state.

## Failure Semantics

Assertions compare exact classifications, findings, coverage, provenance, and canonical bytes so semantic regressions fail the workspace test gate directly.

## Files

### [`state_effect_analysis.rs`](../_code/state_effect_analysis.rs)

Verifies contract ownership, typestate behavior, refined operation classification, capability expressibility, panic and unsafe structure, causal effect closure, policy compatibility, uncertainty, deterministic output, and live self-analysis.

### [`operation_summary.rs`](../_code/operation_summary.rs)

Verifies exact-context effect authority, callback and destructor premises, conflict rejection, disclosed assumptions, unsupported coverage, and the retained comparison of authored, source-derived, and qualified hybrid summaries. The Standard public provider supplies the installed catalog; the comparison fixture is directly owned Testing Data.
