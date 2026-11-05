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

### [`lib.rs`](../_code/lib.rs)

Defines the native test-harness crate root registered by the Engine Cargo manifest. This authored crate-root resolution boundary wires the parent's private aggregation source and the local controls. The existing Testing-to-parent and Testing-to-Core dependencies authorize that wiring; production has no reverse dependency on Testing.

### [`field_projection.rs`](../_code/field_projection.rs)

The integration target compiles the actual private aggregation helper source through the existing declared verification dependency. Fixture construction and public evaluations use the Core facade. Tests compare indexed and zero-admission assembly against the independent original scan, including duplicates, tuple fields, empty and absent symbols. They verify exact scratch admission and incomplete owner-inventory refusal. Complete public cold, freshly prepared and reused evaluations compare the entire canonical model and all findings for both a small admitted fixture and a fixture with 8,192 additional independent functions that naturally exceeds the fixed 16 MiB budget. Every resulting summary's fields are checked against independent full PSM scans. Production has no dependency on Testing and no public budget control is added. The prepared-effect tests also cover adding a formerly unresolved target, rebuilding its field effects, and restoring complete cold-equivalent baseline results without mutating prior preparation.

### [`state_effect_analysis.rs`](../_code/state_effect_analysis.rs)

Verifies contract ownership, typestate behavior, refined operation classification, capability expressibility, panic and unsafe structure, causal effect closure, policy compatibility, uncertainty, deterministic output, and live self-analysis.

### [`operation_summary.rs`](../_code/operation_summary.rs)

Verifies exact-context effect authority, callback and destructor premises, conflict rejection, disclosed assumptions, unsupported coverage, and the retained comparison of authored, source-derived, and qualified hybrid summaries. The Standard public provider supplies the installed catalog; the comparison fixture is directly owned Testing Data.

### [`effect_preparation.rs`](../_code/effect_preparation.rs)

Verifies R07-001 through R07-007: direct-seed and closure replay; exact witness and reverse-dependency rebuilding; cycles and witness budgets, including converging unequal paths, repeated call sites, source-order variants and production/test/unknown execution provenance checked against the independent unprepared producer; conservative topology/inventory fallback; bounded payload retention; current authority rebinding after unrelated catalog edits; and whole-PSM primitive-premise refresh with cold/prepared rejection of stale, malformed, absent, nonunit or nonempty reserved proof claims. Nonreserved caller-established references remain accepted under the ordinary summary authority boundary.
