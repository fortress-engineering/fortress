# Snapshot requirement/test traceability

**Status:** Implemented Snapshot Governance rule
**Rule:** `TEST-TRACEABILITY-001`
**Owning capability:** `AF-SNAPSHOT-GOVERNANCE-0001`

The rule evaluates active feature requirements against supported Rust test
facts. Active requirements are mandatory: their IDs must be unique and each
must reference canonical, globally unique test evidence that exists. Every
observed behavioral or specification-conformance test must map to one active
requirement. Tests explicitly classified as `infrastructure` may intentionally
remain unmapped because they do not claim product behavior coverage.

The Rust analyzer is a subordinate fact source. It parses Rust syntax with
`syn`, recognizes `#[test]` functions, and reads stable test identity from the
function's doc comment. Optional `Fortress requirement: ID` and `Fortress
classification: infrastructure` doc lines add explicit facts. Before parsing a
snapshot file, the analyzer requires its current bytes and size to match the
stabilized snapshot record.

No Node, Python, or generic text-search analyzer is implied. Analyzer facts do
not define requirement semantics, certify execution, or prove that a test ran.
