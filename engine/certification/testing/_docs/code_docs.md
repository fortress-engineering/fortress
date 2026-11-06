# Code

## Role

Contains Certification conformance tests.

## Execution

Cargo invokes the explicit certification target against deterministic in-memory positive and negative fixtures.

## State

Fixtures are process-local and create no persistent evidence or mutable repository state.

## Failure Semantics

Any graph, digest, cycle, status, eligibility, binding, assertion, source-exclusion, affected-closure, or Verified BFG mismatch fails its mapped parent Requirement.

## Files

### [`certification.rs`](../_code/certification.rs)

Exercises Certification v1 conformance.

### [`control_plane.rs`](../_code/control_plane.rs)

Exercises the fixed control layout, exact required effect-summary authority and registered parent-directory admission, rejection of unregistered governance descendants, authority-exclusion boundary, safe immutable manifest identity, matching current and historical schema/layout pairs, historical digest separation, and exact selection lookup. Selection controls reject duplicate context keys and reverse key order while accepting empty bootstrap indexes and independent contexts sharing one generation.

### [`declaration.rs`](../_code/declaration.rs)

Independent truth-table, omission, exact evidence admission, metadata alteration, ALL/ANY, cycle, scope placement, raw residue, cache deletion and canonical replay controls. Small real repository fixtures verify neutral absent/invalid endpoints and supported negative/unknown application reporting without test execution.

### [`provider.rs`](../_code/provider.rs)

Exercises exact binding axes, native names, zero/partial/filtered/ignored/retried runs, ambiguous selectors, forged producer/trust fields, current descriptor changes, explicit assumptions, known failure and normalized resource amplification. These protocol vectors do not claim independent human execution or real-world semantic precision.

Provider R06-013 and R06-014 preserve complete authored obligation identities through missing bindings and deleted report bytes, bind exact selected metadata/payload/inventory, refuse foreign authoring, and withhold ambiguous multiple-run support.

### [`provider_reference.py`](../_code/provider_reference.py)

Independently replays retained bytes, exact native inventory and host-current descriptors using no Fortress producers. It cannot accept serialized freshness or authenticate unsigned names.

### [`provider_xml.py`](../_code/provider_xml.py)

Independent standard-library XML reference with bounded input and normalized rows, original native names and explicit incomplete-report limitations.

### [`provider_sarif.py`](../_code/provider_sarif.py)

Independent standard-library SARIF2.1 reference preserving invocation, rule findings, unknowns and the absence of an independent inventory.

### [`provider_controls.py`](../_code/provider_controls.py)

Manual positive, negative and uncertainty protocol controls supply independent expected outcomes; synthetic host premises never claim actual execution.

### [`provider_conformance.py`](../_code/provider_conformance.py)

Runs twelve independent manual protocol controls and compares the actual native CLI against thirty-two frozen positive, negative and uncertainty XML/SARIF vectors. Each original payload must reproduce canonical metadata through the separate standard-library consumer. This mandatory correctness gate makes no performance, human-adjudication or population-precision claim.

The declaration tests also require exact tool-scope metadata to remain a separately typed, unsigned observation across every application truth state. Stale tool inputs refuse observation; adding scope metadata cannot alter declaration bytes or assessment sufficiency.
