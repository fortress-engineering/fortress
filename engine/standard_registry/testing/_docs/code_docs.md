# Code

## Role

Exercise the Module responsibility through directly owned verification logic without becoming normative authority.

## Execution

Cargo invokes each explicit test target; the code loads direct fixtures or the governed repository, performs deterministic assertions, and terminates with process success or failure.

## State

Verification is stateless apart from process-local values and isolated disposable runtime repositories where a scenario requires filesystem behavior.

## Failure Semantics

A violated assertion or fixture-loading failure fails the test target and surfaces its exact subject; verification never suppresses production errors.

## Files

### [`governance_profiles.rs`](../_code/governance_profiles.rs)

Verifies immutable profile definitions, order-independent composition, explicit conflict rejection, stable Module-scoped overrides, native and strict filing applicability, assurance evidence holds, and policy-only invalidation boundaries.

### [`registry_primitives.rs`](../_code/registry_primitives.rs)

Verifies stable identity parsing and exact draft rule registry metadata at the Standard Registry boundary.

### [`schema_registry.rs`](../_code/schema_registry.rs)

Validates registered JSON Schema documents, the live manifest, emitted proof and certificate shapes, complete compatibility catalog coverage, and agreement with the draft rule registry.

### [`artifact_schemas.rs`](../_code/artifact_schemas.rs)

After issuance produces its exact candidate, validates every advertised artifact schema, including large local materializations, using the registered 2020-12 schemas. The issuer records this as a separate required gate.

### [`wire_contract.rs`](../_code/wire_contract.rs)

Checks duplicate-key rejection, exact public integers, optional bounds, unknown versions and enums, and RFC 8785 canonical byte vectors.

### [`std_id_001.rs`](../_code/std_id_001.rs)

Exercises valid, invalid, and minimum-boundary stable identities for STD-ID-001.
