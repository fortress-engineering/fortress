# Code

## Role

Compose child capabilities through one provider-independent library boundary.

## Execution

Cargo builds the explicit library target; the facade resolves child source paths at compile time and exposes their public contracts to callers.

## State

The facade owns no persistent state and delegates process-local evaluation state to the responsible child capability.

## Failure Semantics

Compile-time boundary violations fail the build; child runtime errors remain typed and propagate without presentation-specific conversion.

## Files

### [`lib.rs`](../code/lib.rs)

Defines the warnings-denied provider-independent crate facade and composes child capability source through explicit target paths.
