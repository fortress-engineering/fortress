# Data

## Role

Declare the independent reference library's native package surface and its local verification target.

## Origin

The Semantic Reference Oracle owns its package metadata under the shared workspace version and toolchain constraints.

## Semantics

The library exports only its pure primitive interpreter. Its local Testing module consumes this native surface without cross-Module file imports. The package has no Fortress evaluator dependency.

## Validity

The manifest resolves its library and local test roots exactly and remains a member of the declared workspace. Package metadata does not assert that tests ran or that any application conforms.

## Lifecycle

Changes to the library surface, toolchain or interpreter require the qualification protocol's current source and oracle bindings to be renewed.

## Files

### [`Cargo.toml`](../_data/Cargo.toml)

Defines the pure reference library and its local literal-control target through native package boundaries.
