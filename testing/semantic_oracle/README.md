# Semantic Reference Oracle

## Purpose

Provide an independently authored reference interpreter for the qualification protocol's restricted primitive language.

## Responsibility

Compute potential effect unions, explicit policy truth and production eligibility from primitive integer and boolean inputs. The responsibility was authored before candidate scoring: the interpreter is pure and therefore deliberately denies filesystem writes and process spawning. Its policy is intent, not a summary inferred from Fortress observations.

## Scope

### Includes

Two potential operation families, pure instructions, explicitly unknown instructions, reachability, ALLOW and DENY intent, absent policy, absent subject, missing source support, and production versus test-only eligibility. Effect unions occupy the closed three-bit domain 0 through 7; other DENY inputs are invalid. Exhaustive pattern matches express the pure reference logic without implicit operator dispatch. Every reference function is real executable source and is consumed by the test-owned qualification driver.

### Excludes

Rust parsing, Fortress evaluator imports, arbitrary source-language inference, application evidence, runtime execution assertions, file access, process execution, human adjudication, population accuracy and general control/data-flow qualification.

## Relationships

This Module has no provider dependencies. Its local Testing boundary verifies literal protocol truth independently of the Fortress implementation.

The native reference-library package exposes this capability to the parent qualification driver and local tests. Consumers import the package surface rather than traversing its implementation files.

## Guarantees

Identical primitive inputs produce identical reference outputs. A sufficient positive survives an unrelated unknown instruction; absent policy and ALLOW never prove absence; zero source support never produces a favorable negative. Only an independently supported production witness permits blocking in this restricted reference table.
