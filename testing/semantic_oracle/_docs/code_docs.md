# Code

## Role

Own the restricted primitive-language reference semantics without importing a Fortress producer or evaluator.

## Execution

The test-owned driver calls the pure reference port before requesting candidate observations. Independent literal unit controls also exercise the interpreter. No fixture operation is executed by this Module.

## State

Only integer and boolean values participate; the interpreter retains no state and performs no I/O.

## Failure Semantics

Unknown instructions have an unknown effect upper bound. Invalid dispositions or effect selectors are invalid policy, missing support is not evaluable, and absent executable subject is nonapplicable. These states never become favorable absence evidence.

## Files

### [`oracle.rs`](../_code/oracle.rs)

Defines primitive effect bits and independent instruction, union, policy-truth and blocking functions. The no-write/no-spawn Module policy follows this deliberately pure responsibility.
