# Data

## Role

The Module owns persisted semantic intent for the finite span-presence lifecycle of FindingLocation and the with_span operation that establishes it.

## Origin

The declarations are project-authored from the stable Finding Model responsibility and exact PSM symbol and nominal identities.

## Semantics

The State Contract classifies FindingLocation as spanned or unspanned from its direct Option field; Function Contract v3 promises that with_span returns the spanned state and permits only the supported receiver-state write needed to establish it.

## Validity

Contracts must be canonical JSON, target Finding Model-owned PSM identities, use valid Semantic Value Domains, resolve direct fields and state identities, and remain synchronized with Function Contract v3 and State Contract v1 schemas.

## Lifecycle

The declarations change only when the governed FindingLocation lifecycle or with_span semantics intentionally changes; PSM identity changes require explicit migration and fresh derived analysis.

## Files

### [`function_contracts.json`](../data/function_contracts.json)

Declares the return typestate and allowed supported effect for FindingLocation::with_span.

### [`state_contracts.json`](../data/state_contracts.json)

Declares mutually exclusive spanned and unspanned FindingLocation states from the span Option field.
