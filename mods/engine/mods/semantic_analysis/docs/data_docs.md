# Data

## Role

The Module owns schemas for authored Function Contract intent and derived Semantic Analysis results.

## Origin

Both schemas are specification-authored for the current draft. Optional function_contracts.json files are authored by the Module that physically owns each contracted PSM symbol.

## Semantics

Function Contracts narrow admitted parameters and output promises while carrying state/effect and information-flow obligations for responsible downstream analyzers without duplicating static signatures. Semantic Analysis documents contain derived value-domain summaries, checks, violations, coverage, unsupported classes, and authority digests.

## Validity

Contracts must be canonical JSON, target unique same-Module PSM symbols and parameters, and express domains contained by the static type. Derived results must match registered schemas, use deterministic order, exclude timestamps and absolute paths, and bind to exact PSM and contract digests.

## Lifecycle

Authored contracts change with intentional function semantics. Schemas change only through explicit semantic evolution; derived results are regenerated whenever their PSM, contract input, or analyzer version changes.

## Files

### [`function_contracts.json`](../data/function_contracts.json)

Narrows and proves the exact iteration-bound contract of the Semantic Analysis fixed-point engine without deriving intent from its callers.

### [`function_contract_schema_v3.json`](../data/function_contract_schema_v3.json)

Defines strict distributed Function Contract v3 documents, supported authored domain forms, state obligations, effect policies, and project-facet information-flow declarations.

### [`program_domain_rule.json`](../data/program_domain_rule.json)

Defines PROGRAM-DOMAIN-001 and the precise supported contradictions that become normative findings.

### [`semantic_analysis_schema_v1.json`](../data/semantic_analysis_schema_v1.json)

Defines the canonical derived Semantic Analysis v1 document envelope.
