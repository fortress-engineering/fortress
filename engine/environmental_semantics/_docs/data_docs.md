# Data

## Role

The Module owns schemas and normative rule Data governing environmental authority and derived analysis.

## Origin

Maintainers author the schemas and draft rule records; analysis output remains derived Info outside this Module.

## Semantics

The contract schema defines generic external nondeterminism and recovery declarations, the analysis schema defines deterministic derived conclusions, and three rules separate handling totality, retry safety, and interruption recovery.

## Validity

Every Data file is canonical JSON, schema-valid, registered exactly once, and uses closed generic vocabularies rather than provider-specific assumptions.

## Lifecycle

Schema and rule changes are reviewed with analyzer semantics and conformance evidence; superseded representations remain only in Git history.

## Files

### [`environment_contract_schema_v1.json`](../_data/environment_contract_schema_v1.json)

Defines retained distributed Environment Contracts v1 whose exact-snapshot legacy symbol references remain eligible for explicit migration.

### [`environment_contract_schema_v2.json`](../_data/environment_contract_schema_v2.json)

Defines canonical distributed Environment Contracts v2 over current versioned semantic symbol identities.

### [`environmental_analysis_schema_v1.json`](../_data/environmental_analysis_schema_v1.json)

Defines canonical deterministic Environmental Analysis v1 derived Info.

### [`program_environment_rule.json`](../_data/program_environment_rule.json)

Defines PROGRAM-ENVIRONMENT-001 handling-totality obligations.

### [`program_recovery_rule.json`](../_data/program_recovery_rule.json)

Defines PROGRAM-RECOVERY-001 bounded interruption and recovery obligations.

### [`program_retry_rule.json`](../_data/program_retry_rule.json)

Defines PROGRAM-RETRY-001 completion, idempotency, and duplicate-delivery obligations.
