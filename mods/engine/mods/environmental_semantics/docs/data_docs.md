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

### [`environment_contract_schema_v1.json`](../data/environment_contract_schema_v1.json)

Defines canonical distributed Environment Contracts v1.

### [`environmental_analysis_schema_v1.json`](../data/environmental_analysis_schema_v1.json)

Defines canonical deterministic Environmental Analysis v1 derived Info.

### [`program_environment_rule.json`](../data/program_environment_rule.json)

Defines PROGRAM-ENVIRONMENT-001 handling-totality obligations.

### [`program_recovery_rule.json`](../data/program_recovery_rule.json)

Defines PROGRAM-RECOVERY-001 bounded interruption and recovery obligations.

### [`program_retry_rule.json`](../data/program_retry_rule.json)

Defines PROGRAM-RETRY-001 completion, idempotency, and duplicate-delivery obligations.
