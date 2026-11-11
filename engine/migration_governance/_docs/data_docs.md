# Data

## Role

Public migration plan, receipt and journal contracts.

## Origin

Migration Governance owns application and recovery records; Standard Registry catalogs their schemas. Existing Snapshot, State, Finding and Development Governance owners retain their independent authority.

## Semantics

Plan and receipt identities use RFC 8785 JCS and SHA-256 with their own digest field set to the empty string. SourceView, canonical subject, state, transition and authority references retain their existing distinct digest domains. Exported approval references and grant provenance never recreate process-local validated grants.

## Validity

Apply recompiles the entire immutable target and compares the exact reviewed plan identity before allocating a source-writing transaction. Public readers reject duplicate keys, incompatible versions, tampering and bounded resource violations. Missing validation is NOT_EVALUABLE, never satisfaction.

## Lifecycle

Version 1 is additive. Plans are proposals exported only explicitly; receipts preserve historical established application facts. External active journals and original byte slots remain recoverable after failure and are not compiler cleanup targets.

## Files

### [`migration_plan_schema_v1.json`](../_data/migration_plan_schema_v1.json)

Ordered operations, executable dependency graph, exact preconditions, target evaluation, existing authorization requirements and inverse expectations.

### [`migration_receipt_schema_v1.json`](../_data/migration_receipt_schema_v1.json)

Independent actual/expected binding, validation and authorization provenance, with no runtime-execution or present-freshness claim.

### [`migration_journal_schema_v1.json`](../_data/migration_journal_schema_v1.json)

Prepared transaction header and known native ownership inventory. Operation JSONL is synchronized before source mutation and hash-linked to this header.

### [`migration_operations_example_v1.json`](../_data/migration_operations_example_v1.json)

An explicit creation proposal accepted by the migration preview adapter. Exact byte arrays avoid locale-dependent encoding and require no manually extracted hashes. The example grants no permission and makes no semantic claim.
