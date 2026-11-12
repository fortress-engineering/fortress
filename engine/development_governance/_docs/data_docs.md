# Data

## Role

Public protected-authority boundary schemas.

## Origin

Development Governance owns versioned derived decisions and nontransferable grant receipts; Snapshot Governance captures exact inputs.

## Semantics

Authorization requirements bind exact proposals and trusted base rules. Public receipts preserve reported checks, never authenticate an issuer or recreate permission. Preview selection files are hypothetical selections, not trusted grants.

## Validity

Use strict public JSON, installed schemas, JCS and SHA-256. Refuse unsupported versions, ambiguous rules, excessive inputs, unsafe paths and mismatched bindings.

## Lifecycle

Version 1 is additive. Historical comparison, declaration, assessment and portable assurance schemas retain their original meaning. No persistent transition or authorization database is required.

## Files

### [`change_decision_schema_v1.json`](../_data/change_decision_schema_v1.json)

Public change decision shape; serialized integrity is distinct from trusted external authorization.

### [`validated_grant_schema_v1.json`](../_data/validated_grant_schema_v1.json)

Public validated grant shape; serialized integrity is distinct from trusted external authorization.

### [`authorization_requirement_schema_v1.json`](../_data/authorization_requirement_schema_v1.json)

Public authorization requirement shape; serialized integrity is distinct from trusted external authorization.

### [`authority_snapshot_schema_v1.json`](../_data/authority_snapshot_schema_v1.json)

Public authority snapshot shape; serialized integrity is distinct from trusted external authorization.

### [`preview_selection_schema_v1.json`](../_data/preview_selection_schema_v1.json)

Public authority preview selection shape; serialized integrity is distinct from trusted external authorization.

### [`application_authority_schema_v1.json`](../_data/application_authority_schema_v1.json)

Provenance-only migration authorization basis and exact decision references. Deserialization never reconstructs a process-local permission handle or validates external approval.

### [`authority_snapshot_schema_v2.json`](../_data/authority_snapshot_schema_v2.json)

Current authority captures bind comparison v2; historical v1 captures remain readable with their original identities. No original schema bytes, semantic finding identities, historical verdicts or authorization proofs are rewritten.
