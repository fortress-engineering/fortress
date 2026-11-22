# Agent Integration

## Purpose

Give local tool clients access to existing Fortress results and let a separately trusted embedding mediate exact reviewed changes.

## Responsibility

Own local MCP framing, capability declarations, and the translation from an independently reviewed local invocation to the existing migration writer. Snapshot Governance and Development Governance retain ownership of evaluation, evidence and permissions.

## Scope

### Includes

Version negotiation, bounded request and response framing, cancellation, immutable inspection, explicit hypothetical evaluation, and trusted application and recovery of exact reviewed migration plans.

### Excludes

Remote listeners, shell interception, editor and operating-system write confinement, external approval issuance, changes to provider rules, and release operations.

## Relationships

### [Engine](../../engine/README.md)

**Types:** `depends_on`

Supplies the canonical read-only query, comparison, and hypothetical evaluation contracts.

### [Certification](../../engine/certification/README.md)

**Types:** `depends_on`

Supplies the existing public content-digest convention for derived provenance.

### [Development Governance](../../engine/development_governance/README.md)

**Types:** `depends_on`

Owns original-policy decisions, scoped authorization requirements, and non-transferable grants.

### [Migration Governance](../../engine/migration_governance/README.md)

**Types:** `depends_on`

Owns all transaction writes, exact target verification, receipts, and recovery.

## Guarantees

Agent requests cannot cross into the trusted writer. Retained evidence maintains its original source, assurance, and authority state. Trusted write coverage is limited to operations routed through the explicit embedding and only while the exact reviewed inputs and authorizations remain valid.

Local client qualification covers the actual stdio protocol, immutable response parity, exact hypothetical changes, and independently asserted refusal and lifecycle cases. Development observations about these tools describe their use within the tested workflow. Comparative agent productivity remains unmeasured.

See [usage and trust boundaries](_docs/code_docs.md).
