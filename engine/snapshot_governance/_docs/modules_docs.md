# Modules

## Composition

The Snapshot Governance responsibility is decomposed where durable child boundaries have exclusive primary ownership and independent contracts; immediate children remain contained by this parent while cross-Module dependencies stay authoritative in contract.json.

## Modules

### [Snapshot Governance Testing](../testing/README.md)

Verifies only Features introduced directly by Snapshot Governance and does not claim requirements owned by ancestor, sibling, or descendant Modules.

## Coordination

The immediate children collectively fulfill the Snapshot Governance responsibility through the parent boundary. Their conceptual contributions compose here without restating or replacing the typed relationship graph declared by their Module contracts.

**Candidate composition**

The parent owns [exact hypothetical evaluation](code_docs.md), reusing SESSION, State Governance, Development Governance and Migration Governance; it introduces no child Module, parser, evaluator, authorization system or source writer.
