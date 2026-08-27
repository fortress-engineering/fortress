# Modules

## Composition

The Project Model responsibility is decomposed where durable child boundaries have exclusive primary ownership and independent contracts; immediate children remain contained by this parent while cross-Module dependencies stay authoritative in contract.json.

## Modules

### [Project Model Testing](../mods/testing/README.md)

Verifies only Features introduced directly by Project Model and does not claim requirements owned by ancestor, sibling, or descendant Modules.

## Coordination

The immediate children collectively fulfill the Project Model responsibility through the parent boundary. Their conceptual contributions compose here without restating or replacing the typed relationship graph declared by their Module contracts.
