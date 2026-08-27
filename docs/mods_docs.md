# Modules

## Composition

The Fortress responsibility is decomposed where durable child boundaries have exclusive primary ownership and independent contracts; immediate children remain contained by this parent while cross-Module dependencies stay authoritative in contract.json.

## Modules

### [CLI](../mods/cli/README.md)

Presents the provider-independent Engine as an honest local command surface.

### [Engine](../mods/engine/README.md)

Combines all provider-independent Fortress capabilities into the callable core used by presentation and verification Modules.

### [Fortress Testing](../mods/testing/README.md)

Verifies only the bootstrap-governance Feature introduced directly by the Fortress root and does not claim requirements owned by descendant Modules.

## Coordination

The immediate children collectively fulfill the Fortress responsibility through the parent boundary. Their conceptual contributions compose here without restating or replacing the typed relationship graph declared by their Module contracts.
