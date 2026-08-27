# Fortress Testing

## Purpose

This verification Module exists to prove only the bootstrap-governance and complete audit Features introduced directly by the Fortress root Module.

## Responsibility

Validate the root-owned self-model, command-declaration agreement, complete contract resolution, truthful non-certification state, and cross-subsystem repository audit lifecycle without claiming evidence for descendant Features.

## Scope

### Includes

Rust verification code whose claims map exclusively to root-owned bootstrap-governance and Fortress audit requirements while using descendant capabilities where execution requires them.

### Excludes

Requirements owned by Engine, CLI, or any deeper Module; normative standard meaning; production implementation; and persisted runtime test artifacts.

## Relationships

### [Engine](../engine/README.md)

**Types:** `depends_on`

Uses provider-independent loaders and evaluators while checking the complete self-model.

### [Fortress](../../README.md)

**Types:** `verifies`

Verifies root declarations, physical Module structure, ownership, truthful certification state, and the intended audit behavior introduced at the CLI/Engine lowest common Module scope.

### [CLI](../cli/README.md)

**Types:** `depends_on`

Uses the CLI registry contract when checking project-wide command declaration agreement.

## Guarantees

Self-verification is deterministic, operates on the declared repository root, and never upgrades development evidence into certification.
