# Fortress Testing

## Purpose

This verification Module exists to prove only the bootstrap-governance Feature introduced directly by the Fortress root Module.

## Responsibility

Validate the root-owned self-model, command-declaration agreement, complete contract resolution, and truthful non-certification state without claiming evidence for descendant Features.

## Scope

### Includes

Rust verification code whose claims map exclusively to root-owned bootstrap-governance requirements while using descendant capabilities where execution requires them.

### Excludes

Requirements owned by Engine, CLI, or any deeper Module; normative standard meaning; production implementation; and persisted runtime test artifacts.

## Relationships

### [Engine](../engine/README.md)

**Types:** `depends_on`

Uses provider-independent loaders and evaluators while checking the complete self-model.

### [Fortress](../../README.md)

**Types:** `verifies`

Verifies root declarations, physical Module structure, ownership, and truthful certification state.

### [CLI](../cli/README.md)

**Types:** `depends_on`

Uses the CLI registry contract when checking project-wide command declaration agreement.

## Guarantees

Self-verification is deterministic, operates on the declared repository root, and never upgrades development evidence into certification.
