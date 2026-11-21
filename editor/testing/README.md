# Editor Testing

## Purpose

Validate the adapter's protocol and normal desktop workflow.

## Responsibility

Exercise independent operational fixtures and actual Fortress read-only queries in isolated editor workspaces.

## Scope

### Includes

Transport, source consistency, diagnostics, exact identities, and proposal-only inspection controls.

### Excludes

Engine semantic evaluation authority, distribution and external authorization.

## Relationships

### [Editor](../README.md)

**Types:** `depends_on`, `verifies`

Exercises the editor adapter at its native boundaries.

## Guarantees

Fixture inputs are disposable, and visible results retain the original protocol meaning and limitations.
