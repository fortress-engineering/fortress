# Standard Registry

## Purpose

The Standard Registry exists so Fortress can identify and load one exact normative draft standard instead of deriving rule meaning from implementation or test output.

## Responsibility

Validate stable Fortress identities and assemble the declared standard manifest, schema registry, and complete rule-document set as one coherent bundle.

## Scope

### Includes

Stable entity and rule identity syntax, common schema vocabulary, standard and schema manifests, rule metadata, and the mutable 1.0.0-draft.1 authority.

### Excludes

Project declarations, repository facts, rule findings, certification evidence, and rule-specific semantics owned by other capability Modules.

## Relationships

This Module declares no outbound architectural relationships.

## Guarantees

Stable IDs remain canonical while meaning is compatible; manifests reject missing, extra, duplicate, or mismatched rules; released editions are expected to be immutable and content-addressed even though the current edition is draft.
