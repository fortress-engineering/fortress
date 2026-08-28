# Finding Model

## Purpose

The Finding Model exists so every evaluator can describe snapshot-bound rule violations through one provider-independent representation without placing that shared contract inside any one rule family.

## Responsibility

Validate, normalize, deterministically order, and content-address canonical finding evidence while preserving normative rule identity, affected entities, source location, remediation, evaluator provenance, standard edition, and optional exemption reference.

## Scope

### Includes

Finding definitions, occurrences, source spans and locations, evaluator provenance, failure state, deterministic ordering, content fingerprints, typed construction errors, and the authored finite span-presence state/effect intent of FindingLocation.

### Excludes

Normative rule meaning, repository observation, architecture analysis, general heap-state reasoning, rule execution, certification, exemptions, and the decision that a particular violation exists.

## Relationships

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Supplies stable entity and rule identities plus the normative rule-category vocabulary embedded in a finding.

## Guarantees

Equal normalized evidence produces the same finding fingerprint and sort position; invalid identities, locations, tiers, or provenance fail construction; and findings never redefine rules or claim certification.
