# Finding Model

## Purpose

The Finding Model exists so every evaluator can describe snapshot-bound rule violations through one provider-independent representation without placing that shared contract inside any one rule family.

## Responsibility

Validate, normalize, deterministically order, and content-address canonical finding evidence; derive stable lifecycle identity independently of presentation; and evaluate authored legacy baseline and finding-specific exception authority without changing raw conformance.

## Scope

### Includes

Finding definitions, occurrences, source spans and locations, evaluator provenance, failure state, deterministic ordering, stable identity eligibility, baseline lifecycle, explicit exception disposition, progressive enforcement, typed construction errors, and the authored finite span-presence state/effect intent of FindingLocation.

### Excludes

Normative rule meaning, repository observation, architecture analysis, general heap-state reasoning, rule execution, certification, broad rule waivers, approval workflow, and the decision that a particular violation exists.

## Relationships

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Supplies stable entity and rule identities plus the normative rule-category vocabulary embedded in a finding.

## Guarantees

Equal semantic violation identity produces the same stable ID despite line, wording, checkout-root, or semantically transparent Module-location drift; unsafe identity is explicitly baseline-ineligible; baseline and exception authority never converts a violation into PASS; and invalid authority fails closed.
