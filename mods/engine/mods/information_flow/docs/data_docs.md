# Data

## Role

The Module owns schemas and normative rule Data needed to govern information-flow policy and derived results.

## Origin

These files are project-authored declarations registered through the Fortress Standard and schema registry.

## Semantics

The policy schema defines project-owned facet vocabularies, the analysis schema defines deterministic derived output, and the rule declares supported information-flow coherency obligations.

## Validity

Each file must remain canonical JSON, match its registered schema or rule grammar, and preserve the closed supported vocabulary.

## Lifecycle

Changes are manually reviewed and semantically versioned alongside analyzer behavior.

## Files

### [`flow_analysis_schema_v1.json`](../data/flow_analysis_schema_v1.json)

Defines the canonical deterministic Information Flow Analysis v1 artifact.

### [`flow_policy_schema_v1.json`](../data/flow_policy_schema_v1.json)

Defines project-owned finite ordered facet and level policy.

### [`program_infoflow_rule.json`](../data/program_infoflow_rule.json)

Defines PROGRAM-INFOFLOW-001 for supported trust and confidentiality constraints.
