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

### [`flow_analysis_schema_v1.json`](../_data/flow_analysis_schema_v1.json)

Defines the canonical deterministic Information Flow Analysis v1 artifact.

### [`flow_policy_schema_v1.json`](../_data/flow_policy_schema_v1.json)

Defines project-owned finite ordered facet and level policy.

### [`program_infoflow_rule.json`](../_data/program_infoflow_rule.json)

Defines PROGRAM-INFOFLOW-001 for supported trust and confidentiality constraints.

### [`flow_policy_schema_v2.json`](../_data/flow_policy_schema_v2.json)

Adds sources, sinks and transforms with exact ProgramContext selectors and bounded slots. v1 remains a strict supported facets-only reader; no operation declaration is silently assigned v1 meaning. Sets are canonical and duplicate/conflicting bindings fail.

### [`flow_analysis_schema_v2.json`](../_data/flow_analysis_schema_v2.json)

Adds selected operation applicability and per-sink/facet evidence, canonical defeaters, assumptions, findings and coverage. The historical v1 schema remains registered. Existing owner-canonical artifact digest semantics remain explicit in the compatibility catalog.

### [`flow_claim_schema_v1.json`](../_data/flow_claim_schema_v1.json)

Defines the standalone, explicitly versioned per-sink record used in analysis v2 and declaration rule details. It binds scope, context, policy, source, findings, defeaters and assumptions without importing internal evaluator types. Integrity validation does not establish semantic correctness or producer authentication.
