# Data

## Role

Persist the schema and normative rule contract that define Intended BFG representation and modeled-flow coherency.

## Origin

The schema and rule are specification-authored under the Fortress draft Standard and maintained with their provider-independent compiler and conformance evidence.

## Semantics

The Data defines the canonical Intended BFG v1 document surface and the BEHAVIOR-FLOW-001 proposition applied only to Features containing authored checkpoints.

## Validity

Both JSON documents must remain valid UTF-8 canonical JSON, use registered schema and rule identities, declare only supported semantics, and preserve stable field, applicability, remediation, and logic metadata.

## Lifecycle

The v1 schema remains stable for its representation identity; compiler semantic changes are versioned explicitly, while the draft rule changes only through reviewed Standard evolution.

## Files

### [`behavior_graph_schema_v1.json`](../data/behavior_graph_schema_v1.json)

Defines the canonical serialized Intended Behavioral Flow Graph v1, including Feature states, flows, provenance, derivations, and explicit semantic limits.

### [`behavior_flow_rule.json`](../data/behavior_flow_rule.json)

Defines BEHAVIOR-FLOW-001 applicability and modeled-flow coherence obligations without making unmodeled Features fail.
