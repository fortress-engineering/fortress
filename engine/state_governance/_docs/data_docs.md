# Data

## Role

Public versioned comparison schemas.

## Origin

State Governance owns these schemas and the Standard Registry registers their immutable identifiers.

## Semantics

ComparisonState preserves exact original evidence and necessary owner assets. TransitionAnalysis is derived and content-addressed; it is neither approval nor producer trust.

## Validity

Use the registered schemas and validated native facade. Unsupported versions, malformed bindings and resource exhaustion are refused.

## Lifecycle

Schema version 1 and comparator version 1.0.0 are additive. Existing StateView and protocol v1 schemas retain their meanings; incompatible future changes require a new version.

## Files

### [`comparison_state_schema_v1.json`](../_data/comparison_state_schema_v1.json)

Exact immutable input shape including explicitly absent historical assets.

### [`transition_analysis_schema_v1.json`](../_data/transition_analysis_schema_v1.json)

Derived transition model with independent axes, evidence, uncertainty and nonvalidated authorization citations.
