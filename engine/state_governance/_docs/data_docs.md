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

### [`comparison_projection_schema_v1.json`](../_data/comparison_projection_schema_v1.json)

Defines the lossless public candidate comparison projection. Its native identity is SHA-256 over concatenated canonical UTF-8 chunks; public owner facts are bound to the exact native input. Native comparison v1 frames can retain later StateView versions accepted by the owner even where their earlier standalone schema did not describe those versions. This envelope preserves those historical bytes and reports native standalone schema conformance as NOT_ASSERTED_NATIVE_OWNER_VALIDATED; it does not redefine the old schema or promote missing support.

### [`comparison_state_schema_v2.json`](../_data/comparison_state_schema_v2.json)

Current comparison inputs explicitly admit StateView v3 while retaining v1/v2 views and their original meaning. No original schema bytes, semantic finding identities, historical verdicts or authorization proofs are rewritten.
