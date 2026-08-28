# Data

## Role

The Module owns schemas defining its distributed authored contracts and deterministic derived output plus the two draft Standard rules that govern supported state and effect contradictions.

## Origin

Schemas and rule records are specification-authored Fortress engineering authority maintained with the analyzer semantics.

## Semantics

The Data defines State Contract v1, State/Effect Analysis v1 output, PROGRAM-STATE-001, and PROGRAM-EFFECT-001 without containing generated analysis results.

## Validity

Each JSON document must satisfy canonical serialization, schema identity, closed object grammar, stable identifiers, registry consistency, and the owning evaluator semantics.

## Lifecycle

Files change deliberately when supported state/effect semantics or the draft Standard evolves and are reviewed with matching Code, contracts, tests, and generated Info.

## Files

### [`program_effect_rule.json`](../data/program_effect_rule.json)

Defines the opt-in function effect-policy rule evaluated from supported direct and transitive effects.

### [`program_state_rule.json`](../data/program_state_rule.json)

Defines the typestate obligation rule evaluated from supported state contracts, transitions, and calls.

### [`state_contract_schema_v1.json`](../data/state_contract_schema_v1.json)

Defines canonical distributed declarations of finite states over direct nominal fields and Semantic Value Domains.

### [`state_effect_schema_v1.json`](../data/state_effect_schema_v1.json)

Defines the deterministic derived State/Effect Analysis document serialized for inspection and freshness gating.
