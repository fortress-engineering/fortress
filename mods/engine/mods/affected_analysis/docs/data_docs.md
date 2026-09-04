# Data

## Role

Data defines the stable machine-readable schema for affected-analysis results.

## Origin

The schema is authored from the exact-snapshot affected-dependency doctrine and the existing stable identities exposed by Fortress authorities and projections.

## Semantics

The schema separates authoritative input changes, invalidated dependency units, reusable units, affected Modules, projection impact, and explicit reasons. Serialized results explain recomputation; they do not make cached material authoritative.

## Validity

Every path is repository-relative, every unit uses a stable kind and identity, dependency and reason collections are canonical, and aggregate counts agree with the listed units.

## Lifecycle

Compatible additions retain v1. Any incompatible change to change classes, affected-unit meaning, or dependency bindings requires a new schema identity.

## Files

### [`affected_analysis_schema_v1.json`](../data/affected_analysis_schema_v1.json)

Defines exact snapshot fingerprints, authoritative input changes, affected units and reasons, reusable unit identities, affected Modules and projections, and aggregate recomputation counts.
