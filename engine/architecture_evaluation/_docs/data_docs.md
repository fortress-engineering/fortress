# Data

## Role

Persist authored inputs and machine contracts directly consumed by this Module.

## Origin

Maintainers author these files under project, schema, standard, Cargo, or capability authority according to each element description.

## Semantics

The Data declares configuration, structure, identity, applicability, or normative input meaning used by the Module; it is not computational output.

## Validity

Consumers require valid UTF-8 where textual, correct schema or ecosystem syntax, canonical identities and paths, complete required fields, and compatible declared versions.

## Lifecycle

Maintainers update Data through reviewed semantic changes; schema versions change only when representation identity changes, while Git retains superseded history.

## Files

### [`dependency_rule.json`](../_data/dependency_rule.json)

Carries the draft normative rule record interpreted by the dependency evaluator.

### [`realization_rule.json`](../_data/realization_rule.json)

Defines ARCH-REALIZATION-001 and its direct-authorization, transitive-bypass, coverage-truthfulness, and remediation semantics.

### [`semantic_conformance_rule.json`](../_data/semantic_conformance_rule.json)

Defines ARCH-SEMANTIC-001, including applicability, causal evidence, unsupported behavior, and canonical remediation.

### [`semantic_conformance_schema_v1.json`](../_data/semantic_conformance_schema_v1.json)

Preserves the original deterministic Module semantic-conformance projection contract for compatibility with previously materialized v1 artifacts.

### [`semantic_conformance_schema_v2.json`](../_data/semantic_conformance_schema_v2.json)

Defines the deterministic derived Module semantic-conformance projection with exact governed/source-symbol coverage on every Module and claim, including explicit zero-coverage uncertainty.

### [`semantic_conformance_schema_v3.json`](../_data/semantic_conformance_schema_v3.json)

Defines the retained deterministic projection in which ALLOW entries are authored authorizations with observed-usage counts while only DENY entries carry conformance and blocking conclusions.

### [`semantic_conformance_schema_v4.json`](../_data/semantic_conformance_schema_v4.json)

Defines the retained deterministic projection with per-claim execution-provenance composition and stable advisory reasons when supported violations lack production-capable evidence.

### [`semantic_conformance_schema_v5.json`](../_data/semantic_conformance_schema_v5.json)

Preserves the deterministic projection whose effect observations carry stable operation-site identities and whose semantic findings aggregate causal fan-in without using it as finding identity.

### [`semantic_conformance_schema_v6.json`](../_data/semantic_conformance_schema_v6.json)

Defines the current deterministic projection with stable semantic-policy claim identities, canonical defeater objects, and per-claim and per-Module defeater references. Defeaters carry closed kind, exact strength, stable scope, structured current facts, deterministic semantic inputs, and an explicit current-snapshot retirement condition.
