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

### [`dependency_rule.json`](../data/dependency_rule.json)

Carries the draft normative rule record interpreted by the dependency evaluator.

### [`realization_rule.json`](../data/realization_rule.json)

Defines ARCH-REALIZATION-001 and its direct-authorization, transitive-bypass, coverage-truthfulness, and remediation semantics.

### [`semantic_conformance_rule.json`](../data/semantic_conformance_rule.json)

Defines ARCH-SEMANTIC-001, including applicability, causal evidence, unsupported behavior, and canonical remediation.

### [`semantic_conformance_schema_v1.json`](../data/semantic_conformance_schema_v1.json)

Defines the deterministic derived Module semantic-conformance projection containing policy claims, observed consequences, coverage, dependency convergence, and summary counts.
