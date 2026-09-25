# Program Semantics

## Purpose

Provide a trustworthy implementation-semantic substrate beneath architectural Modules and intended Feature behavior.

## Responsibility

Analyze exact snapshot-bound source into deterministic language-neutral facts about nominal declarations, implementation blocks, executable symbols, typed interfaces and local expressions, calls, initial value transfers, and supported cross-Module execution boundaries without treating implementation facts as authored intent.

## Scope

### Includes

Stable Cargo package and target interpretation, explicit known or unknown feature/cfg and platform context, structural Rust syntax analysis, canonical executable identities, nominal structs/enums/traits/aliases and impls, recursive type normalization, local expression-type propagation, type-directed inherent and concrete trait method resolution, one accounted outcome for each enumerated syntactic operation, separate observed/opened/parsed/symbol-bearing file coverage, stable residual-resolution reasons, call-graph derivations, initial value-transfer topology, neutral body/control structure for downstream reasoning, Testing classification, analyzer coherency, provenance, canonical serialization, and deterministic digesting.

### Excludes

Behavioral checkpoint realization, capability-to-symbol mapping, Function Contract interpretation, value-domain reasoning, function correctness, complete Rust trait solving, user-defined dereference chains, macro expansion, general effects, alias/heap flow, symbolic execution, dynamic-dispatch proof, security flow proof, and automatic contract generation.

## Relationships

### [Contract Coherency](../contract_coherency/README.md)

**Types:** `depends_on`

Supplies canonical Module identities, containment, logical source bindings, and verification topology when authored project authority exists. Program Semantics consumes the resolved ownership relation and otherwise retains analysis-only Cargo ownership without importing it into the CCG.

### [Implementation Observation](../implementation_observation/README.md)

**Types:** `depends_on`

Supplies the exact snapshot-bound source substrate and the broader observed Module dependency projection against which cross-Module call facts are reconciled.

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Supplies the CONTROL namespace layout and role registry used to distinguish partitioned application inputs from governed control configuration and nonrecursive retained evidence.

### [Repository Observation](../repository_observation/README.md)

**Types:** `depends_on`

Supplies the bounded source manifest and explicit observation barriers used for source coverage accounting.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Supplies strict JSON preflight for authored and cached semantic inputs without changing PSM identity.

## Guarantees

Identical semantic inputs produce byte-identical PSM documents and digests; semantic input identity binds Rust bytes, Cargo authority, explicit analysis context, project ownership configuration, and stable Module identity while leaving unrelated Module policy to downstream conformance; certification separately binds the resulting PSM to the complete exact repository snapshot. Unknown target, feature, cfg, toolchain, or generated-input semantics never imply a known empty context. Every enumerated call has an outcome; unexpanded macro bodies and unsupported implicit operations remain coverage barriers. Every fact retains deterministic source provenance; ordinary repository placement is not a semantic-analysis admission condition; exact resolution is never assigned to unsupported or ambiguous Rust semantics; missing project or test governance remains explicit; Testing and production symbols remain distinguishable where authority supports it; and no PSM fact or analysis territory is represented as architecture or behavioral intent.
