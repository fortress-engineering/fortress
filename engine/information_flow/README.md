# Information Flow

## Purpose

Information Flow exists to establish explainable security-relevant provenance and policy compatibility for values moving through the supported program model.

## Responsibility

Information Flow consumes canonical program, value-domain, state, and effect facts plus explicit project policy, propagates ordered facet classifications conservatively, and rejects supported flows that violate declared consumers.

## Scope

### Includes

This Module owns policy algebra, Function Contract flow interpretation, explicit value and field propagation, sink reconciliation, trusted-transition diagnostics, coverage, and deterministic derived information.

**Declared operation boundaries**

The optional `GOV-FORTRESS-DECLARED-FLOW` profile governs Operation Policy v2 declarations at the registered `__fortress/governance/information_flow_policy.json` role. It can be selected for the project or individual Modules through existing exact profile references. The project retains its own finite facet vocabulary. No environment input is classified as secret by default. A missing policy, absent sink or unselected profile is NOT_APPLICABLE, never a security PASS.

Sources name an operation, an output slot, a facet and a level. Sinks name an operation, an input slot, a facet and a bound: maximum confidentiality or minimum integrity. Selectors accept an exact current symbol ID, full local qualified name, or exact externally resolved operation identity. Every selector pins the PSM ProgramContext digest, including dependency and analyzer context. Zero or multiple local matches, unavailable operations, invalid slots and stale contexts fail explicitly. Fields require an observed nominal owner/field access within the declared operation; uncertain instance identity never establishes a clean field claim.

Use `fortress flow-author --schema` for the complete policy grammar. After authoring finite facets, `fortress flow-author . --source sample::credential --sink sample::log --facet FLOW-CONFIDENTIALITY --level SECRET --bound PUBLIC --format json` resolves readable names and previews canonical bytes with the current context already filled in. The result is PROPOSED and UNAPPROVED. It writes no authority. Review the preimage and accept through the applicable protected-change boundary before selecting and evaluating the policy. Distributed Function Contracts keep their existing ownership and semantics.

Transforms identify input/output slots, an endorsement or declassification rule, and a nonempty declared trust basis. The only repository-authored trust state is DECLARED_ASSUMPTION. An editable reference cannot authenticate an approver. Transformation assumptions remain in provenance and defeat unconditional favorable conclusions; neither a sanitizer name nor an effect upper bound proves implementation correctness. Nonmatching levels survive a partial transformation. Legacy Function Contract results retain their original propagation inputs.

**Coverage and evidence**

Aggregate source, sink, check and unknown counts include the selected operation declarations and evaluated sink bindings alongside legacy Function Contracts. Nonselection reports its scope reason rather than a fictitious propagation-resource failure. Analysis v2 reports each sink/facet separately with exact input identities, classification origins, source-to-sink derivation references, original findings, canonical defeaters, assumptions and coverage. Supported violations survive unrelated uncertainty. With no sufficient witness, missing classification, opaque calls, callbacks, dispatch, incomplete files, ambiguous shared call contexts or field-instance precision produce NOT_EVALUABLE. A negative result covers explicit supported value transfers only. Implicit control flow, concurrency, covert channels, arbitrary aliases and unmodeled language semantics remain unsupported; it is not a noninterference or comprehensive information-flow security proof.

The existing PSM owns external argument/return movement; it assigns no security meaning. Information Flow reuses its finite propagation and Function Contract machinery. Exact unambiguous local interprocedural paths are supported. Multiple caller contexts that could mix arguments and returns are disclosed, not used to manufacture violation witnesses. The initial operation envelope does not establish path feasibility, reassignment-sensitive value history or alias-sensitive mutation: relevant control structures, mutations and hidden macro semantics make those claims unevaluable. Each observed sink invocation must have classified input; one public input cannot cover an unclassified second invocation. Test-only or uncertain execution provenance remains advisory for progressive enforcement. Exceptions never change raw violations into safety evidence.

The existing declaration and Profile Assessment preserve the per-sink outcomes in a DECLARED_FLOW dimension, or the selected Module dimension. EXPLAIN pages contain the source scope and canonical defeaters. Portable assurance retains those same upstream results and their binding; successful bundle integrity verification does not recompute semantics, authenticate the producer or prove freshness against another repository.

**Bounds and qualification**

The v2 loader admits at most 1 MiB of policy, 64 facets with 256 ordered levels each, 4096 total declarations and 8192 resolved boundary bindings. Derived operation facts have count, provenance-byte and chain bounds; aggregate compact per-sink records are bounded to 64 MiB so shared provenance cannot amplify output without limit. Exhausted resources fail explicitly. Querying an already-loaded context never initiates analysis. `serve --stdio --flow-authoring` explicitly prepares its immutable authoring context once; ordinary read-only serve/status/doctor omit this preparation. RPC v3 adds typed flow_author; earlier protocol editions remain supported and reject that newer method.

The source-control corpus under local Testing separates compiler-executed finite controls from analyzer expectations. It covers credential-to-log, redacted telemetry, an unresolved callback with both leaking and redacting implementations, an unrelated public flow, and a falsely declared sanitizer. These are authored standalone consumer controls, not an independent-maintainer study, human adjudication, population accuracy measurement or application execution evidence. Their narrow result cannot promote broader security promises. A paired control preserves the complete local call relationships and direct/transitive effect sets while changing only which classified value reaches the sink; FLOW distinguishes the permitted and prohibited cases. This is its demonstrated value beyond dependency and effect checks, not a claim of general semantic precision.

Configuration provenance follows the existing frontend boundary. Rust conditional compilation depends on externally supplied target/cfg/features ([Rust Reference](https://doc.rust-lang.org/reference/conditional-compilation.html)); function pointers and trait objects can require runtime target selection ([function pointers](https://doc.rust-lang.org/reference/types/function-pointer.html), [trait objects](https://doc.rust-lang.org/reference/types/trait-object.html)). Those facts justify retaining scoped uncertainty rather than assuming a complete call graph.

**Consumer handoff**

Migration and editor/host consumers must preserve proposal/preimage/context bindings, source observation versus authored classification, conditional transformation assumptions, exact selected scopes, and raw findings versus enforcement. State comparison must not interpret changed policy, unsupported coverage or absent findings as remediation. The registered root policy remains a protected governance input. No workflow, external approval validator, implicit repair or authority writer is introduced here.

### Excludes

This Module excludes source parsing, architecture intent, behavioral intent, hard-coded sanitizer knowledge, complete implicit-flow proof, arbitrary alias analysis, and certification claims.

## Relationships

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Provides the normalized security finding representation used for supported sink contradictions.

### [Program Semantics](../program_semantics/README.md)

**Types:** `depends_on`

Provides canonical executable bodies, value transfers, calls, fields, reads, and mutations without security interpretation.

### [Semantic Analysis](../semantic_analysis/README.md)

**Types:** `depends_on`

Provides the value-domain result and input identity on which information-flow derivation is bound.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Supplies duplicate-key-rejecting JSON decoding for authored information-flow policy.

### [State and Effect Analysis](../state_effect_analysis/README.md)

**Types:** `depends_on`

Provides canonical state/effect consequences and field precision boundaries consumed by the information-flow layer.

## Guarantees

Information Flow preserves deterministic ordering and provenance, never improves trust or reduces confidentiality without explicit authority, retains opaque semantics as uncertainty, and never treats absence of a finding as comprehensive security proof.
