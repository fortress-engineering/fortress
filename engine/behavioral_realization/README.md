# Behavioral Realization

## Purpose

Behavioral Realization exists to determine whether supported implementation semantics realize a Feature's explicitly modeled meaningful behavior without bypassing its required behavioral structure.

## Responsibility

Behavioral Realization validates distributed checkpoint-to-anchor declarations, derives a language-neutral implementation-event graph from canonical upstream models, projects next meaningful checkpoint transitions, reconciles them with the Intended BFG, and detects supported dominator bypasses and terminal or decision contradictions.

## Scope

### Includes

This Module owns Behavior Realization Contract v1, exact semantic anchor resolution, coverage-aware event reachability, checkpoint and Feature realization states, intended/realized edge reconciliation, dominator-bypass analysis, verification-obligation projection, Realized BFG v1, and the two behavioral realization rule evaluators.

### Excludes

This Module excludes source reparsing, runtime traces, automatic checkpoint inference, natural-language intent matching, capability-to-symbol realization, presentation geometry, dynamic execution probabilities, certification, and changes to the Intended BFG or CCG.

## Relationships

### [Behavioral Semantics](../behavioral_semantics/README.md)

**Types:** `depends_on`

Provides the canonical Intended BFG, modeled checkpoints, edges, dominators, decisions, terminals, and source provenance.

### [Contract Coherency](../contract_coherency/README.md)

**Types:** `depends_on`

Provides the canonical CCG Feature, Module, checkpoint declaration, and containment authority used to validate distributed realization ownership.

### [Environmental Semantics](../environmental_semantics/README.md)

**Types:** `depends_on`

Provides exact modeled external operation and outcome events without duplicating environmental outcome logic.

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Provides normalized content-addressed findings for proven realization and bypass contradictions.

### [Information Flow](../information_flow/README.md)

**Types:** `depends_on`

Provides exact trusted information-transition events and their contract authority.

### [Program Semantics](../program_semantics/README.md)

**Types:** `depends_on`

Provides executable symbols, structured bodies, resolved calls, static control structure, Modules, and source provenance.

### [Semantic Analysis](../semantic_analysis/README.md)

**Types:** `depends_on`

Provides supported return-domain refinements used by exact Boolean terminal anchors.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Provides stable Feature, checkpoint, and rule identities used by realization authority and findings.

### [State and Effect Analysis](../state_effect_analysis/README.md)

**Types:** `depends_on`

Provides exact supported typestate transitions and effect occurrences used as semantic anchors.

## Guarantees

Behavioral Realization never turns missing semantic coverage into realization or bypass freedom, never promotes internal helpers to behavioral checkpoints, retains derivation evidence for every realized edge and bypass, and emits canonical deterministic results without claiming runtime execution or verification evidence.

**Optional bounded checkpoint governance**

Compose GOV-FORTRESS-BOUNDED-BEHAVIOR with a compatible canonical or native layout profile, explicitly at project or Module scope, after reviewing its bounded claim. It is an optional add-on and does not replace mandatory layout governance. Authored CCG checkpoints and Intended BFG retain independent authority. The claim covers explicit static entry/return checkpoint order, required transitions, mandatory dominators and terminal containment in supported direct-call paths. It does not prove that a function named authorize implements authorization, that a sanitizer performs its declaration, or that a path actually executed.

For a small workflow with authored CHK-START → CHK-AUTH → CHK-MUTATE → CHK-END and Feature AF-WORKFLOW-0001, a developer can preview complete bindings without extracting hashes:

```console
fortress behavior-author ./workflow --feature AF-WORKFLOW-0001 --checkpoint CHK-START=sample::entry --checkpoint CHK-AUTH=sample::authorize --checkpoint CHK-MUTATE=sample::mutate --checkpoint CHK-END=sample::entry --return CHK-END --format human
fortress behavior-author --schema
fortress serve --stdio ./workflow --behavior-authoring
```

The resulting v3 contract includes the exact context and readable names. It remains PROPOSED with accepted_authority=false. Review it as the distributed Module _data/behavior_realization_contracts.json declaration; normal contract admission checks intent membership, ownership and complete bindings. Bind requirements to tests using the existing EVIDENCE verification-binding format separately. Execution evidence never replaces static realization, and accepted exceptions never prove checkpoint correctness.

The optional selected realized graph is version 2; its bounded_analysis reports independent source/context/input identities, static verdicts, coverage, counterexample events, canonical defeaters and conditional FLOW provenance. NOT_EVALUABLE includes unknown branches, loop admission/exit, unresolved calls, recursion, unsupported expressions, ambiguous or alternative anchors without proven exclusivity, insufficient effect/state/environment evidence, Boolean return refinements requiring closure of authored Function Contract premises, and resource exhaustion. Unmodeled Features remain unmodeled. A missing path never becomes evidence of checkpoint execution or absence of bypass. Identical-operation reorder anchoring retains the existing documented PSM limitation.

The frozen positive and reordered controls have the same named call/effect set but different ordering verdicts, establishing value beyond simple adjacency inventory. Eleven pinned Rust entry-probe controls independently adjudicated expected finite source traces. This is automated source adjudication, not a human authoring study, independent security audit or population accuracy claim. The readable consumer example is covered by proposal/admission regressions. Performance observations are diagnostic only.

The lowering scope was checked against the primary Rust Reference on [operand evaluation order](https://doc.rust-lang.org/reference/expressions.html#evaluation-order-of-operands), [call convergence](https://doc.rust-lang.org/reference/expressions/call-expr.html) and [return control transfer](https://doc.rust-lang.org/reference/expressions/return-expr.html). Unsupported mechanisms retain uncertainty. STANDARD_RC and RELEASE must rerun integration when contract, graph, claim, selector or protocol versions change; no workflow admission, migration or unified-IR authority is introduced.
