# Code

## Role

The Code defines the language-neutral PSM and the Rust-specific translator that emits nominal type, impl, executable, typed-expression, call, neutral body/control, transfer, derivation, coverage, coherency, and provenance facts.

## Execution

The orchestrator verifies snapshot-bound bytes, consumes application files already partitioned by the project context, derives Cargo package and target contexts, builds a workspace-wide nominal/interface/impl index, propagates supported local static types, resolves only unique type-directed call targets, derives graph and transfer topology, assigns structurally established execution provenance, reconciles cross-Module calls with Implementation Observation, and serializes canonical output. The CONTROL role registry admits required active configuration as identity input and excludes nonrecursive or unrecognized `__fortress` payloads from application parsing. A Cargo root or an explicit source binding beneath the control root is a typed failure; an include or macro body remains an explicit coverage barrier. PSM v6 binds source, Cargo, explicit context, ownership, and stable Module-identity inputs that can alter program semantics, allowing unrelated Module policy changes to reuse identical PSM bytes while exact-snapshot certification remains independently complete.

The Rust 1.97.1 signature catalog supplies exact return types only for the registered `std::process::Command` and `std::fs::OpenOptions` constructors and receiver-preserving builder methods. These signature facts are separate from State/Effect operation classification. Local bindings use the bounded `UNKNOWN`, `KNOWN`, `FINITE_ALTERNATIVES`, and `CONFLICT` lattice, join branch environments conservatively, and iterate loop environments to a fixed point with an eight-iteration cap. Exceeding the nesting or iteration cap emits a `type_worklist_limit` coverage barrier. Exact package, crate, module, and type paths select same-name methods when available; a simple name with multiple candidates remains ambiguous.

Supported dereference inference is limited to structural references and raw pointers. Trait objects, unresolved trait selection, callbacks/function pointers, macro bodies, user-defined dereference, and unsupported external operations remain explicit residual calls or coverage barriers. A local `Drop` implementation produces an implicit-destructor barrier because scope execution and destructor effects are not proven. Calling a local async function without an enclosing `.await` records `ASYNC_BODY_NOT_POLLED` and does not propagate the body effects; a directly awaited local call may resolve normally. The structural envelope closes the measured release cases without a rustc/HIR dependency. The independent qualification corpus required for an accuracy claim is not yet available, so this decision is retained as unscored rather than presented as a general Rust-resolution result.

**Rust semantic identity specification.** Fortress assigns semantic identity from the strongest deterministic Rust and Cargo structure represented by the production PSM. Identity is separate from source occurrence: repository-relative paths, spans, exact spelling, and causal paths remain evidence. The current executable namespace is `rust_symbol:v2:sha256`, computed from canonical structured identity material. The former `rust_symbol:sha256` token-stream digest is retained only as a legacy alias for explicit reference and finding-governance migration.

Two supported declarations are the same semantic executable when their language, Cargo package/crate identity, Rust module namespace, executable kind, owning type and trait, item name, receiver form, ordered parameter types and arity, return type, generic semantic structure, relevant bounds, `async`, `unsafe`, `const`, and declared ABI/`extern` qualifiers are equal. Generic type, const, and lifetime declarations are alpha-normalized by declaration order, and their authored names are replaced consistently in types, bounds, defaults, and `where` predicates.

Identity deliberately excludes parameter binding names, generic/lifetime spelling, whitespace, comments and documentation, line and column, checkout root, repository-relative source placement, formatter output, diagnostic wording, parser allocation identity, collection traversal order, and attributes whose semantics are not explicit qualifiers above. Execution provenance and Fortress Module ownership remain separate facts. Owner, type, bound, default, and ABI syntax is token-normalized after alpha-renaming. Unsupported syntax retains deterministic normalized structural spelling; Fortress does not claim compiler-level type equivalence, macro-generated identity, arbitrary alias equivalence, trait selection, or semantic equivalence across unsupported syntax.

**Source occurrences and operation sites.** A source occurrence contains the current repository-relative path, span, exact spelling, and analyzer provenance. The `rust_operation_site:v1:sha256` identity binds the containing current symbol, canonical resolved or stable exceptional operation identity, operation kind, and zero-based source-order ordinal among matching operations inside that symbol. It survives line insertion, formatting, parameter renaming, and unrelated operation insertion while distinguishing repeated calls. Inserting, removing, or reordering an otherwise identical earlier operation can change subsequent ordinals; without HIR or an authored operation anchor Fortress cannot truthfully distinguish them more strongly.

**Semantic findings.** Two supported semantic-policy findings are the same violation when governing rule identity, owning Fortress Module stable identity, policy target kind and target, violation kind, and stable operation-site identity are equal. Coordinates, diagnostics, entry symbol, transitive caller fan-in, full call chains, evidence ordering, and execution provenance remain causal evidence rather than finding identity. A distinct direct operation site remains a distinct finding.

**Legacy migration.** Every current executable exposes its exact-snapshot token-stream ID as a non-authoritative alias. A legacy reference resolves only when that alias maps to exactly one current symbol; successful resolution normalizes in memory and reports legacy use, while missing or ambiguous aliases fail. Ordinary audit, check, and certification never rewrite authority. The explicit identity-migration command reports and applies only reviewed, exact-snapshot, unambiguous symbol-reference and finding-governance replacements, preserves baseline/exception metadata, never adds unrelated findings, and refuses incomplete or many-to-one mappings. Historical schemas retain their historical meaning.

## State

Analysis is stateless beyond deterministic process-local indexes built from one immutable input set.

## Failure Semantics

Snapshot mutation, malformed supported source, missing ownership, or analyzer disagreement returns a typed error. Ambiguous or unsupported language semantics remain explicit coverage facts instead of failures or invented exact targets.

## Files

### [`graph.rs`](../_code/graph.rs)

Derives deterministic call adjacency, reachability, strongly connected components, recursion, entry/leaf facts, and cross-boundary projections.

### [`program.rs`](../_code/program.rs)

Defines canonical language-neutral PSM v6 types, nominal and impl facts, executable-symbol provenance, syntactic operation outcomes, file coverage, structured places and mutations, input/output boundaries, canonical serialization, digests, resolution/coverage summaries, and analyzer coherency.

### [`analysis_context.rs`](../_code/analysis_context.rs)

Defines machine-independent package and target context with explicit known and unknown feature, cfg, platform, and toolchain values.

### [`semantic_identity.rs`](../_code/semantic_identity.rs)

Constructs versioned structured Rust symbol and operation-site identities, alpha-normalizing generic/lifetime binders while retaining exact legacy token-stream aliases for explicit migration.

### [`rust.rs`](../_code/rust.rs)

Translates snapshot-bound Cargo manifests and structurally parsed Rust declarations, nominal types, impls, explicit signatures, supported expression types, calls, and transfers into the language-neutral PSM. It resolves unique inherent and concrete trait implementation methods from proven receiver types, applies the bounded local type lattice and installed signature catalog, classifies known external ownership, and preserves ambiguity, dynamic dispatch, unpolled async bodies, expression and statement macros, custom dereference, destructor uncertainty, and missing type information as explicit residual states. Macro bodies are not expanded; their invocation sites remain opaque calls.
