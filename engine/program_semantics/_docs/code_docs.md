# Code

## Role

The Code defines the language-neutral PSM and the Rust-specific translator that emits nominal type, impl, executable, typed-expression, call, neutral body/control, transfer, derivation, coverage, coherency, and provenance facts.

## Execution

The immutable model exposes borrowed `semantic_inputs` in the same canonical provenance order and with the same path, role and digest fields as serialized PSM evidence. Consumers can validate exact input coverage without constructing a second full-model JSON representation. The borrowed descriptors carry no mutable state or reuse authority.

The orchestrator verifies snapshot-bound bytes, consumes application files already partitioned by the project context, derives Cargo package and target contexts, builds a workspace-wide nominal/interface/impl index, propagates supported local static types, resolves only unique type-directed call targets, derives graph and transfer topology, assigns structurally established execution provenance, reconciles cross-Module calls with Implementation Observation, and serializes canonical output. The CONTROL role registry admits required active configuration as identity input and excludes nonrecursive or unrecognized `__fortress` payloads from application parsing. A Cargo root or an explicit source binding beneath the control root is a typed failure; an include or macro body remains an explicit coverage barrier. PSM v6 binds source, Cargo, explicit context, ownership, and stable Module-identity inputs that can alter program semantics, allowing unrelated Module policy changes to reuse identical PSM bytes while exact-snapshot certification remains independently complete.

The Rust 1.97.1 signature catalog supplies exact return types only for the registered `std::process::Command` and `std::fs::OpenOptions` constructors and receiver-preserving builder methods. These signature facts are separate from State/Effect operation classification. Local bindings use the bounded `UNKNOWN`, `KNOWN`, `FINITE_ALTERNATIVES`, and `CONFLICT` lattice, join branch environments conservatively, and iterate loop environments to a fixed point with an eight-iteration cap. Exceeding the nesting or iteration cap emits a `type_worklist_limit` coverage barrier. Exact package, crate, module, and type paths select same-name methods when available; a simple name with multiple candidates remains ambiguous.

Supported dereference inference is limited to structural references and raw pointers. Trait objects, unresolved trait selection, callbacks/function pointers, macro bodies, user-defined dereference, and unsupported external operations remain explicit residual calls or coverage barriers. A local `Drop` implementation produces an implicit-destructor barrier because scope execution and destructor effects are not proven. Calling a local async function without an enclosing `.await` records `ASYNC_BODY_NOT_POLLED` and does not propagate the body effects; a directly awaited local call may resolve normally. The structural envelope closes the measured release cases without a rustc/HIR dependency. The independent qualification corpus required for an accuracy claim is not yet available, so this decision is retained as unscored rather than presented as a general Rust-resolution result.

**Rust semantic identity specification.** Fortress assigns semantic identity from the strongest deterministic Rust and Cargo structure represented by the production PSM. Identity is separate from source occurrence: repository-relative paths, spans, exact spelling, and causal paths remain evidence. The current executable namespace is `rust_symbol:v2:sha256`, computed from canonical structured identity material. The former `rust_symbol:sha256` token-stream digest is retained only as a legacy alias for explicit reference and finding-governance migration.

Two supported declarations are the same semantic executable when their language, Cargo package/crate identity, Rust module namespace, executable kind, owning type and trait, item name, receiver form, ordered parameter types and arity, return type, generic semantic structure, relevant bounds, `async`, `unsafe`, `const`, and declared ABI/`extern` qualifiers are equal. Generic type, const, and lifetime declarations are alpha-normalized by declaration order, and their authored names are replaced consistently in types, bounds, defaults, and `where` predicates.

Identity deliberately excludes parameter binding names, generic/lifetime spelling, whitespace, comments and documentation, line and column, checkout root, repository-relative source placement, formatter output, diagnostic wording, parser allocation identity, collection traversal order, and attributes whose semantics are not explicit qualifiers above. Execution provenance and Fortress Module ownership remain separate facts. Owner, type, bound, default, and ABI syntax is token-normalized after alpha-renaming. Unsupported syntax retains deterministic normalized structural spelling; Fortress does not claim compiler-level type equivalence, macro-generated identity, arbitrary alias equivalence, trait selection, or semantic equivalence across unsupported syntax.

**Source occurrences and operation sites.** A source occurrence contains the current repository-relative path, span, exact spelling, and analyzer provenance. The `rust_operation_site:v1:sha256` identity binds the containing current symbol, canonical resolved or stable exceptional operation identity, operation kind, and zero-based source-order ordinal among matching operations inside that symbol. It survives line insertion, formatting, parameter renaming, and unrelated operation insertion while distinguishing repeated calls. Inserting, removing, or reordering an otherwise identical earlier operation can change subsequent ordinals; without HIR or an authored operation anchor Fortress cannot truthfully distinguish them more strongly.

**Semantic findings.** Two supported semantic-policy findings are the same violation when governing rule identity, owning Fortress Module stable identity, policy target kind and target, violation kind, and stable operation-site identity are equal. Coordinates, diagnostics, entry symbol, transitive caller fan-in, full call chains, evidence ordering, and execution provenance remain causal evidence rather than finding identity. A distinct direct operation site remains a distinct finding.

**Legacy migration.** Every current executable exposes its exact-snapshot token-stream ID as a non-authoritative alias. A legacy reference resolves only when that alias maps to exactly one current symbol; successful resolution normalizes in memory and reports legacy use, while missing or ambiguous aliases fail. Ordinary audit, check, and certification never rewrite authority. The explicit identity-migration command reports and applies only reviewed, exact-snapshot, unambiguous symbol-reference and finding-governance replacements, preserves baseline/exception metadata, never adds unrelated findings, and refuses incomplete or many-to-one mappings. Historical schemas retain their historical meaning.

Independent cold compilation executes the same complete Rust producer and final assembler with no previous preparation. After every caller has resolved, it consumes uniquely owned body/caller contributions into the finished model instead of copying those facts into preparation that the cold caller immediately drops. This changes temporary ownership only: all analyses, fixed-point work, dependency recording, sorting and canonical facts still execute. The prepared path retains its existing copies, units, counters and reuse validation. No parser syntax crosses threads and no cold result is supplied by a resident cache.

The producer carries its analyzer descriptor alongside its facts in both cold and prepared analysis. The shared assembler derives the language list from that descriptor. The private boundary keeps the existing Rust v6 document, coverage, provenance, and preparation semantics.

## State

Canonical analysis owns deterministic process-local indexes from one immutable input set. Optional coordinator preparation retains exact reusable units between requests, separately from immutable finished models; cache eviction changes work only.

## Failure Semantics

Snapshot mutation, malformed supported source, missing ownership, or analyzer disagreement returns a typed error. Ambiguous or unsupported language semantics remain explicit coverage facts instead of failures or invented exact targets.

## Files

### [`go_test_observer.go`](../_code/go_test_observer.go)

Uses the existing virtual build matcher and bounded Go parser to observe
selected test declarations. It recognizes package-level `Test` names under
Go 1.22 naming rules, separates internal and external test packages, and records
direct `*testing.T` forms and `TestMain(*testing.M)` hooks with their physical
signature and import spans. Renamed direct imports are admitted. Type aliases,
unresolved imports, invalid signatures and bodyless functions retain explicit
limitations. It does not load imports, compile the package or start its runner.

### [`go_test_observation.rs`](../_code/go_test_observation.rs)

Admits only the explicit test-declaration exchange with the existing closed
build input. Checks the exact selected and excluded files, native matching,
source-proven package and declaration occurrences, source-bound import and
type locations, context and worker identity. The derived report supplies no
test execution, coverage, verification or canonical PSM facts.

### [`graph.rs`](../_code/graph.rs)

Derives deterministic call adjacency, reachability, strongly connected components, recursion, entry/leaf facts, and cross-boundary projections.

### [`program.rs`](../_code/program.rs)

Defines canonical language-neutral PSM v6 types, nominal and impl facts, executable-symbol provenance, syntactic operation outcomes, file coverage, structured places and mutations, input/output boundaries, canonical serialization, digests, resolution/coverage summaries, and analyzer coherency.

### [`analysis_context.rs`](../_code/analysis_context.rs)

Defines machine-independent package and target context with explicit known and unknown feature, cfg, platform, and toolchain values.

### [`semantic_identity.rs`](../_code/semantic_identity.rs)

Constructs versioned structured Rust symbol and operation-site identities, alpha-normalizing generic/lifetime binders while retaining exact legacy token-stream aliases for explicit migration.

### [`model_digest.rs`](../_code/model_digest.rs)

The crate-private digest memo belongs to one completed immutable owner model. The first digest streams the unchanged pretty JSON plus trailing LF into SHA-256; subsequent readers reuse that digest for the same object. Model constructors start with empty memos, identical model clones may copy an established memo, and serialization failures are never cached. Memo population is excluded from serialization, debug output and semantic equality; every semantic field still participates in the owner's equality. Adding any model mutation requires invalidating its memo. Independent cold evaluations construct their own models and perform their own first hash. This removes repeated serialization within one evaluation without reusing analysis across source, executable, toolchain, configuration or dependency identities. The helper is provided through the existing Program Semantics dependency of downstream semantic analyzers; it does not grant a direct Project Model dependency or transfer model authority.

### [`rust.rs`](../_code/rust.rs)

**External boundary transfers**

Semantic version 6.2.0 adds argument and direct return-consumer movements at resolved external operation sites. Nodes bind to existing operation-site identities, so distinct calls remain distinct. These observations assign no security labels, sanitization claims, completeness or external implementation proof. Unsupported receivers and nested/dynamic semantics remain bounded by the existing frontend.

Translates snapshot-bound Cargo manifests and structurally parsed Rust declarations, nominal types, impls, explicit signatures, supported expression types, calls, and transfers into the language-neutral PSM. It resolves unique inherent and concrete trait implementation methods from proven receiver types, applies the bounded local type lattice and installed signature catalog, classifies known external ownership, and preserves ambiguity, dynamic dispatch, unpolled async bodies, expression and statement macros, custom dereference, destructor uncertainty, and missing type information as explicit residual states. Macro bodies are not expanded; their invocation sites remain opaque calls.

Inline module traversal retains its own lookup directory, including nested and explicit path components, while source evidence remains bound to the original physical files. This follows the Rust Reference module source rules; missing external module bytes remain an explicit failure. Native repository adoption regressions exercise both existing namespace observers together.

Unresolved feature/custom cfg conditions, conditional attributes and disabled empty alternatives retain unknown execution provenance; they cannot give a positive witness production blocking authority. A syntactic test requirement remains test-only, including conjunctions that require test, while an explicit `not(test)` remains production-capable. Target selection records caller facts but does not claim that cfg selection has been applied to the AST.

Cold and prepared compilation share the final assembler. Prepared parse and declaration contributions, body facts, caller outcomes and graph units remain private to a coordinator; the finished owned PSM is `Send + Sync`. Reuse accepts unchanged input or one isolated ordinary free-function body change with exact exterior bytes and unchanged context/ownership/declarations. Every body and caller in that changed file is rebuilt to refresh shifted spans. Removed contribution spellings are not carried into a fresh type registry. Graph reuse compares complete weak-component members, edges and relevant symbol metadata, retains global Tarjan DFS-root emission order, and rebuilds split, merged or changed components. Neutral query records retain successful and missed name, type, import, cfg and destructor reads. Work counters count executed or replayed owner units; cache accounting stays outside model identity.

### [`reachability.rs`](../_code/reachability.rs)

The existing directed relation is evaluated with borrowed symbol keys and bounded integer scratch. Admission uses checked accounting before allocation: 512 bytes per possible node and 16 bytes per edge, with a 16 MiB scratch allowance. This is an operational allocation estimate, not a process RSS guarantee. A missing target or refused budget uses the complete original traversal. Output strings are created only for the canonical result; direction, self-reachability through cycles and lexical ordering are preserved. Scratch is rebuilt from current immutable edges and is never a persistent semantic cache. Singleton components keep the original direct traversal instead of allocating an unnecessary index.

Cold construction moves complete graph results into the PSM instead of cloning them into an immediately discarded preparation. Resident graph reuse retains its complete component membership, edge and symbol-metadata checks, historical Tarjan ordering and conservative reconstruction. These implementation strategies preserve the existing model and analyzer semantic versions because their supported meanings and canonical bytes are unchanged. Their new operational strategy contract is version 1; any semantic difference requires separate producer versioning and qualification.

### [`go_observation.rs`](../_code/go_observation.rs)

Validates an exact closed Go source request and the bounded native response from a separately selected trusted process. The version 1 observation preserves physical declaration and call occurrences, direct source-body or bodyless declaration associations, explicit unsupported states and original source, authority, context and producer bindings. This projection has its own identity and keeps canonical Rust PSM v6, finding generation, enforcement and certification unchanged.

### [`collector.go`](../_code/collector.go)

Uses the Go standard library parser and type checker to observe one explicit source-only package. The reviewed host builds and selects this helper separately. It reads a bounded request on stdin and writes one bounded JSON frame to stdout. It runs no project code, package resolver, compiler or subprocess. Explicit Go 1.17 and 1.22 contexts on Windows and Linux amd64 are admitted. The closed observation refuses dependency, build directive, test, generated/foreign and unsupported context. Declaration-site resolutions and syntactic activation markers do not establish execution, control flow, effects, or stable cross-revision symbol identity.

### [`go_body.go`](../_code/go_body.go)

Adds an explicit scalar body mode when built together with the single-file
collector. Native Go name resolution and type checking verify ordered local
bindings. Admitted statements include short declarations, assignment,
conditionals and return over exact bool and signed-int64 scalars. Constants
are admitted through native type information and exact ranges. Exact bool
equality and inequality plus ordering and equality of exact int64 values use
the existing comparison expression. Runtime arithmetic, dynamic or external calls, methods, goroutines, defer, limited
identifiers and larger bodies retain explicit refusal. The worker never
imports or executes repository code.

### [`go_body_observation.rs`](../_code/go_body_observation.rs)

Checks the exact closed-package transport and source inventory before admitting
each row to shared Program Semantics body construction. The body receipt binds
the originating evaluation, producer, stdout and physical source occurrences.
Effects, behavioral proof and conformance are outside this standalone
observation.

### [`collector_build_context.go`](../_code/collector_build_context.go)

Adds explicit standalone build selection for one sealed Go source directory. The trusted host builds the two named source files with the selected Go toolchain and invokes the result with the single argument `--select-build-go`. The original single-file collector source and build remain byte-identical. With no argument the combined helper also emits the existing v1 wire projection.

Version 2 binds the exact complete supplied inventory, sorted source digests, package identity, target, Go language version, explicit cumulative compiler release and architecture tags, custom tags and test mode. It asks the native Go build library to match only admitted virtual files. Selection never calls package resolution or reads an ambient source path. Each admitted source records its exact digest and distinct selected, excluded, unsupported or unavailable outcome. Inputs including dependencies, cgo, generated code, external test context and non-build compiler directives remain unsupported. The two declared test modes either exclude matching test input as production-only or require a separately established test context.

This standalone interface projects direct source-body and external-declaration observations for the selected inputs. It grants no repository authority or complete package, linkage, effect, runtime, or certification conclusion. Snapshot Governance integration must independently bind the complete physical source inventory and the trusted build context before using the selected source set. Targets describe compile selection and do not establish operational platform support.


### [`collector_local_imports.go`](../_code/collector_local_imports.go)

Adds explicit module-local type observations for a closed pure-Go library package graph. A trusted build links all three Go collector source files and passes only `--observe-go-module`. Version 3 accepts only a selected Go 1.22 release and Windows or Linux amd64 target context, with the qualified Go 1.22.12 Windows or Go 1.22.2 Linux helper and `GODEBUG=gotypesalias=0`. The no-argument v1 and explicit `--select-build-go` v2 modes retain their wire shapes and meanings.

The request adds an exact module root directory, declared module path, digest-bound `go.mod` bytes and explicit directory-to-import-path mappings to the build-selection input. The observer accepts a bounded `go.mod` containing only its module and Go 1.22 directives. The context digest covers the sorted source inventory, build context and exact module file identity and mapping. An optional type comparison names two independently selected package-scoped type declarations. Request hashing retains the comparison selectors as exact input. All spans refer to the physical source bytes and use the existing byte/line conventions.

The Go file matcher reads only admitted virtual bytes. A single `go/types` package universe resolves local imports reachable from the selected entry. No standard library, ambient source, default importer, cgo, generated or foreign inputs, runnable main packages, separate test context, module replacements, vendoring, internal visibility or workspace behavior is inferred. The trusted host still has to establish the complete original ordinary source inventory, its module boundaries and exact build context before admitting a request. The worker does not discover these from the project filesystem.

A successful result gives per-package lexical import occurrences, aliases, declaration and call positions, and any requested native nominal-type identity comparison. Static qualified function and method associations include the exact declaring package and source site. Function values, interface calls and unsupported call forms retain unresolved states. An unavailable import, unsupported input, cycle, resource limit or type checking error yields a typed refusal with no projected package facts. This protocol exposes source observations only. It establishes neither runtime behavior nor semantic or certification authority. The explicit CLI and Snapshot Governance admission bind actual source and an independently registered worker.

### [`go_build_selection.rs`](../_code/go_build_selection.rs)

Shares legacy native response admission and verifies the explicit Go build-context receipt. Every returned source path and digest must match the complete admitted inventory in order. Physical declaration, call and diagnostic spans can reference only selected files.

### [`go_module_observation.rs`](../_code/go_module_observation.rs)

Admits the exact current Go module and package map from independently captured ordinary source. It checks the separately selected build context, source and module digests, known worker and request identity, package reachability, returned file dispositions and bounded declaration, call, import and type-comparison coordinates. Unsupported paths and contexts fail closed. A public projection contains only these actual native observations and their provenance.

### [`native_body.rs`](../_code/native_body.rs)

Accepts the selected native frontend's bounded scalar body attachment after
verified exchange framing. The attachment binds the exact physical source
bytes, evaluation, runtime registration and exchange receipt. The owner checks
ordinary portable source paths, source hashes, identifier and statement ranges,
physical UTF-8 coordinates, declared scalar scopes, and ordered structure.
The pinned native producer establishes language syntax, definite lexical
binding and supported control facts. Arithmetic, calls, aliasing, arbitrary
truthiness, scope ambiguity and non-scalar behavior are outside this intake.

Go fixed-width signed 64-bit values and Python bounded integer literal
witnesses have distinct representations. Only independently selected exact
boolean assumptions bind Python parameters. The attachment constructs existing
ProgramBody, ProgramStatement and ProgramExpression values and preserves the
original version 6 model. Its digest names one exact occurrence. It grants
no authority to infer stable symbol equivalence, project conformance, effect
freedom, or execution evidence.

### [`python_scalar.rs`](../_code/python_scalar.rs)

Binds the independently selected Python scalar function, ordered exact boolean
parameter names, interpreter and worker identities to the immutable source and
evaluation key. It emits the exact worker request and strictly correlates
the bounded reply. The common native body boundary validates and lowers
the result to Program Semantics types. This adapter leaves the historical
Rust model and its test populations untouched.

The Go module dependency adapter consumes only compiler-admitted import
occurrences. Each target uses the complete selected source files of its
verified Go package. The snapshot owner separately supplies original Fortress
ownership. Exact logical Module contract files selected by that authority
remain part of the original snapshot and separate from the Go compiler input.
Unrecognized files in the selected module still prevent observation. Native
scope remains source-level and bounded by the original worker request.

### [`native_callable.rs`](../_code/native_callable.rs)

Defines a linked native declaration and lowered body separate from canonical
PSM assembly. The Go slot uses package, declaration name, and ordered compiler
scalar types. The Python slot is restricted to a zero-argument lexical
function in a separately verified regular module. Both retain exact origin,
exchange, source, and body occurrence identities. The optional original
logical owner is recorded independently from the slot.

### [`go_callable.rs`](../_code/go_callable.rs)

Checks the exact v3 package selection and rebuilds a legacy body request from
its admitted immutable files. The initial join uses one import-free ordinary
package, the same pinned Go version, and bounded default build tags. The body
must refer to the same declaration name and exact physical identifier span.

### [`go_fs_collector.go`](../_code/go_fs_collector.go)

An explicit bounded Go compiler worker observes source call positions and
compares the callee object with an independently packaged standard library
declaration. Its native exporter only opens admitted embedded archive members.
The supported source scope is one ordinary closed package file with no local
build variation. A shadowed binding or a dynamic callee has no standard
operation credit. Existing native worker builds keep their exact inputs.

### [`go_filesystem_observation.rs`](../_code/go_filesystem_observation.rs)

Validates bounded raw Go filesystem receipts against the exact supervised
request, physical data, native declaration and independently pinned library
assets. It keeps unsupported observations open and supplies only typed
call evidence to Snapshot Governance.

### [`python_filesystem.rs`](../_code/python_filesystem.rs)

Admits one bounded compile-only call shape from the selected Python source
and independently configured exact CPython worker. The existing scalar
source gate and producer identity bind an immutable view, evaluation, path,
function, installed profile and source bytes. The host compares exact live
READY before forwarding source. The reply must be one bounded canonical
line with exact correlation, a supported outcome and defensible UTF-8 byte
coordinates. This wire edition admits the exact reviewed worker and bootstrap
by digest. The host verifies their bytes before dispatch. The installed receiver, qualified CPython context and
source classification remain separate. Project runtime imports, execution
and effects are unestablished at this boundary.
