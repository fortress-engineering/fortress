# Code

## Role

The Code owns the universal source-region vocabulary, Source Profile and archetype model, deterministic Source Artifact compiler, the Rust structural adapter, PSM reference projection, structural evaluation, and shared Finding Model integration.

## Execution

The compiler consumes Project Filing inventory, canonical ownership, canonical `code_docs.md` responsibilities, exact bytes, profile adapter observations, and stable semantic references. The Rust adapter projects `syn` syntax and Cargo target observations without performing name, call, trait-selection, or macro-expansion semantics.

An adapter can identify a language for one exact source artifact when a shared
suffix does not establish its interpretation. The file-specific observation
must match the admitted repository-relative path and content digest. Identical
observations deduplicate. Conflicting or stale observations keep the language
unresolved and record a coverage limitation. That state never assumes the
suffix override, an available profile, or applicable semantic coverage.

## State

All registries, indexes, artifact conclusions, and summary counts are process-local deterministic derivations from immutable inputs.

## Failure Semantics

Invalid profile authority returns typed errors, while missing responsibility, unavailable required observation, unresolved archetype, forbidden composition, and missing generator identity become normalized rule findings only when applicable.

## Files

### [`python_test_declarations.rs`](../_code/python_test_declarations.rs)

Projects already admitted module-lexical function scopes using the fixed
pytest default test-name prefix. Physical indentation distinguishes direct
module statements from declarations inside a conditional or other compound
statement. Opaque headers and classes and visible test-name rebindings or
imports remain source-bound barriers. The projection has no runner, coverage
or verification authority.

### [`source.rs`](../_code/source.rs)

Defines Source Artifact Model v1, universal semantic regions and coverage, Source Profile/archetype contracts, generated and verification provenance, lightweight PSM projections, deterministic compilation, SOURCE-PROFILE-001/SOURCE-ARTIFACT-001 evaluation, and a human summary that explicitly distinguishes clean evaluation from remaining findings.

### [`rust.rs`](../_code/rust.rs)

Projects Rust/Cargo source roles, declarations, visibility, trait/implementation structure, attributes, and explicit macro-expansion limitations into the registered Rust Source Profile without creating a second program-semantic model. Rust tokenization invokes Repository Observation's neutral retained-input admission helper before parsing; inactive admission preserves ordinary profile observation.

### [`python_lexical.rs`](../_code/python_lexical.rs)

Admits one read-only compile-only worker response into a typed Python lexical observation. The caller selects a portable ordinary Python path in an immutable SourceView, its current EvaluationKey, observation mode, and trusted runtime and worker digest pins. The opaque request ID binds all those inputs and the exact file bytes. Admission rejects stale input, mismatched reply correlation, an unsupported worker protocol, malformed phase results, and out-of-scope coverage, provenance or UTF-8 byte spans. The shared JSON admission scan applies reply byte, nesting, token count, and encoded token limits before the strict decoder allocates the decoded report. A resource refusal is distinct from malformed JSON. Failed runtime or worker custody cannot report completed compiler phases. Output exhaustion retains only the phase status and an unavailable result.

This owner admits observations independently of process startup. It preserves syntax-only, partial, invalid source, unsupported and unavailable outcomes. Imports and calls remain unresolved. Observation facts neither enter the PSM nor change Source Profiles, ownership, findings, execution evidence or certification. Future host integration must establish actual runtime and dependency identity and bounded execution separately.

### [`native_regions.rs`](../_code/native_regions.rs)

Projects the shared source region vocabulary over a selected, already admitted
Go or Python receipt. Go declaration entries contribute positive declaration
facts and only confirmed source bodies contribute positive implementation
facts. Python function scopes contribute positive lexical declaration facts.
Unresolved Python import occurrences remain attached to unsupported dependency
coverage. Other regions remain unsupported. This output carries no inferred
absence, ownership, authored responsibility, semantic effects or verification
relationships. The canonical Source Artifact Model continues to use its
established ownership and verification inputs.

### [`python_filesystem_worker.py`](../_code/python_filesystem_worker.py)

Uses bounded compile-only Python source, exact worker readiness, and fixed isolated standard-library receiver evidence. The source shape and installed receiver remain separate from actual application binding and effect assessment.

### [`python_origin_worker.py`](../_code/python_origin_worker.py)

Uses a fresh pinned CPython installation to observe the top-level standard library import specification before loading the module. It validates isolated startup, cache and finder constraints, ordinary assets, and exact bytes. It accepts no project input and derives no project runtime origin.

### [`python_lexical_worker.py`](../_code/python_lexical_worker.py)

Provides the fixed CPython 3.12 or 3.13 compile-only worker for a trusted host.
The host independently selects the interpreter, runtime installation and worker
bytes, uses an isolated working directory and environment, and invokes the
interpreter with `-I -S -B`. The source request supplies bytes and exact identities.
It supplies no filenames, imports, executable, environment or interpreter flags.

Invoke the worker with `--serve --worker-ref DIGEST --runtime-ref DIGEST`. Keep
stdin empty until it publishes one bounded 4 KiB ASCII JSON line with schema
`fortress-host/python-lexical-ready/1` and status `READY`. The record binds both
pinned digests, exact grammar (`cpython3.12` or `cpython3.13`), platform profile
and verified limits.
`UNAVAILABLE` carries only a fixed reason and exits without reading source. The
host checks the launch-local record against its independent pins and sends a
single request of at most 192 KiB, then closes stdin. The existing lexical
response is a separate line of at most 1 MiB. Require the expected process exit
and complete frames. Timeout or cancellation discards the response and requires
bounded teardown. The no-input `--describe-runtime` operation describes compiler
pieces for independent pinning. It does not qualify the interpreter installation.

`LINUX_AS_CPU_V1` verifies hard and soft limits of 96 MiB address space and one
second direct-process CPU time before source intake and disables core dumps.
`WINDOWS_JOB_WALL_V1` verifies assignment to a private Job Object, 96 MiB process
and job commit limits, one active process and kill on close. The host owns the
wall deadline on both systems. Windows hard CPU-duration enforcement and Linux
denial of arbitrary child creation are outside these profiles. Unavailable or
incompatible OS limits prevent input admission. The profiles constrain the
reviewed worker process. They do not provide an operating-system sandbox.

The worker consumes one UTF-8 source buffer of at most 128 KiB. It verifies
canonical encoding and exact byte identity, bounds token, AST and projection
work, and invokes only CPython's tokenizer, AST parser, symbol table and module
compiler. It never loads the subject from disk, resolves imports, runs the
compiled module or publishes compiler warnings containing subject text. The
observation preserves unresolved imports and call targets, unsupported source
forms, encoding and contextual validity distinctions.

### [`python_static_imports.rs`](../_code/python_static_imports.rs)

Evaluates typed, admitted Python import declarations against a bounded
source-only inventory. The trusted caller independently selects the canonical
JCS/SHA-256 pin for a `fortress:python:static-import-roots:1` JSON object.
The object includes `source_view_ref`, `evaluation_ref`, `inventory` and
an explicitly ordered `roots` array. The accepted inventory value is
`COMPLETE_SOURCE_ONLY`. The resolver requires a current matching source view,
evaluation key and lexical request. The pin binds the configuration and root
order. The caller owns its provenance and the completeness premise.

Root paths are portable ASCII repository-relative paths. The resolver supports
one to four disjoint roots, at most 4,096 files and 16 MiB of selected bytes.
Only ordinary `.py` source names with ASCII identifier components contribute.
Case aliases, file and directory conflicts, unsupported entries, missing roots,
incomplete inventory and unavailable lexical facts return distinct errors.
Directories come from admitted files. Empty physical directories are outside
this model. The configuration is limited to 8 KiB and the report to 512 KiB,
256 declarations and 512 names.

Under the selected roots, a regular package initializer precedes a module
in a single root. The first concrete file wins across roots, including when it
shadows earlier namespace portions. A namespace retains its ordered represented
portions. Relative imports require the exact importing file to be the selected
origin in that scope. From-imports resolve their base while their member
binding remains unresolved. Missing results describe the admitted inventory.

The output is a separate `fortress:python:static-import-observation:1` record
with lexical request identity, root provenance, original scope and UTF-8
byte spans, and exact source target paths and digests when available.
Runtime imports, dynamic calls, runtime reachability, installed packages,
built-ins and native extensions remain outside the projection. It creates
no ownership, Architecture Evaluation edge or certification evidence.

An independently pinned root-scope document can select ordered source roots
before actual lookups. Snapshot Governance binds that scope to its observed
view and context before invoking the existing resolver. Typed source and
occurrence getters retain exact original digest, path, context, lexical scope,
and UTF-8 byte spans for downstream observational projections.

### [`python_scalar_worker.py`](../_code/python_scalar_worker.py)

Projects an exact, compile-only Python scalar function into a bounded native
body witness. The worker loads its fixed sibling lexical bootstrap only after
verifying the reviewed bootstrap digest against independently selected pins.
It installs the same pre-input operating-system gate, verifies its own and
the runtime identities, then emits a bounded
`fortress-host/python-scalar-ready/1` readiness record. The lexical worker and
its reply protocol retain their existing bytes. The explicit scalar CLI mode
selects this worker through a separate trusted registration.

The request names one ordinary Python source file, exact source bytes, one
function, and independently selected exact-bool parameter domains. Annotations
do not establish those domains. Supported bodies use exact bool values and
bounded signed 32-bit integer literals, definitely initialized local bindings,
simple assignment, Boolean negation, if/else and explicit uniform scalar
returns. Source spans use one-based byte columns and retain physical UTF-8
byte offsets, including CRLF. Any unsupported construct clears the body,
including calls, object or alias behavior, implicit returns, exceptional
control and integer operations outside the literal surface.

The worker compiles the source for contextual validation without running it.
It reports conditional native facts before Program Semantics admission and
does not establish actual caller argument types, runtime execution, semantic
conformance, governance, or certification.
