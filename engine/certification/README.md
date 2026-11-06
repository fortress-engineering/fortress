# Certification

## Purpose

Certification establishes whether sufficient current evidence supports every obligation in an exact certification profile for an exact repository source snapshot.

## Responsibility

Certification constructs immutable content-addressed evidence nodes including derived defeaters, validates their dependency DAG, binds current rule proofs and executed verification to obligations, evaluates deterministic certification status, projects Intended and Realized behavior into the Verified BFG, and validates immutable assessment manifests and exact selection indexes.

## Scope

### Includes

This Module owns current Evidence Graph v2 while retaining v1 schema compatibility, Certification Profile and result v1, distributed Verification Binding v1, assessment generation manifest v5 with retained v1-v4 readers, selection index v1, source-snapshot exclusion identity, test execution and defeater evidence semantics, affected-evidence closure, and Verified BFG v1.

### Excludes

This Module excludes semantic re-analysis, signatures, trusted issuer identity, timestamps, Git attestations, remote evidence, grades, hosted orchestration, badges, and claims that trusted assertions are mechanical proofs.

## Relationships

### [Architecture Evaluation](../architecture_evaluation/README.md)

**Types:** `depends_on`

Provides Module semantic-conformance rule identity and the scoped defeaters referenced by certification evidence.

### [Behavioral Realization](../behavioral_realization/README.md)

**Types:** `depends_on`

Provides realized checkpoints, edges, contradictions, and generated verification obligations.

### [Behavioral Semantics](../behavioral_semantics/README.md)

**Types:** `depends_on`

Provides Intended BFG identity, modeled Feature structure, and the semantic artifact whose digest becomes authority evidence.

### [Contract Coherency](../contract_coherency/README.md)

**Types:** `depends_on`

Provides the canonical ecosystem authority, requirements, Testing topology, and exact semantic source provenance.

### [Environmental Semantics](../environmental_semantics/README.md)

**Types:** `depends_on`

Provides environmental proof results, generated scenarios, and trusted environmental assertions without Certification re-evaluation.

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Provides deterministic finding fingerprints and canonical scoped defeaters attached to rule evidence.

### [Information Flow](../information_flow/README.md)

**Types:** `depends_on`

Provides information-flow proof coverage and explicit trusted endorsement or declassification dependencies.

### [Program Semantics](../program_semantics/README.md)

**Types:** `depends_on`

Provides the observed executable semantic artifact and source-bound coverage identity.

### [Reference Resolution](../reference_resolution/README.md)

**Types:** `depends_on`

Supplies the content-addressed stable identity-to-location projection whose current freshness is mandatory for full-snapshot certification.

### [Repository Observation](../repository_observation/README.md)

**Types:** `depends_on`

Provides exact stabilized repository bytes from which the recursion-free certification source identity is derived.

### [Semantic Analysis](../semantic_analysis/README.md)

**Types:** `depends_on`

Provides deterministic value-domain proof evidence and coverage without reparsing program source.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Owns the canonical full-snapshot profile and Standard identity whose applicable rule results become static-proof evidence.

### [State and Effect Analysis](../state_effect_analysis/README.md)

**Types:** `depends_on`

Provides current typestate and effect proof identities, coverage, and exact upstream bindings.

## Guarantees

Certification never changes upstream semantic conclusions, never treats a defeater as authored policy or as a replacement for raw failure, never treats CI configuration as execution, never allows ignored or filtered tests to satisfy full evidence, and never hides stale, missing, invalid, unsupported, or trusted inputs behind a top-level PASS.

**Provider evidence**

Provider evidence reports tool facts separately from source declarations, evidence sufficiency and certification conclusions. Normalization and a valid schema do not authenticate a producer. A successful invocation can contain failed tests or analysis findings; a failed invocation does not say that every individual test failed. Accepted verification failure produces `NOT_SATISFIED` with `EXECUTION_FAILED`, without inventing a Module `SUPPORTED_VIOLATION`.

Module Contract4 adds `external_verification: "SUCCESSFUL_EXECUTION"` to an existing Feature Requirement. Its `tests` list may be empty only with that explicit intent. Contract2 and Contract3 retain their nonempty governed Test ID requirements. CCG2 projects native verification intent separately from source-observed test support and never invents stable Test IDs for native test names. A local Testing Module still explicitly verifies its real parent Feature.

Authored `__fortress/governance/verification_bindings.json` maps those real Requirement identities to a provider, invocation scope and uniquely resolved native selectors. The compiler derives every external obligation from the CCG before reading bindings or imports. Missing bindings, missing reports, ambiguous selectors and two selected matching runs cannot erase obligations or select a newest green result. Existing governed Test IDs and original native package/target/qualified names use separate explicit namespaces.

The initial adapters are the existing controlled Cargo record, bounded JUnit XML and single-run/single-invocation SARIF2.1.0. Cargo retains the original unfiltered execution and inventory guarantees. An unsuccessful aggregate leaves individual outcomes unknown rather than falsely marking every test failed. Its older missing binary, argv and environment details remain unknown. The common Cargo record is additionally retained as an Observation in the Evidence DAG; it grants no new authentication or replacement qualification authority.

JUnit uses an explicit companion manifest for independently enumerated inventory, filters, attempts and actual process status. A missing companion yields observations only. The implemented XML1.0 subset rejects DTDs, namespace declarations, duplicate native identities, duplicate or mixed terminal elements, invalid declarations and malformed entities. Unknown extensions, retry metadata, disabled members and inconsistent aggregate counts withhold complete-run support. Lack of retry metadata does not invent an attempt count.

SARIF imports retain tool/rule/invocation scope, invocation status and positive findings separately. Empty results are not an independent rule inventory; missing results are unavailable. Unresolved external properties, extensions, overrides and suppressed or noncurrent results retain limitations. No external properties are fetched. These analysis observations cannot replace ExecutedTest evidence or Fortress StaticProof and cannot prove a Module semantic absence proposition.

The normalized envelope binds original payload bytes, exact metadata, native inventory, complete execution descriptors and explicit limitations. A complete retained test run requires nonempty independently enumerated inventory, known unfiltered selection, all members enabled and present, exact single attempts, no retry metadata and known terminal outcomes. Inventory accounting and invocation success are separate propositions. Shared ternary ALL/ANY preserves accepted failure versus missing support; an unknown premise cannot manufacture a successful proof.

The host injects acceptance separately. Retained execution reuse requires the exact independently supplied current binary, tool, ordered argv, directory, input and environment dependency descriptors, with no unknown dependency. Otherwise a genuinely fresh run is required. A producer name, local configuration file, timestamp, cached green status or serialized freshness marker is insufficient. Local unsigned reporting remains `UNVERIFIED`. The explicit CLI host-admission format cannot assert authentication or construct fresh execution receipts; policy files physically within the candidate repository are refused.

Registered native execution requires an explicit physical-project trust grant for the exact registered command before invoking its trusted executor. The executor owns bounded capture and process-tree supervision through OPS. Source, ProgramContext, inventory, physical project identity and executable bytes are checked before and after the run. Unresolved child records, drift, malformed output and incomplete storage cleanup cannot mint the opaque single-use fresh receipt. Operational and resource failures remain errors rather than software-policy findings.

ControlLayout4 registers required authored bindings and the closed nonrecursive import pair `__fortress/evidence/imports/<envelope-sha256>/{envelope.json,payload.bin}`. Loading selected imports verifies exact content identities and reconstructs normalized metadata from original bytes. It does not execute project code or grant trust. The selected EvidenceInputSet binds all selected envelope/payload/inventory identities to source, context and authority, including unavailable members. Availability does not change its identity or the declaration. Deleting cached bytes withholds support while retaining known requirements and selections.

Assessment2 binds that evidence-input digest. StateView2 carries the complete input set and native selection provenance. GenerationManifest5 binds ControlLayout5 and the exact application evidence-input context. Historical assessment, StateView, layout and generation schemas remain retained with explicit readers and unchanged historical digest contracts; StateView1 cannot reinterpret Assessment2 or new execution-failure metadata.

`fortress evidence junit|sarif payload [--manifest path] [--output path]` emits canonical observations without executing project code. Keep the exact original payload alongside the canonical envelope when retaining the closed import pair. `fortress assess [path] --evidence-inputs selection.json [--provider-policy host-policy.json]` assesses the explicit selection; no supplied host admission means no implicit trust. Declare and StateView accept the same explicit selection options. Native API callers can instead obtain fresh admission from the registered trusted execution port.

Application assessment and the older Rust-only implementation qualification remain separate ports. Native external execution can satisfy its declared application requirement while the overall application remains partial for unsupported semantics or other missing evidence. The Rust-only qualification port retains pending native intent, including mixed legacy/native requirements, and never interprets an empty Rust test list as successful native verification. Evidence from Python tests does not add Python program-semantics support or establish absence of arbitrary effects.

Input and canonical provider documents are bounded at 32 MiB, with 100,000 records, 10,000 authored selectors, 1,024 selected imports and a 64 MiB conservative normalized metadata charge. XML depth is bounded at 64, events at one million, attributes at 256 and attribute/native-name bytes at 64 KiB. JSON depth and token limits apply before typed traversal. Aggregate selected inputs and generated proof metadata also have bounded admission. Allocation charges are resource controls, not measured RSS or performance claims.

The independent standard-library replay consumer imports no Rust normalizer or evaluator. Twelve manual protocol controls and 32 frozen XML/SARIF vectors exercise positive, negative and uncertainty cases through the real native CLI. Expected outcomes precede native CLI comparison and distinguish synthetic host premises from actual execution. The separate native demonstration executes a real Python unittest assertion at its original source paths without fake native Test IDs. The mandatory `PROVIDER_EVIDENCE` gate certifies protocol correctness, not speed, population precision, false-positive rates or independent human adjudication. Full real-world external assurance remains a separate research question.

Primary format references are the [OASIS SARIF2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html), [JUnit reporting documentation](https://docs.junit.org/5.12.0/user-guide/) and the [pinned quick-xml0.42 Reader API](https://docs.rs/quick-xml/0.42.0/quick_xml/reader/struct.Reader.html). JUnit report dialects vary; the bounded subset above is explicit rather than a universal interchange claim.

Automated qualification scope is a separate typed observation attached through `ConformanceDeclaration::qualification_scope`. The caller supplies independently admitted tool metadata and every current input identity; copying the report inputs is not independent validation. This observation preserves declaration-v1 bytes, application truth, profile satisfaction and proof leaves. It explicitly reports TOOL_CAPABILITY_METADATA, application_evidence=false and UNVERIFIED authenticity. A tool benchmark cannot prove application execution or promote Standard defaults.
