# Data

## Role

Certification Data defines authored profile/binding authority and derived Evidence Graph, certification result, and Verified BFG representations.

## Origin

Maintainers author schemas; the Standard owns profiles; Testing Modules author bindings; Fortress derives evidence and certification artifacts.

## Semantics

Schemas preserve evidence authority class, content identity, dependency provenance, exact status algebra, and separate intended, realized, and verification dimensions.

## Validity

All schemas are canonical JSON Schema 2020-12 documents with unique registered identities.

## Lifecycle

Incompatible semantic changes advance schema versions rather than silently changing persisted evidence meaning.

## Files

### [`generation_manifest_schema_v1.json`](../_data/generation_manifest_schema_v1.json)

Retains source-bound immutable generation manifests using control layout v1 with included and external artifact descriptors.

### [`generation_manifest_schema_v2.json`](../_data/generation_manifest_schema_v2.json)

Retains source-bound immutable generation manifests using control layout v2. Historical v1 manifests retain their original layout and content-address semantics; a schema/layout version mismatch is rejected.

### [`selection_index_schema_v1.json`](../_data/selection_index_schema_v1.json)

Defines the sorted exact selection-key to generation-digest index.

### [`certification_profile_schema_v1.json`](../_data/certification_profile_schema_v1.json)

Defines Certification Profile v1.

### [`certification_result_schema_v1.json`](../_data/certification_result_schema_v1.json)

Defines deterministic Certification result v1.

### [`evidence_graph_schema_v1.json`](../_data/evidence_graph_schema_v1.json)

Preserves content-addressed Evidence Graph v1 before derived defeaters were a dedicated evidence class.

### [`evidence_graph_schema_v2.json`](../_data/evidence_graph_schema_v2.json)

Defines the current content-addressed Evidence Graph, including dedicated `DEFEATER` evidence nodes and coverage counts.

### [`verification_binding_schema_v1.json`](../_data/verification_binding_schema_v1.json)

Defines distributed Testing-owned verification bindings.

### [`verified_bfg_schema_v1.json`](../_data/verified_bfg_schema_v1.json)

Defines Verified Behavioral Flow Graph v1.

### [`conformance_declaration_schema_v1.json`](../_data/conformance_declaration_schema_v1.json)

Strict multidimensional raw reporting, complete manifests, proof requirements, scoped profile references, provenance and residue; no global PASS.

### [`profile_assessment_schema_v1.json`](../_data/profile_assessment_schema_v1.json)

Strict exact-profile sufficiency outcomes with typed blockers, declaration/obligation/acceptance bindings and explicit uncertainty.

### [`state_view_schema_v1.json`](../_data/state_view_schema_v1.json)

Neutral ungoverned/invalid/partial/negative/complete endpoints for later comparison. Observation survives unavailable authority.

### [`generation_manifest_schema_v3.json`](../_data/generation_manifest_schema_v3.json)

Layout-v3 immutable quality/application publication; APPLICATION binds exact profile/scope/context selection. Previous schema/layout assets remain immutable.

### [`profile_assessment_schema_v2.json`](../_data/profile_assessment_schema_v2.json)

Binds the complete selected provider input set and distinguishes accepted verification failure from a Module policy violation. The v1 reader/schema retain their original meanings and bytes.

### [`provider_evidence_schema_v1.json`](../_data/provider_evidence_schema_v1.json)

Closed normalized provider protocol with exact raw payload, native or governed namespace, inventory, attempts, invocation scope, producer claims and explicit unknown execution dependencies.

### [`provider_bindings_schema_v1.json`](../_data/provider_bindings_schema_v1.json)

Authored mappings name existing external-verification Requirements and uniquely selected original native tests; they confer no host trust.

### [`evidence_inputs_schema_v1.json`](../_data/evidence_inputs_schema_v1.json)

Complete selected content identities bind application source, ProgramContext and authority independently of cache availability.

### [`provider_admission_schema_v1.json`](../_data/provider_admission_schema_v1.json)

Explicit external host admission format. It cannot assert authentication or fresh execution; the CLI refuses physical in-candidate policy files.

### [`state_view_schema_v2.json`](../_data/state_view_schema_v2.json)

Current neutral endpoint with Assessment2 and exact evidence inputs; StateView1 retains only historical Assessment1 semantics.

### [`generation_manifest_schema_v4.json`](../_data/generation_manifest_schema_v4.json)

Retained fourth-edition immutable generation metadata binds ControlLayout4; application selection includes the exact provider input digest. Historical generation editions retain their bytes and meanings.

### [`generation_manifest_schema_v5.json`](../_data/generation_manifest_schema_v5.json)

Current layout-v5 generation metadata preserves exact provider-aware application selection. Local quality generations additionally bind compact automated tool qualification; native application semantics do not fabricate that test-owned artifact.

### [`qualification_scope_schema_v1.json`](../_data/qualification_scope_schema_v1.json)

Separate exact declaration/tool-scope metadata observation. Application evidence is always false and authenticity UNVERIFIED; no application truth or proof-manifest field changes.

### [`state_view_schema_v3.json`](../_data/state_view_schema_v3.json)

Versioned public portable-evidence contract. Its exact registered identity, strict fields, independent reader and compatibility are recorded in the shared schema catalog. Historical schemas retain their prior semantics.

### [`assessment_replay_schema_v1.json`](../_data/assessment_replay_schema_v1.json)

Versioned public portable-evidence contract. Its exact registered identity, strict fields, independent reader and compatibility are recorded in the shared schema catalog. Historical schemas retain their prior semantics.

### [`portable_authority_schema_v1.json`](../_data/portable_authority_schema_v1.json)

Versioned public portable-evidence contract. Its exact registered identity, strict fields, independent reader and compatibility are recorded in the shared schema catalog. Historical schemas retain their prior semantics.

### [`portable_bundle_schema_v1.json`](../_data/portable_bundle_schema_v1.json)

Versioned public portable-evidence contract. Its exact registered identity, strict fields, independent reader and compatibility are recorded in the shared schema catalog. Historical schemas retain their prior semantics.

### [`assurance_statement_schema_v1.json`](../_data/assurance_statement_schema_v1.json)

Versioned public portable-evidence contract. Its exact registered identity, strict fields, independent reader and compatibility are recorded in the shared schema catalog. Historical schemas retain their prior semantics.

### [`portable_verification_schema_v1.json`](../_data/portable_verification_schema_v1.json)

Versioned public portable-evidence contract. Its exact registered identity, strict fields, independent reader and compatibility are recorded in the shared schema catalog. Historical schemas retain their prior semantics.

### [`projection_loss_schema_v1.json`](../_data/projection_loss_schema_v1.json)

Versioned public portable-evidence contract. Its exact registered identity, strict fields, independent reader and compatibility are recorded in the shared schema catalog. Historical schemas retain their prior semantics.

### [`generation_manifest_schema_v6.json`](../_data/generation_manifest_schema_v6.json)

Binds new generations to CONTROL layout 6 while retaining each earlier generation/layout pair and the same evidence/provenance distinctions.

### [`generation_manifest_schema_v7.json`](../_data/generation_manifest_schema_v7.json)

Versioned OVERLAY interface: exact immutable proposals and actual-state separation, original authority bindings, compatible registered CONTROL records and explicit uncertainty. Historical versions retain their original identities.
