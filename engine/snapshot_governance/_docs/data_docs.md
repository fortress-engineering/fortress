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

### [`bootstrap_proposal_schema_v1.json`](../_data/bootstrap_proposal_schema_v1.json)

Defines the deterministic non-authoritative discovery proposal that separates observed repository/Cargo facts, reviewed authored content, unresolved owner choices, exact source identity, and deferred governed legacy-residue evaluation.

### [`environment_contracts.json`](../_data/environment_contracts.json)

Declares the live filesystem document-read boundary and its truthful success/failure outcome space for shared environmental handling analysis.

### [`identity_migration_schema_v1.json`](../_data/identity_migration_schema_v1.json)

Defines the exact-snapshot, reviewable migration plan for legacy symbol references and semantic finding-governance identities, including occurrence counts and dependency-bound source digests.

### [`quality_certificate_schema_v2.json`](../_data/quality_certificate_schema_v2.json)

Defines the retained pre-control-layout quality certificate representation. Its reader is retired and migration preserves exact historical bytes.

### [`quality_certificate_schema_v3.json`](../_data/quality_certificate_schema_v3.json)

Defines the current generation-bound quality certificate with logical artifact IDs, exact source, gates, digests, and explicit unverified authenticity.

### [`contract_rule.json`](../_data/contract_rule.json)

Carries the draft normative rule governing canonical CCG compilation and currently supported logical coherency.

### [`documentation_rule.json`](../_data/documentation_rule.json)

Carries the draft normative rule for the closed companion-document grammar, flat-file catalogs, scalable structured Data/Info collection catalogs, Module relationships, and link synchronization.

### [`module_rule.json`](../_data/module_rule.json)

Carries the draft normative rule for the complete recursive Project Filing System grammar and its Project Model evaluator.

### [`ownership_rule.json`](../_data/ownership_rule.json)

Carries the draft normative rule record interpreted by the ownership evaluator.

### [`repository_snapshot_schema_v2.json`](../_data/repository_snapshot_schema_v2.json)

Defines the version-two snapshot identity that binds distributed Module contracts and their resolved-set fingerprint.

### [`snapshot_audit_schema_v4.json`](../_data/snapshot_audit_schema_v4.json)

Defines the version-four machine representation for snapshot audit records, including raw normative findings, orthogonal lifecycle/disposition/enforcement, non-normative architecture diagnostics, and explicitly unsupported analysis classes.

### [`snapshot_audit_schema_v5.json`](../_data/snapshot_audit_schema_v5.json)

Defines the retained audit representation with an explicit `NOT_APPLICABLE` rule state, stable applicability reasons, and summary counts that exclude non-applicable rules from PASS.

### [`snapshot_audit_schema_v6.json`](../_data/snapshot_audit_schema_v6.json)

Defines the retained version-six audit representation with raw finding evidence eligibility, stable eligibility reasons, and progressive-enforcement summaries that distinguish advisory non-blocking findings from baseline or exception governance.

### [`snapshot_finding_schema_v2.json`](../_data/snapshot_finding_schema_v2.json)

Defines the version-two machine representation and validation boundary for stable or explicitly baseline-ineligible snapshot finding records.

### [`snapshot_finding_schema_v3.json`](../_data/snapshot_finding_schema_v3.json)

Defines the current finding representation with orthogonal raw enforcement eligibility and a stable optional reason while preserving finding identity and conformance state.

### [`test_boundary_rule.json`](../_data/test_boundary_rule.json)

Carries the draft normative rule for recursive parent-local Feature verification boundaries.

### [`traceability_rule.json`](../_data/traceability_rule.json)

Carries the draft normative rule record interpreted by the traceability evaluator.

### [`query_request_schema_v1.json`](../_data/query_request_schema_v1.json)

Registers the transport-independent v1 method envelope with strict per-method parameter schemas, explicit state/context references and bounded pagination.

### [`query_response_schema_v1.json`](../_data/query_response_schema_v1.json)

Registers canonical v1 status, diagnostics, pages, explanations, proposals, lifecycle results and structured failures with exact request and loaded-state identities.

### [`query_request_schema_v2.json`](../_data/query_request_schema_v2.json)

Adds exact-state transition requests while retaining v1 readers unchanged.

### [`query_response_schema_v2.json`](../_data/query_response_schema_v2.json)

Versioned transition summary and complete paged result envelope.

### [`governance_proposal_schema_v1.json`](../_data/governance_proposal_schema_v1.json)

Derived read-only baseline/exception maintenance proposal, original authority, compared states, retirement records and unapplied postimage; never a grant.

### [`snapshot_audit_schema_v7.json`](../_data/snapshot_audit_schema_v7.json)

Current audit projection adds unresolved baseline identities and exception review/authentication facts. Absent IDs no longer populate the legacy resolved count; all original raw findings and progressive fields remain visible.

### [`finding_lifecycle_schema_v1.json`](../_data/finding_lifecycle_schema_v1.json)

Versioned read-only aggregate binds current raw/progressive projections, exact original/current states, explicit review time and comparable retirement records without changing their owners or meanings.

### [`query_request_schema_v3.json`](../_data/query_request_schema_v3.json)

Adds typed flow_author parameters for readable, unapproved operation-policy proposals. Versions 1 and 2 retain their meanings and reject the newer method.

### [`query_response_schema_v3.json`](../_data/query_response_schema_v3.json)

Preserves the existing bounded response family under protocol v3, including explicit proposal acceptance and context bindings. Source preparation remains an explicit adapter step.

### [`query_request_schema_v4.json`](../_data/query_request_schema_v4.json)

Adds the typed behavior_author preview under protocol v4 while preserving versions 1–3. An explicitly prepared immutable context is required; response formatting never starts analysis.

### [`query_response_schema_v4.json`](../_data/query_response_schema_v4.json)

Adds the typed behavior_author preview under protocol v4 while preserving versions 1–3. An explicitly prepared immutable context is required; response formatting never starts analysis.

### [`identity_migration_schema_v2.json`](../_data/identity_migration_schema_v2.json)

Version 2 adds the exact physical source identity required to reject stale identity migration reviews before writes. Version 1 remains a historical preview schema; executable application uses MigrationPlan v1 and the common writer.

### [`candidate_request_schema_v1.json`](../_data/candidate_request_schema_v1.json)

Versioned OVERLAY interface: exact immutable proposals and actual-state separation, original authority bindings, compatible registered CONTROL records and explicit uncertainty. Historical versions retain their original identities.

### [`hypothetical_evaluation_schema_v1.json`](../_data/hypothetical_evaluation_schema_v1.json)

Versioned OVERLAY interface: exact immutable proposals and actual-state separation, original authority bindings, compatible registered CONTROL records and explicit uncertainty. Historical versions retain their original identities.

### [`candidate_reconciliation_schema_v1.json`](../_data/candidate_reconciliation_schema_v1.json)

Versioned OVERLAY interface: exact immutable proposals and actual-state separation, original authority bindings, compatible registered CONTROL records and explicit uncertainty. Historical versions retain their original identities.

### [`query_request_schema_v5.json`](../_data/query_request_schema_v5.json)

Versioned OVERLAY interface: exact immutable proposals and actual-state separation, original authority bindings, compatible registered CONTROL records and explicit uncertainty. Historical versions retain their original identities.

### [`query_response_schema_v5.json`](../_data/query_response_schema_v5.json)

Versioned OVERLAY interface: exact immutable proposals and actual-state separation, original authority bindings, compatible registered CONTROL records and explicit uncertainty. Historical versions retain their original identities.

### [`governance_proposal_schema_v2.json`](../_data/governance_proposal_schema_v2.json)

Current governance proposals preserve original/current endpoints through lossless comparison projections, including legacy native identities. No original schema bytes, semantic finding identities, historical verdicts or authorization proofs are rewritten.

### [`bootstrap_proposal_schema_v2.json`](../_data/bootstrap_proposal_schema_v2.json)

Defines the immutable reviewed onboarding record, complete source inventory, authored Module choices, selected authority, exact candidate assessment, reviewed residue origin and shared migration plan. Prediction never constitutes current certification or approval.

### [`onboarding_request_schema_v1.json`](../_data/onboarding_request_schema_v1.json)

Defines explicit readable native/canonical project identity, Module bindings, authored contracts, profile selections, exact canonical source operations and baseline choices. Defaults infer no permissions.

### [`onboarding_result_schema_v1.json`](../_data/onboarding_result_schema_v1.json)

Records verified application and receipt identities, actual governance, read-only status and doctor observations, and explicit absence of established execution certification.
