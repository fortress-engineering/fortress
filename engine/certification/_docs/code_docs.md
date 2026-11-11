# Code

## Role

Certification Code defines content-addressed evidence nodes and DAG validation, certification aggregation, source identity, executed-suite evidence, distributed binding validation, affected closure, and Verified BFG projection.

## Execution

The implementation consumes one stabilized source identity, one already-compiled semantic artifact stack including current CCG-bound Reference Resolution and Module semantic-conformance projections, canonical semantic defeaters, the resolved assurance requirement manifest, applicable rule results, one canonical local Rust suite result, and distributed Testing bindings before building evidence nodes in dependency order. Semantic rule evidence depends on its scoped defeater nodes, freshness failures produce defeating evidence without changing obligation status algebra, non-applicable rules are not mislabeled as conformance proof, and unsupported applicable claims remain missing evidence. Missing assurance evidence is reported as `REQUIRED_EVIDENCE_MISSING` without rewriting an upstream semantic `UNKNOWN`.

## State

All state is process-local and deterministic. Node IDs are SHA-256 over canonical node bodies excluding their IDs, while historical validity and current-subject freshness remain distinct conclusions.

## Failure Semantics

Missing references, digest corruption, cycles, invalid bindings, unsupported authority, or noncanonical ordering return typed errors; valid negative evidence becomes FAIL, prior-subject evidence becomes STALE, insufficient evidence becomes MISSING, and status precedence is `INVALID > FAIL > STALE > MISSING > PASS`.

## Files

### [`certification.rs`](../_code/certification.rs)

Implements Evidence Graph including the dedicated defeater evidence class, certification, source identity, execution evidence, affected closure, and Verified BFG semantics.

### [`control_manifest.rs`](../_code/control_manifest.rs)

Validates immutable assessment generation manifests and exact selection indexes, including safe members, logical external artifacts, canonical ordering, and content-addressed generation identity. Selection keys must be strictly increasing: two generations cannot compete for one context, while independent contexts may share a generation. Current manifest/layout v4 supports application and implementation-quality publications with exact provider input identity. Retained manifest/layout pairs v1/v1, v2/v2 and v3/v3 preserve their original meaning; mismatched pairs are invalid.

### [`declaration.rs`](../_code/declaration.rs)

Defines strict v1 ConformanceDeclaration reporting, complete trusted dimension/claim manifests, associated scoped profile references, raw semantic truth, exact slot/instance/context/universe identities, source coverage, provenance partitions, original proof graphs and residue. RFC 8785 bytes have no unrestricted top-level PASS and never contain local cache availability. VerificationSessionReport reports exact local materializations separately.

### [`assessment.rs`](../_code/assessment.rs)

Traverses every trusted required obligation. SATISFIED, NOT_SATISFIED, NOT_EVALUABLE and INVALID are distinct. A caller supplies expected authority and independently admitted payload **and metadata** identities, authentication, assumptions and assessment time. Producer names and raw payload hashes alone confer no authenticity or semantic sufficiency. Shared ALL/ANY proof structure is evaluated after exact subject/context/scope/class/predicate/trust/freshness admission. Rule checks cannot discharge Module policies; ALLOW and nonapplicability cannot discharge evaluability or DENY. Canonical assessments bind the complete obligation manifest and explicit acceptance policy. Parsing an assessment validates shape; independent replay establishes its conclusion.

### [`application.rs`](../_code/application.rs)

**Declared-flow reporting**

The application composer can receive existing Information Flow per-sink rule projections with exact selected project/Module scope. It preserves raw truth, original findings, canonical defeaters and transformation assumptions in declarations and assessments, and retains the same inputs for portable replay. It does not rerun flow semantics or admit editable authorization claims.

Composes existing typed semantic and rule results using Standard-owned application-assessment-policy v1. Scope references bind premises separately when call edges are shared across claims. Required claim identities come from effective authored authority, independently of result enumeration. Native profile defaults and existing full implementation qualification are unchanged. Supported static leaves are reconstructible from exact binding, raw claim and original premise; they remain UNVERIFIED local provenance. Unknown/failed applications are valid reporting results and require no fabricated RustSuiteExecution.

Manifest v3 pairs with layout v3 and adds APPLICATION generations with recomputed exact profile/scope/context selection keys. Editions v1/v1 and v2/v2 retain their original bytes and digest meaning; unrelated index selections are preserved.

Static premise payload identity is SHA-256 of JCS `["static-claim-premise-v1", binding, SHA256(JCS(raw_claim)), upstream_premise_ref]`. Metadata identity separately binds every evidence field. The trusted expected artifact manifest prevents omission of required immutable projections. Reporting dimension rule membership is explicit immutable Standard policy; PROGRAM_SEMANTICS remains Module policy truth, with registered semantic rule checks reported separately.

Unknown, nonapplicable and authorization records emit observation-only metadata, never synthetic absence proof. Known unavailable premises have an explicit UNAVAILABLE proposition. Native semantic evidence is scoped to the complete upstream claim instance, including selector, policy, ProgramContext and governed-universe binding.

### [`provider.rs`](../_code/provider.rs)

Defines context-bound unsigned provider envelopes, explicit native versus governed identity namespaces, complete inventory/retry descriptors, unique borrowed selector indexes and external host admission. Unknown execution dependencies require an actual fresh registered execution; producer names and candidate fresh markers cannot grant it. Shared proof leaves preserve known execution failure separately from software policy truth.

### [`provider_inputs.rs`](../_code/provider_inputs.rs)

Compile the complete native Requirement manifest, authored selectors and exact selected evidence-input set. Missing bytes never erase known obligations; the global normalized budget and single prepared provider index bound retained work.

Declaration scope observations consume generic Standard-owned exact metadata and independently supplied current inputs. They preserve canonical declaration-v1 truth and cannot be parsed as application AssessmentEvidence. GenerationManifest5 uses ControlLayout5; retained v1-v4 readers keep their original digest meanings.

### [`state_view.rs`](../_code/state_view.rs)

Owns neutral StateView data and validation, including v3 retained portable replay observations. Historical v1/v2 bytes and meanings remain supported. Snapshot Governance reexports the historical API path; lower comparison owners consume this data without importing orchestration.

### [`portable.rs`](../_code/portable.rs)

Defines portable-bundle v1 manifests and typed errors. SHA-256 of exact original bytes (`wire_digest`) preserves historical encodings. New public `jcs_digest` values identify RFC 8785 UTF-8 JSON; binary provider reports have no JSON digest. Integers outside the exact 53-bit public range require canonical decimal-string fields. Duplicate keys, nonfinite numbers and lone surrogates are invalid; Unicode is never normalized. Sets use their documented stable ordering, not filesystem or timestamp order.

### [`bundle.rs`](../_code/bundle.rs)

Assembles one compact directory from immutable products supplied by the composition root. `manifest.json` and `statement.json` are JCS. Artifact members preserve original bytes and use content-addressed relative names. Required DAG nodes, leaf payloads, complete declarations/assessments, exact Standard/profile assets and provider records remain bound. Large PSM and other reproducible projections are identified rather than copied. Their materialization is necessary to recompute analyzer conclusions; checking a digest is not recomputing those conclusions.

An in-toto Statement v1 uses `_type=https://in-toto.io/Statement/v1`, a SHA-256 source subject and an explicit caller-selected HTTPS predicate URI ending in `/v1`. No default publication namespace, license, signature, issuer, approval or registry is selected. The consumer must independently supply the expected predicate URI. Namespace selection does not authenticate ownership.

The predicate binds the complete manifest digest, source/context/authority and selected profile composition. Unsigned authenticity and assurance remain UNVERIFIED. Independent integrity means that public bytes, required references and the **declared** proof/assessment algebra agree. It does not establish producer identity, actual execution, semantic correctness, authoring completeness, external authorization or current-source freshness. A producer can rewrite an entirely unsigned record; hashes are not a trust root.

Native certification checks also bind the source observation, Standard authority, original profile definition, obligation support edges, trusted-assertion closure, aggregate verdict and summary counts. Application-only graph profiles bind the exact application assessment composition. A consistent digest inventory cannot excuse disagreement among these public records.

StateView3 retains an application replay observation using existing EvidenceGraph2 semantics. StateView1/2 and earlier CONTROL generations retain their original identities and readers. An application-only record does not acquire implementation certification. A historical declaration/assessment pair without original replay inputs remains incomplete; the exporter never reconstructs it under current authority.

Offline consumers read only listed members. Admission limits are 32 MiB per artifact, 128 MiB aggregate, 128 artifacts, 64 JSON nesting levels and bounded proof/provider inventories. Optional ZIP input is read without extraction and rejects unsafe names, links, duplicate identities, encryption, excess depth/size or expansion. These are resource-safety limits, not performance certification thresholds.

Future distribution, extension, pilot and Standard release consumers must qualify their readers against these schemas, independent replay vectors, exact subject/profile/context binding and projection losses. Migration must preserve historical digest algorithms. Future identity/signature consumers may authenticate these bytes but cannot infer execution or semantic correctness from a signature. State comparison uses explicit original bindings and supported evidence; a new envelope or historical verdict is not implementation improvement or permission.

Original identity recipes remain separate from public JCS. Native source identity hashes repository-relative UTF-8 paths in stable order, framing each path and original content with its unsigned 64-bit big-endian byte length. The source-observation contract selects the inventory; machine paths and timestamps are excluded. Local quality source fingerprints use their own domain and must not be substituted. Original ProgramContext identity hashes its exact pretty JSON plus LF, retained as `program_context_utf8`. Original Standard identity hashes length-framed `standard_manifest`, raw manifest bytes and sorted rule path/raw-byte pairs. EvidenceGraph2 node identity hashes compact original JSON with ordered fields `kind`, `subject`, `result`, `inputs`, `producer`, `producer_semantic_version`, `evidence_class`, `payload`, excluding the node ID; original payload maps use UTF-8 lexical ordering. The public consumer verifies these retained recipes independently while artifact `jcs_digest` values always use RFC 8785. A public digest does not upgrade historical authority or authenticate original inputs.

The qualified Microsoft SARIF Viewer 3.4.5 experiment accepted nine producer vectors and retained identities and properties. Its display converts non-failure `none` levels to note/warning and shows the first observed code flow in the details pane. Exported SARIF retains every supported flow and reports these presentation losses. Empty or hidden UI rows cannot establish conformance. Research timings and machine conditions are separate diagnostics, with no latency certification threshold.

Bounded behavior owner projections enter compose_application_with_semantic_rules independently of FLOW. Exact context and selected project/Module scope are validated before ordinary RuleCheck proof leaves and obligations are composed. Raw static verdicts, progressive disposition and assurance remain distinct. Conditional FLOW annotations cannot prove checkpoint execution, while separate provider execution evidence cannot replace static path completeness. Public offline verification checks the recorded source/context/identity and reporting closure without asserting semantic correctness, producer authentication or runtime execution.
