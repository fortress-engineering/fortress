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

Composes existing typed semantic and rule results using Standard-owned application-assessment-policy v1. Scope references bind premises separately when call edges are shared across claims. Required claim identities come from effective authored authority, independently of result enumeration. Native profile defaults and existing full implementation qualification are unchanged. Supported static leaves are reconstructible from exact binding, raw claim and original premise; they remain UNVERIFIED local provenance. Unknown/failed applications are valid reporting results and require no fabricated RustSuiteExecution.

Manifest v3 pairs with layout v3 and adds APPLICATION generations with recomputed exact profile/scope/context selection keys. Editions v1/v1 and v2/v2 retain their original bytes and digest meaning; unrelated index selections are preserved.

Static premise payload identity is SHA-256 of JCS `["static-claim-premise-v1", binding, SHA256(JCS(raw_claim)), upstream_premise_ref]`. Metadata identity separately binds every evidence field. The trusted expected artifact manifest prevents omission of required immutable projections. Reporting dimension rule membership is explicit immutable Standard policy; PROGRAM_SEMANTICS remains Module policy truth, with registered semantic rule checks reported separately.

Unknown, nonapplicable and authorization records emit observation-only metadata, never synthetic absence proof. Known unavailable premises have an explicit UNAVAILABLE proposition. Native semantic evidence is scoped to the complete upstream claim instance, including selector, policy, ProgramContext and governed-universe binding.

### [`provider.rs`](../_code/provider.rs)

Defines context-bound unsigned provider envelopes, explicit native versus governed identity namespaces, complete inventory/retry descriptors, unique borrowed selector indexes and external host admission. Unknown execution dependencies require an actual fresh registered execution; producer names and candidate fresh markers cannot grant it. Shared proof leaves preserve known execution failure separately from software policy truth.

### [`provider_inputs.rs`](../_code/provider_inputs.rs)

Compile the complete native Requirement manifest, authored selectors and exact selected evidence-input set. Missing bytes never erase known obligations; the global normalized budget and single prepared provider index bound retained work.

Declaration scope observations consume generic Standard-owned exact metadata and independently supplied current inputs. They preserve canonical declaration-v1 truth and cannot be parsed as application AssessmentEvidence. GenerationManifest5 uses ControlLayout5; retained v1-v4 readers keep their original digest meanings.
