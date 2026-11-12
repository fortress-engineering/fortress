# Development Governance

## Purpose

Protect governing authority from candidate self-authorization.

## Responsibility

Own pure base-bound authorization requirements and independent change decisions.

## Scope

### Includes

Prepared transitions, registered protected roles, exact proposals, trusted grant injection, required assurance and explicit host coverage.

### Excludes

Approval services, signing, identity management, apply workflows, semantic analysis, release publishing and provider enforcement configuration.

## Relationships

### [State Governance](../state_governance/README.md)

**Types:** `depends_on`

Supplies existing immutable contracts; no semantic evaluator is duplicated.

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Supplies existing immutable contracts; no semantic evaluator is duplicated.

### [Repository Observation](../repository_observation/README.md)

**Types:** `depends_on`

Supplies existing immutable contracts; no semantic evaluator is duplicated.

### [Certification](../certification/README.md)

**Types:** `depends_on`

Supplies existing immutable contracts; no semantic evaluator is duplicated.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Supplies existing immutable contracts; no semantic evaluator is duplicated.

## Guarantees

Candidate text cannot supply a validated grant or amend its own judge. Permission preserves the original weakening and findings. Unknown authorization is never approval. Read-only preview is unmediated.

The v1 decision algebra reports semantic enforcement, explicitly required assurance,
protected authority and host coverage independently. A supported base-policy blocking
finding yields `DENY_SUPPORTED_VIOLATION`. Missing protected authorization yields
`REQUIRE_AUTHORIZATION`. Missing explicitly required assurance yields
`HOLD_REQUIRED_ASSURANCE`. Incomplete authority, scope or semantic evidence yields
`UNEVALUATED`. `PERMIT` requires all applicable premises; it describes a decision and
does not establish write mediation. Accepted baselines and exceptions remain visible
in the original declaration rather than erasing raw violations.

`TrustedBasePolicy::from_host` is a trusted embedding operation. The embedding must
pin original base authority and its evaluator independently of the candidate. Its
`GrantValidator` implementation must authenticate issuers, issuer policy, verifier
configuration and qualification evidence outside candidate control. Replacing the
validator with candidate code is outside this trusted boundary. Production does not
ship a validator that accepts repository JSON, commit messages, URLs or unsigned
portable statements. Test implementations are fixtures only. Policy selection
content is digest-bound in addition to its external root-policy reference.

`ValidatedGrant` has no public constructor or deserializer. A serializable
`HostAssertion` is accepted only as the result of an explicitly trusted validator;
its bytes alone have no authority. Exported grant receipts are
`PROVENANCE_ONLY_NOT_TRANSFERABLE`. Portable assurance integrity verification does
not validate external authorization. Historical declarations, profile assessments,
transitions and findings retain their original authority and meanings.

The preview CLI requires an explicit base-selection proposal. No public authority
default or owner approval is inferred from that file. It always uses
`NoGrantValidator` and `UnmediatedHost`; provider protection is `UNVERIFIED`.
Documented branch rules and provider-enforced rules remain separate facts. Real
provider approval adapters and write mediation belong to HOSTS and require owner
configuration; this package does not configure branch protection or publish releases.

Future MIGRATE, OVERLAY and HOSTS integrations consume these same exact-proposal
requirements and injected grant semantics. They must not add a permissive bypass,
rehydrate serialized receipts as grants, or replace original semantic findings with
authorization outcomes. Assessor upgrades require externally trusted qualification
bound to the exact candidate in addition to scoped authorization. Outages remain
explicit; an operational outage policy, if later selected by trusted authority,
cannot rewrite semantic truth.

AuthoritySnapshot v1 captures authoritative observed inputs and the registered
current evidence index. Hosts may explicitly include registered nonrecursive
publication/history bytes in the same exact proposal inventory. Those bytes are
bound by the proposal digest while retaining their original exclusion from the
Certification source fingerprint. Capture does not scan or authenticate all history,
copy large materializations, or reconstruct unavailable artifacts. `@authority/`
selectors identify explicit Standard, profile, assessor or exclusion identity changes
even when their authority was supplied outside the repository operation set.

`candidate_binding` reuses the original DeclarationBinding consumed by Certification
and portable assurance manifests. `portable_binding_status` checks equality only;
successful bundle integrity does not verify external permission. Public decision and
grant-receipt schemas are v1, use RFC 8785 JCS/SHA-256, and preserve explicit
version/resource errors. `from_json_str_bound` verifies a caller-supplied full result
digest. No new signing, provider identity or release authority is introduced.

Protection covers byte operations on registered governance surfaces, including
relocation and formatting edits. This conservative action boundary does not label
those edits semantic weakenings: the independent four-axis comparison retains that
distinction. Ordinary application implementation inputs outside protected scopes do
not acquire authorization requirements merely because they were compared.

Trusted hosts use `evaluate_change_with_grants` to retain a process-local
`ChangeEvaluation` and opaque `ValidatedGrant` handles. The report-only
`evaluate_change` entry point exposes the same decision without a receipt-to-grant
conversion. An assessor qualification assertion additionally identifies actual
external qualification evidence, the exact candidate, pinned original evaluator and
original qualification policy. A boolean or candidate certificate cannot substitute
for this separately verified provenance. The host port must authenticate its producer
and establish its admitted qualification scope outside candidate control.

**Candidate integration**

OVERLAY uses the same original-policy decision and external grant boundaries. A process-local pre-write candidate permit does not replace writer mediation; candidate files, portable proposals and unsigned reconciliations cannot construct it. Assessor qualification, finding-maintenance proofs and raw semantic outcomes remain independent.

Current authority-snapshot v2 captures use comparison-state v2 and its StateView v3-compatible public contract. v1 snapshots remain immutable historical inputs. This representation update does not validate external approval, change trusted policy or make serialized grants transferable.
