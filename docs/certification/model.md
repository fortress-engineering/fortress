# 08 — Certification Model

**Status:** Normative certification architecture
**Authority class:** Certification

## Certification thesis

Fortress certification is not a transient green terminal line.

It is a reproducible, content-addressed claim that a defined engineering scope satisfied a defined Fortress Engineering Standard edition under defined tools and inputs.

## Certification unit

A certification unit is the smallest reusable proof node in the certification DAG.

Examples:

- source formatting;
- TypeScript strict typing;
- Python requirement tests;
- architecture dependency integrity;
- documentation integrity for a feature;
- security audit;
- cross-language semantic conformance;
- package build;
- release baseline.

Each unit defines:

- stable `CERT-*` ID;
- description;
- applicability;
- input dependency closure;
- upstream certification dependencies;
- toolchain requirements;
- executor;
- command/work definition;
- outputs;
- evidence;
- trust level;
- resumability/cache semantics.

## Certification DAG

Certification units depend on other units.

Example:

```text
Rust tests ─────┐
Node tests ─────┼─> semantic conformance ─> release certification
Python tests ───┘
```

If an upstream certification becomes stale, dependent units become stale.

Independent branches remain reusable.

## Canonical completed states

A required unit has one of:

- `PASS`;
- `FAIL`;
- `STALE`;
- `MISSING`;
- `INVALID`.

`RUNNING` is an operational job state rather than completed evidence.

### PASS

Trusted evidence exists and fingerprints match current dependencies.

### FAIL

Certification ran against current dependencies and failed.

### STALE

Evidence exists but the dependency closure no longer matches.

### MISSING

No required evidence exists.

### INVALID

Artifact, signature, schema, provenance, or trust requirements are invalid.

## Certification artifact

Canonical fields include:

- certification ID;
- standard edition;
- Fortress implementation version;
- project identity;
- scope/profile;
- status;
- input fingerprint;
- dependency-manifest digest;
- toolchain fingerprint;
- upstream certification digests;
- result digest;
- result summary;
- evidence digests;
- provenance;
- attestation metadata.

Human-readable Markdown is a generated projection.

## Certification scopes

Fortress supports certification of a rule/capability, feature, component, archetype, language surface, pipeline, repository, or release.

Higher certification aggregates lower required units but never hides failures.

## Binary final meaning

A scope is Fortress Certified only when all mandatory applicable certification requirements are current and PASS under the claimed standard.

Migration progress is not certification.

## Structural and behavioral evidence

Certification includes both where applicable.

Structural evidence includes ownership, architecture, dependency direction, file placement, public API mapping, and docs completeness.

Behavioral evidence includes requirement tests, conformance, mutation, fuzz, property tests, performance, and security obligations.

## Generated certification docs

Fortress should generate a canonical evidence tree such as:

```text
certification/
├── manifest.json
├── current/
│   ├── summary.json
│   └── summary.md
├── units/
└── evidence/
```

Projects may store this beneath `.fortress/` according to the standard, but semantics remain standardized.

## Quality ledger

`fortress status` should expose objective state such as:

- active features;
- requirement coverage;
- documentation coverage;
- architecture violations;
- certification counts by state;
- current standard;
- stale units;
- active jobs;
- exemptions.

Metrics describe state; they do not substitute for rule-level evidence.

## Advanced evidence obligations

A risk profile may require mutation results, fuzz corpus execution, property testing, security scans, performance bounds, cross-platform matrices, or distribution smoke tests.

A PASS result must identify the exact obligation satisfied.

## Release certification

Release certification is the strongest routine profile.

It should require:

- all applicable repository gates;
- complete certification DAG current;
- package/release artifact checks;
- public API compatibility analysis;
- dependency/license/security review;
- generated artifact reproducibility;
- provenance/SBOM where applicable;
- zero stale mandatory units;
- zero unresolved release-blocking exemptions.

## Evidence authority

Generated evidence proves conformity. It is not normative product meaning.

Evidence cannot rewrite the governing standard or feature contract merely because expected output changed.

## Explainability

Fortress must explain:

- why a certification is stale;
- which input invalidated it;
- which upstream unit blocked it;
- which rule requires it;
- how to reproduce it;
- which evidence supports PASS.

## Goal

A Fortress certification should be independently inspectable enough that CI, a maintainer, or an AI agent can verify the claim without blindly rerunning every expensive operation.
