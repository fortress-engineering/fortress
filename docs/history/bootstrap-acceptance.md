# 24 — Bootstrap Acceptance Criteria

**Status:** Bootstrap completion gate and historical acceptance record
**Authority class:** Bootstrap acceptance

## Purpose

The first Fortress repository initialization task must establish a disciplined constitutional skeleton without pretending to have implemented the full product.

Initialization is complete only when the criteria below are satisfied or an explicit blocker prevents safe completion.

## 1. Repository identity

The initialized repository must correctly establish:

- organization/product naming;
- repository description;
- Rust workspace identity;
- license choice as explicitly authorized by the task/owner;
- README with accurate product definition;
- contribution/security/governance entrypoints;
- canonical links to website and organization surfaces where available.

The task MUST NOT invent an unapproved license.

## 2. Authority hierarchy

The repository must have permanent documents that establish:

- product definition;
- engineering philosophy;
- standard versus implementation authority;
- architecture authority;
- contract authority;
- certification authority;
- temporal/onboarding governance entrypoints.

The temporary bootstrap packet must no longer be necessary to understand authority after promotion.

## 3. Repository structure

Create only justified initial top-level roots consistent with `04-repository-architecture.md`.

The bootstrap should establish enough structure for subsequent work without creating empty architecture theater.

At minimum the design for these roots must be represented and validated:

- `.fortress/`;
- `.github/`;
- `crates/`;
- `standard/`;
- `schemas/`;
- `conformance/`;
- `tests/`;
- `docs/`.

`analyzers/`, `adapters/`, and `examples/` may be created when initial implementation content justifies them, or represented as reserved target architecture in docs until then.

## 4. Standard bootstrap

The repository must establish:

- a draft path toward Fortress Engineering Standard 1.0.0;
- standard manifest schema or initial versioned schema foundation;
- stable rule-ID conventions;
- immutable-release-directory rule;
- clear distinction between draft standard material and released editions.

It MUST NOT falsely publish Standard 1.0.0 as final merely because the folder exists.

## 5. Fortress project self-model

The Fortress repository must contain an initial `.fortress/` self-governance model sufficient to demonstrate self-application from the beginning.

At minimum define:

- project identity;
- current standard/draft identity;
- initial architecture declaration;
- initial feature/capability ownership model for bootstrap code;
- initial command declarations;
- initial certification scaffolding;
- active change/bootstrap record.

## 6. Canonical CLI skeleton

A minimal Rust CLI must compile and provide at least:

- `fortress --version`;
- `fortress help`;
- a structured placeholder/discovery path for future command registration.

The initialization task must not create fake implementations of audit/certification commands that report success without proof.

Unimplemented commands must be clearly unavailable, not green stubs.

## 7. Core library boundary

The bootstrap should separate CLI presentation from the initial core standard/project model logic sufficiently that future providers and UI surfaces do not become architectural dependencies of the core.

The exact crate count should remain minimal and justified.

## 8. Initial schemas

Bootstrap must establish a schema/versioning framework and at least the minimum schemas necessary for the self-model introduced in the task.

Candidate early schemas include:

- project manifest;
- rule identity/metadata;
- feature/entity ownership;
- change record;
- certification placeholder/manifest.

Do not attempt to finalize every 1.0 schema in the bootstrap task.

## 9. Test and conformance harness

Bootstrap must establish:

- Rust implementation tests;
- a distinct conformance-fixture location;
- stable test-ID convention;
- at least one positive and one controlled negative fixture for any actual Fortress rule implemented during bootstrap.

Tests and generated fixture output must not become normative authority.

## 10. Source quality gates

All bootstrap source introduced by the task must satisfy the strongest immediately available local rules for:

- rustfmt;
- Clippy/warnings;
- source documentation;
- unsafe policy;
- naming;
- tests;
- repository hygiene.

No warning baseline may be created merely to move forward.

## 11. Documentation quality

Every permanent bootstrap document must have:

- clear purpose;
- authority/status;
- no contradictory duplicate source of truth;
- links to controlling documents where relevant.

Source files and substantive symbols introduced during bootstrap must be documented according to the Fortress documentation philosophy to the extent the initial tooling can enforce it.

## 12. Generated artifact governance

Any generated file introduced in bootstrap must have:

- authoritative source;
- generator identity;
- deterministic expectation;
- check command.

If no generated artifacts are required, do not create unnecessary infrastructure solely to satisfy this criterion.

## 13. CI skeleton

Bootstrap must establish a low-cost CI workflow that performs the checks Fortress can truthfully enforce at that stage.

It must not pretend incremental attestation exists before implemented.

The CI architecture should be intentionally compatible with the later model in which hosted CI verifies fingerprinted certification evidence rather than blindly rerunning every expensive task.

## 14. Branch/governance policy documentation

Document the intended branch authority model:

- development automation may work on task branches and/or `dev` according to later project policy;
- only the owner-authorized identity may merge/push protected `main` under the intended production workflow;
- autonomous tools must not bypass failed gates.

Actual GitHub ruleset creation may be outside the repository task if permissions/tooling do not allow it; the task must report this rather than claiming enforcement.

## 15. Bootstrap change record

Initialization itself should be represented as the first temporal engineering change record or bootstrap historical record.

It should record:

- baseline empty/new repository state;
- bootstrap authority packet digest;
- promoted artifacts;
- implementation created;
- tests/checks run;
- unresolved work;
- resulting repository commit fingerprint where available.

## 16. Packet disposition

Before the temporary bundle is deleted, produce a disposition matrix for every file in `MANIFEST.yaml` stating:

- promoted unchanged;
- promoted with transformation;
- encoded into schema/config;
- archived as bootstrap history;
- intentionally discarded with rationale.

No required design artifact may simply disappear.

## 17. Completion evidence

The initialization task must report:

- files/directories created;
- architecture established;
- schemas established;
- commands available;
- tests and checks run;
- exact results;
- generated artifacts;
- temporary packet disposition;
- blockers/deferred 1.0 capabilities;
- repository status and commit/push state.

## 18. Prohibited completion shortcuts

The task MUST NOT declare bootstrap complete by:

- implementing placeholder commands that always PASS;
- copying the temporary packet wholesale into permanent docs without resolving authority/duplication;
- creating empty directories/crates to mimic future architecture;
- suppressing warnings or tests;
- inventing unresolved product semantics;
- claiming full Fortress certification before certification exists;
- deleting the bootstrap packet before disposition is recorded.

## 19. Definition of bootstrap done

Bootstrap is done when the repository has become a **coherent, buildable, documented, self-governed starting system** whose next development tasks can be bounded by permanent project authorities rather than by this temporary packet.

It is not done because Fortress 1.0 is implemented. It is done because Fortress 1.0 can now be developed without foundational architectural improvisation.
