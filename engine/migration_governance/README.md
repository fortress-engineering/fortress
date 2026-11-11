# Migration Governance

## Purpose

Apply explicit exact-state governance migrations recoverably without claiming filesystem-wide atomicity.

## Responsibility

Own immutable planning, deterministic operation lowering, journaled mutation, conflict-preserving recovery and verified final receipts through injected canonical evaluation and OPS resource ports.

## Scope

### Includes

Bounded regular-file creation, replacement, relocation and owned deletion; exact preimages/postimages; explicit graph dependencies; trusted authorization consumption; same-volume external staging; durable operation journals; cancellation, resume and rollback; actual-target validation; immutable proposal and receipt records. Directory trees are represented by reviewed file sets; arbitrary recursive directory mutation is excluded.

### Excludes

New parsers, semantic evaluators, authorization authorities, onboarding/admission/upgrade orchestration, hostile-filesystem transactions and filesystem-wide atomicity.

## Relationships

### [Certification](../certification/README.md)

**Types:** `depends_on`

Provides the existing Certification contract; this Module does not redefine its authority.

### [Development Governance](../development_governance/README.md)

**Types:** `depends_on`

Provides the existing Development Governance contract; this Module does not redefine its authority.

### [Finding Model](../finding_model/README.md)

**Types:** `depends_on`

Provides the existing Finding Model contract; this Module does not redefine its authority.

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Provides the existing Project Model contract; this Module does not redefine its authority.

### [Repository Observation](../repository_observation/README.md)

**Types:** `depends_on`

Provides the existing Repository Observation contract; this Module does not redefine its authority.

### [Standard Registry](../standard_registry/README.md)

**Types:** `depends_on`

Provides the existing Standard Registry contract; this Module does not redefine its authority.

### [State Governance](../state_governance/README.md)

**Types:** `depends_on`

Provides the existing State Governance contract; this Module does not redefine its authority.

**Application and recovery contract.** Preview evaluates complete immutable base and target byte views through Snapshot Governance. A plan binds both physical source inventories and their independently filtered canonical evaluations. A candidate cannot hide a protected edit by excluding it from analysis. The graph evacuates original files before target installation and lowers permutations through exclusive same-volume OPS slots. Source writes use synchronized write-ahead intent, exact preimages and native object identities. Required hard-link support and journal/recovery capacity are checked before source mutation.

Protected application consumes the existing AUTHORITY boundary and its actual in-memory external grants. Existing original-authority assessment can be reused only when State Governance establishes identical software subjects; changed software and governing meaning require an explicitly supported common-authority cell. No missing assessment or grant is inferred. First bootstrap establishes reviewed intent only where no protected authority already exists; it cannot relax an existing policy. Retirements require exact owner-derived RATCHET proofs, not citations or disappeared findings.

An interrupted transaction retains original bytes, staged postimages, its reviewed plan and hash-linked journal. Resume rechecks authorization and the exact plan. Rollback restores only known preimages or removes exclusively owned postimages, verifies actual bytes and preserves independent edits as explicit conflicts. A published completed receipt is historical: reversing an already completed migration requires a new reviewed inverse plan. Incomplete source application blocks native fresh certification and Python current-source verification; immutable historical/offline inspection remains independent.

**Supported limits.** Version 1 admits regular-file operations only, at most 1,024 operations and a 32 MiB public/input admission bound. Directory trees require explicit file sets; empty-directory inventories, permissions, ACLs, open external writer exclusion and filesystem-wide atomicity are not promised. Cooperative same-host leases coordinate Fortress writers. Ordinary same-volume filesystems must support safe non-overwriting hard links. Files and journals use synchronization; portable Windows directory metadata does not establish arbitrary power-loss ordering, so process-crash recovery is the qualified scope. Unknown content, ownership, partial/corrupt journal records and exhausted resource budgets remain conflicts with retained material.

**Consumers.** ONBOARD, ADMISSION and UPGRADE must use MigrationPlan and the single writer rather than implement their own rollback paths. SECURITY must qualify any stronger hostile-host boundary separately. OVERLAY is not required or implemented. CLI inspection formats retained results; explicit preview is the only analysis operation. An embedding supplies trusted original policy and a real external validator for protected writes; command-line JSON never supplies that validator. No release publication, signing or approval service is introduced.

Incomplete preparation can finish explicit recovery by verifying every original byte and path condition twice, retaining the incomplete records and returning no application receipt. This is an original-state verification, not proof that missing journal entries exist. Source-changing resume still requires fresh exact authorization. Identity normalization consumes the existing identity owner's opaque, source-bound plan through the lifecycle owner; it cannot create/retire entries, expand a baseline or replace current anchors. External permission remains independently required.

## Guarantees

Preview does not mutate the repository. Applying requires exact current inputs and applicable trusted authorization. Recovery never intentionally overwrites independently changed bytes. Missing evidence, failed validation and ambiguous ownership cannot produce a successful receipt. Active migration state blocks fresh assessment until verified completion or recovery.
