# 13 — Job, Process, Progress, and Resumption Model

**Status:** Normative job and process architecture
**Authority class:** Operational architecture

## Purpose

Fortress must manage long-running engineering work without freezing the user's interaction with the project.

Security audits, mutation campaigns, fuzz corpora, package matrices, cross-platform builds, release certification, and remote CI operations may run for minutes, hours, or overnight.

Fortress therefore requires a persistent job model.

## Conceptual architecture

```text
Human / AI
    ↓
fortress CLI
    ↓
Fortress Control Plane
    ↓
Job Store + Scheduler
    ↓
Executors
  ├─ local process
  ├─ local container
  └─ remote provider
```

A lightweight background supervisor, conceptually `fortressd`, should own persistent local execution where useful.

Users interact through `fortress`.

## Job identity

Every asynchronous operation receives a stable job ID.

A job record includes:

- job ID;
- command/certification/change that created it;
- state;
- executor;
- normalized inputs;
- standard/project fingerprints;
- work units;
- progress model;
- start/end timestamps;
- logs/events;
- checkpoints;
- produced artifacts;
- retry/resumption metadata;
- parent/child job relationships.

## Job states

Recommended states:

- QUEUED;
- PREPARING;
- RUNNING;
- PAUSING;
- PAUSED;
- CANCELLING;
- CANCELLED;
- FAILED;
- SUCCEEDED;
- INTERRUPTED;
- RECOVERING.

Certification PASS/FAIL is separate from process SUCCEEDED/FAILED. A successful process may correctly produce a failing certification result.

## Required interaction

Users should be able to run:

```text
fortress jobs
fortress job <id>
fortress job <id> logs
fortress job <id> watch
fortress job <id> pause
fortress job <id> resume
fortress job <id> cancel
```

Where an operation is not pausable/resumable, Fortress must say so truthfully.

## Resumability classes

Fortress MUST NOT pretend arbitrary processes can resume from an instruction pointer after a power loss.

Task contracts classify execution semantics, for example:

- `restartable`;
- `idempotent`;
- `checkpointable`;
- `shardable`;
- `remote_resumable`;
- `non_resumable`.

## Sharded work

Long work should be decomposed into deterministic work units where practical.

Example:

```text
Security corpus: 5,000 units
1–1,847    PASS / fingerprinted
1,848      RUNNING
1,849–5,000 PENDING
```

After interruption, Fortress validates completed unit fingerprints and resumes from the unfinished frontier.

## Checkpoint evidence

Checkpoint state should include:

- work-unit identity;
- exact input digest;
- executor/tool identity;
- completion state;
- result/evidence digest.

A checkpoint is reusable only if its input closure remains valid.

## Progress semantics

Fortress must report progress truthfully.

If exact progress is known, report counts and percentages.

If only phases are known, report phase state without fabricating a percentage.

Example:

```text
Phase 4 of 7 — dependency security analysis
Progress: indeterminate
Elapsed: 00:18:42
```

A false 73% estimate is worse than an honest indeterminate state.

## Persistence

Local job runtime state should use a transactional store robust to abrupt termination.

SQLite or an equivalent embedded transactional system is appropriate.

The runtime DB is not the normative project model. Durable certification evidence is emitted separately.

## Process supervision

Fortress should capture:

- stdout/stderr streams;
- process exit classification;
- child process identity where practical;
- termination signal/reason;
- resource metadata where relevant.

Cancellation must attempt orderly shutdown before forced termination according to command policy.

## Recovery

After restart, Fortress should detect interrupted jobs and classify whether they can:

- resume from checkpoint;
- continue by querying a remote provider;
- restart safely;
- require manual intervention.

## Job artifacts to certification evidence

A completed job may become the provenance source for certification evidence.

The chain is:

```text
Job
 ↓
work units / checkpoints
 ↓
results
 ↓
evidence
 ↓
certification artifact
 ↓
attestation
```

## Concurrency and resources

The scheduler should support declared resource requirements and concurrency limits.

A project may prevent multiple destructive commands from running simultaneously or limit CPU-heavy certification jobs.

## Remote jobs

Remote CI/provider executions are represented using the same Fortress job abstraction where possible.

The executor location is metadata; project semantics remain canonical.

## Goal

Fortress should preserve developer control and expensive progress even when engineering work lasts overnight, a machine restarts, or execution moves between local and remote environments.
