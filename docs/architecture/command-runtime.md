# 12 — Command Runtime and Project Control Plane

**Status:** Normative command-runtime architecture
**Authority class:** Operational architecture

## Purpose

Fortress should become the primary high-level command surface through which humans and AI interact with a governed software project.

The command system is not a bag of aliases. It is a typed, contracted operational model of the project.

## Governing principle

A Fortress-managed repository should increasingly expose one canonical project vocabulary:

```text
fortress test
fortress build
fortress serve
fortress audit
fortress certify
fortress affected
fortress release
fortress deploy
fortress package
fortress clean
fortress status
```

Project-specific commands may extend this vocabulary:

```text
fortress db refresh
fortress docs generate
fortress benchmark corpus
fortress fixture rebuild
```

Fortress does not replace Cargo, npm, pytest, Docker, Terraform, GitHub Actions, or other specialized tools. It supplies a governed semantic interface over them.

## Command contract

Every registered command must define:

- stable command ID;
- canonical name;
- optional aliases;
- human description;
- typed arguments/options;
- owning component/capability;
- prerequisites;
- input entities/files;
- expected outputs;
- produced artifacts;
- external tools invoked;
- environment requirements;
- executor class;
- cacheability;
- idempotence expectations;
- resumability class;
- expected duration class;
- resource requirements;
- certification implications;
- commands/jobs it depends on.

## Command discovery

Users must be able to discover the complete project operation vocabulary without reading package scripts manually.

Required capabilities include:

- `fortress help`;
- `fortress commands`;
- `fortress explain command <name>`;
- structured machine-readable command discovery for AI/IDE integrations.

## Hierarchical command namespaces

Command names may use hierarchical namespaces for clarity:

- `fortress db ...`;
- `fortress ci ...`;
- `fortress job ...`;
- `fortress pipeline ...`;
- `fortress change ...`;
- `fortress onboard ...`.

Project extensions must not shadow protected Fortress core command meanings without an explicit compatibility rule.

## Synchronous versus asynchronous execution

Fast deterministic operations may execute synchronously.

Long-running commands should submit persistent jobs and promptly return control to the user.

The user should never need to keep a terminal blocked overnight merely because an audit or certification is running.

## Command execution provenance

Fortress should record enough data to reconstruct what operation ran:

- command ID/version;
- normalized arguments;
- resolved project/standard state;
- executor;
- toolchain identity;
- inputs;
- start/end state;
- output artifacts;
- job identity where asynchronous.

When a command contributes certification evidence, provenance requirements are stricter.

## Project scripts

Projects may register existing scripts rather than rewriting them.

Fortress should support wrapping:

- shell scripts;
- PowerShell;
- package-manager scripts;
- Cargo commands;
- Python tools;
- .NET tooling;
- Docker commands;
- provider jobs.

Wrapped commands must still declare semantics, inputs, outputs, and failure behavior.

## Typed parameters

Fortress command parameters should support types such as:

- boolean;
- integer/number;
- enum;
- path;
- entity ID;
- environment;
- target profile;
- package/component reference.

Machine-readable parameter definitions reduce ambiguity for automation and AI.

## Composition

Commands may depend on other commands or certification units.

Fortress resolves the dependency DAG rather than relying on fragile hand-coded command chains.

Cycles in command dependencies are prohibited.

## Failure semantics

Commands must define meaningful failure classification rather than treating every non-zero exit as identical.

Where an external tool only provides process-level failure, the adapter may normalize output into Fortress findings or job failure categories.

## AI interaction

The command runtime should expose structured context so an AI can ask:

- what commands exist;
- what a command changes;
- what inputs it requires;
- whether it is safe to run;
- whether it launches a long job;
- what certification it invalidates or produces.

## Local-first control

The core command runtime must function locally and must not require a hosted Fortress service.

Remote execution is an optional executor behind the same command contract.

## Goal

Fortress should make the project feel like a coherent living engineering environment rather than a repository whose operations are scattered across package scripts, README fragments, CI files, and tribal knowledge.
