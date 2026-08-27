# Snapshot rule evaluation

**Status:** Implemented Snapshot Governance foundation
**Authority class:** Implementation documentation
**Owning capability:** `AF-SNAPSHOT-GOVERNANCE-0001`

## Standard loading

The core loads the exact standard manifest and every manifest-declared rule
document as one typed bundle. It rejects missing, extra, duplicate, malformed,
or unsupported inputs and validates stable rule identities, status, category,
integrity tier, applicability text, remediation, and required evaluator
capabilities before dispatch.

## Truthful execution

The built-in rule engine walks the loaded bundle and records one deterministic
execution result per applicable rule:

- `PASSED` means a registered evaluator ran and produced no violation;
- `FAILED` means a registered evaluator ran and produced normalized findings;
- `UNSUPPORTED` means no Snapshot Governance evaluator is registered.

Unsupported never means pass. The current engine evaluates
`ARCH-DEPENDENCY-001`. `STD-ID-001` remains visible as unsupported at the
snapshot-engine layer because its existing parsers do not yet inventory every
stable identity-bearing contract in a repository.

Rule executions sort by stable rule ID and canonical findings use their shared
global ordering. The loaded standard edition must equal the edition bound into
the snapshot.

## Boundary

The result is deterministic development audit evidence. It does not activate
onboarding states, execute external tools, create certification evidence, or
interpret an absent evaluator as proof.
