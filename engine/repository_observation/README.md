# Repository Observation

## Purpose

Repository Observation exists to turn an ordinary local repository tree into stable content facts without confusing those facts with declarations or ownership.

## Responsibility

Walk repository files using explicit operational exclusions, normalize repository-relative paths, hash bytes, and return a deterministically ordered observation suitable for snapshot stabilization whether or not project governance authority is present.

## Scope

### Includes

Ordinary-file discovery, portable path normalization, byte sizes, SHA-256 digests, exclusion policy identity, explicit nonregular-entry and symlink barriers, immutable source views, conflict-checked hypothetical byte changes, and local filesystem error reporting.

Neutral local retained-input admission for parser lifetimes, with exact input counters and no policy or orchestration authority.

### Excludes

Project ownership claims, semantic rule interpretation, source-language analysis, remote provider state, and filesystem locking against a malicious host.

## Relationships

### [Project Model](../project_model/README.md)

**Types:** `depends_on`

Consumes a project-authored observation exclusion policy when present. Without project authority, tooling may apply a documented operational exclusion such as `.git` without materializing that behavior as authored intent.

## Guarantees

Equivalent included content produces equivalent sorted facts; unsafe exclusions fail explicitly; links and reparse points are never followed by read-only manifest discovery and appear as bounded limitations. The strict legacy observer rejects them. A proposed source view remains separate from actual observed bytes. No timestamp or absolute host path enters semantic observation identity.

Retained-input accounting is operational and thread-local. An active budget cannot be reset to hide live input allocations; exhausted admission remains exhausted until the dedicated thread ends. The byte charge does not assert a hard process-RSS bound or alter canonical observations.

Optional bounded observation limits ordinary-file count, total-entry count including empty directories, source bytes and path bytes before hashing or whole-input allocation. Admitted inputs retain ordinary canonical output; exceeding a limit is an explicit operational failure. R04 parent-local controls verify equality and rejection without weakening the unbounded observer.
