# Declared file ownership reconciliation

**Status:** Implemented Snapshot Governance rule
**Rule:** `ARCH-OWNERSHIP-001`
**Owning capability:** `AF-SNAPSHOT-GOVERNANCE-0001`

The evaluator reconciles the stabilized observed path inventory with the
declared architecture. A component path ending in `/` owns its descendants; an
exact component path owns only that path. Explicit repository artifacts name
an exact owner, classify the artifact as repository metadata or generated, and
state whether it must exist.

Every governed observed file must resolve to exactly one distinct component
owner. Zero owners produce an orphan finding. Multiple owners produce an
overlap finding even when the overlap arose from otherwise valid declarations.
Every component path and every artifact marked `required` must have an observed
match. Excluded paths are absent from the stabilized inventory and are not
silently reintroduced by this rule.

The rule has no universal filename exceptions. Fortress declares its root
metadata, generated `Cargo.lock`, workflow directory, and documentation areas
in its self architecture.
