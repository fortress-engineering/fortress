# Declared repository placement

**Status:** Implemented Snapshot Governance rule
**Rule:** `REPO-PLACEMENT-001`
**Owning capability:** `AF-SNAPSHOT-GOVERNANCE-0001`

The architecture model declares which top-level directory names are permitted,
which path prefixes are governed source roots, which artifact classifications
are prohibited inside source, and which Fortress-controlled paths require exact
spelling. The evaluator applies those declarations to the stabilized inventory
and also reports files outside component or artifact ownership.

This is not a universal directory template. Ecosystem-required root files such
as `Cargo.toml` are legitimate when explicitly classified and owned. Fortress's
self-model allows its actual workspace, governance, standard, schema,
conformance, documentation, and test roots while protecting its canonical
`.fortress` declarations and standard manifest path.
