# Fortress schemas

**Status:** Versioned serialized contract authority

**Authority class:** Contract architecture

This directory contains the versioned JSON Schemas that encode Fortress
serialized contracts. Schemas are subordinate to the controlling product,
standard, architecture, and governance documents listed in
[`docs/README.md`](../docs/README.md). A schema defect does not silently redefine
those authorities.

`v1/` is the initial schema family. Schema-family versioning is independent from
the Fortress CLI version and Fortress Engineering Standard edition. Backward-
incompatible serialized-contract changes require a new schema family or an
explicitly governed compatibility mechanism.

The bootstrap validator checks that every registered schema is valid JSON,
carries the expected dialect and Fortress identity, has no unresolved local
registry entry, and that repository self-model instances deserialize and satisfy
their domain invariants. Full JSON Schema vocabulary evaluation remains a
separate implementation unit and is not claimed by this bootstrap foundation.
