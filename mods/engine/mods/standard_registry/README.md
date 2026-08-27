# Standard Registry Module

This Module owns stable Fortress identity, the draft standard registry, common
standard schemas, and the exact manifest that selects applicable draft rules.
It defines normative meaning; implementation and conformance evidence do not.

The Fortress Engineering Standard composes universal rules, archetypes,
capabilities, language/tool profiles, project extensions, and bounded
exemptions. Mandatory rules are hard gates when applicable. Rule IDs remain
stable while their meaning remains compatible, and released editions are
immutable and digest-addressed. The current `1.0.0-draft.1` records remain
mutable draft authority and do not support a stable certification claim.

Serialized Fortress IDs retain uppercase hyphenated normative syntax.
Fortress-controlled filesystem names use one to three lowercase underscore
words with an optional `_vN` identity suffix. Repository structure follows
`REPO-MODULE-001`: every Module has `README.md`, direct attributes are flat, and
architectural children recur only beneath `mods/`.

Documentation and tests are governed contracts. Every implemented rule has
valid, invalid, and boundary conformance evidence, while generated results are
never treated as normative rule meaning.
