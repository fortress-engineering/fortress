# CLI Module

The CLI Module owns terminal presentation, command registration, argument
validation, process exit semantics, and human/JSON rendering. It depends on the
Engine but the Engine does not depend on it.

Implemented entrypoints are `fortress --version`, `fortress help`, and
`fortress audit [path] [--format human|json]`. Audit exits successfully only
when every actually evaluated mandatory rule has no violation. Invalid project
or snapshot state and unsupported commands/options are non-success. Unsupported
rule capabilities remain explicit in output. No command claims certification.
