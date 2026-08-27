# Fortress implementation test support

**Status:** Implementation evidence boundary
**Authority class:** Implementation testing

Crate-local unit and integration tests exercise the Rust implementation. This
root is reserved for repository-level implementation harnesses that genuinely
span crates or processes. It is intentionally distinct from `conformance/`,
whose fixtures are authored from governed rule meaning.

Tests are evidence. They must not generate the normative expected output used to
judge the same implementation.
