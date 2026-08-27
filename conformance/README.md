# Fortress conformance corpus

**Status:** Specification-authored conformance evidence
**Authority class:** Conformance

This directory contains deliberately authored inputs and expected canonical
findings for implemented Fortress rules. Fixtures exercise already governed
rule meaning; neither fixture output nor implementation behavior may silently
become normative authority.

Each implemented rule receives stable positive, negative, and boundary fixtures
plus exemption or conflict cases when its contract makes them applicable.
`manifest.json` registers the current corpus. Implementation tests consume these
files without rewriting expected results.
