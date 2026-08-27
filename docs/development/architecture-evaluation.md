# Declared architecture dependency evaluation

**Status:** Implemented development architecture
**Authority class:** Implementation documentation
**Owning capability:** `AF-ARCHITECTURE-EVALUATION-0001`
**Governing rule:** `ARCH-DEPENDENCY-001`

## Purpose

`fortress-core` loads version-one declared architecture JSON, validates stable
component identities, unique zones/components/paths/dependencies, zone
membership, canonical repository-relative path prefixes, and dependency target
existence, then evaluates the component graph for directed cycles.

Cycle traversal is deterministic: components and their dependencies are visited
in stable identity order, and a back-edge produces a canonical ordered cycle
whose first entity is repeated at the end. The finding carries the stable rule
ID, `FAIL` state, affected entity sequence, and a reproducible message.

## Evidence and boundary

Specification-authored `ARCH-DEPENDENCY-001` fixtures cover an acyclic graph, a
two-component cycle, and a one-component no-edge boundary. Implementation tests
also cover invalid model structure and evaluate Fortress's own declared graph.

This capability evaluates declarations only. It does not yet extract imports or
references from source, compare observed edges with declarations, enforce zone
direction beyond cycles, or apply a transition/exemption. A passing declared DAG
does not prove that implementation dependencies obey it and does not create a
certification PASS.
