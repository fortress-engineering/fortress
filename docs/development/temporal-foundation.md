# Initial temporal schema foundation

**Status:** Implemented development architecture
**Authority class:** Implementation documentation
**Owning capability:** `AF-PROJECT-MODEL-0001`

## Purpose

Schema family `v1` represents a general `CHG-*` transition record containing an
objective, baseline, governing authority references, scope, validation checks,
decisions, deferred capabilities, and result. Bootstrap packet provenance is an
optional specialized member rather than a requirement for every future change.

This separation was introduced immediately after bootstrap because the first
schema coupled all temporal governance to packet metadata. Preserving that shape
would have made ordinary feature and remediation records lie or carry irrelevant
fields. The refactor is a deliberate self-hardening change: general change
semantics remain independent, while `CHG-BOOTSTRAP-0001` retains its complete
historical packet provenance.

## Current boundary

The schema and records exist, but Fortress does not yet implement the full
change lifecycle, authorization, baseline fingerprinting, drift detection, or
transition certification. Records therefore continue to make truthful
`NOT CERTIFIED` claims unless and until certification semantics exist.
