"""Public integrity records for correctness evidence and separate diagnostic costs.

This reader does not authenticate a producer, prove execution or reevaluate any
Fortress semantic claim. Actual qualification remains with the existing owners.
"""
import hashlib
import re
from verify_bundle import canonical, parse

SCHEMA = "urn:fortress:qualification:v2:performance-equivalence"
CORPORA = {"candidate_differential_cases": 1000, "resident_differential_cases": 1000}
HISTORICAL_POPULATION = {"independent_comparisons": 300, **CORPORA}
POPULATION = {
    "independent_comparisons": 30,
    "verified_baseline_restorations": 30,
    "lifecycle_operations": 100,
    **CORPORA,
}
FIELDS = {"$schema", "schema_version", "claim", "source_domain", "source_ref", "correctness_certificate", "workload_manifest_digest", "required_qualification", "independent_cold_proof", "unfiltered_required_suite", "numeric_performance_certification", "observations", "correctness_evidence", "limitations", "authenticity", "record_id"}

def population(version):
    if type(version) is not int or version not in (1, 2):
        raise ValueError("UNSUPPORTED_VERSION")
    return HISTORICAL_POPULATION if version == 1 else POPULATION


def workload_manifest(data):
    if len(data) > 64 * 1024:
        raise ValueError("RESOURCE_LIMIT: workload manifest")
    value = parse(data)
    fields = {"$schema", "schema_version", "id", "numerical_performance_requirements", "generator", "required_qualification", "workloads", "limitations"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("INCOMPATIBLE_WORKLOAD_MANIFEST")
    version = value["schema_version"]
    expected = population(version)
    if value["$schema"] != f"urn:fortress:research:v{version}:performance-workloads" or value["id"] != f"canonical-performance-workloads-v{version}" or value["generator"] != "rust_straight_line_v1" or value["numerical_performance_requirements"] is not False or value["required_qualification"] != expected:
        raise ValueError("INCOMPATIBLE_WORKLOAD_MANIFEST")
    workloads = value["workloads"]
    if not isinstance(workloads, list) or not 3 <= len(workloads) <= 16:
        raise ValueError("RESOURCE_LIMIT: workload population")
    names = []
    for row in workloads:
        if not isinstance(row, dict) or set(row) != {"id", "functions", "lines_per_function", "functions_per_file", "approximate_lines", "warm_queries", "warm_evaluations"}:
            raise ValueError("INVALID_WORKLOAD")
        if not isinstance(row["id"], str) or not re.fullmatch(r"[a-z][a-z0-9_]+", row["id"]) or any(type(row[k]) is not int for k in row if k != "id") or not 1 <= row["functions"] <= 50000 or row["lines_per_function"] != 20 or row["functions_per_file"] != 25 or row["approximate_lines"] != row["functions"] * 20 or row["warm_queries"] != 100 or row["warm_evaluations"] != 10:
            raise ValueError("INVALID_WORKLOAD_BINDING")
        names.append(row["id"])
    if len(names) != len(set(names)):
        raise ValueError("AMBIGUOUS_WORKLOAD")
    if not isinstance(value["limitations"], list) or not 1 <= len(value["limitations"]) <= 32 or any(not isinstance(x, str) or not 1 <= len(x) <= 1024 for x in value["limitations"]):
        raise ValueError("INVALID_WORKLOAD_LIMITATIONS")
    return value


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def exact_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value)


def check(record, expected_source):
    """Validate public integrity and an independently supplied source reference.

    A caller must separately verify the referenced certificate and raw reports;
    neither an asserted digest nor this record is authenticated execution proof.
    """
    if not isinstance(record, dict):
        raise ValueError("INVALID_RECORD: performance qualification fields")
    version = record.get("schema_version")
    expected = population(version)
    required_fields = FIELDS if version == 1 else FIELDS | {"selection_manifest_digest"}
    if set(record) != required_fields:
        raise ValueError("INVALID_RECORD: performance qualification fields")
    if record["$schema"] != f"urn:fortress:qualification:v{version}:performance-equivalence":
        raise ValueError("UNSUPPORTED_VERSION")
    if record["claim"] != "RECORDED_CORRECTNESS_EVIDENCE_AND_DIAGNOSTICS" or record["source_domain"] != "QUALITY_CERTIFICATE_SOURCE_FINGERPRINT" or record["source_ref"] != expected_source:
        raise ValueError("SOURCE_OR_CLAIM_MISMATCH")
    if any(not exact_digest(record[key]) for key in ["source_ref", "correctness_certificate", "workload_manifest_digest", "record_id"]):
        raise ValueError("INVALID_DIGEST")
    if version == 2 and not exact_digest(record["selection_manifest_digest"]):
        raise ValueError("INVALID_SELECTION_IDENTITY")
    if record["required_qualification"] != expected or record["independent_cold_proof"] is not True or record["unfiltered_required_suite"] is not True:
        raise ValueError("INCOMPLETE_REQUIRED_CORRECTNESS")
    if record["numeric_performance_certification"] is not False or record["authenticity"] != "UNVERIFIED":
        raise ValueError("UNSUPPORTED_ASSURANCE_CLAIM")
    observations = record["observations"]
    if not isinstance(observations, list) or not 1 <= len(observations) <= 64:
        raise ValueError("RESOURCE_LIMIT: observation references")
    names = []
    for observation in observations:
        if not isinstance(observation, dict) or set(observation) != {"id", "digest", "bytes"}:
            raise ValueError("INVALID_OBSERVATION")
        name = observation["id"]
        if not isinstance(name, str) or len(name) > 128 or not re.fullmatch(r"[a-z][a-z0-9_]+", name) or not exact_digest(observation["digest"]) or type(observation["bytes"]) is not int or not 0 < observation["bytes"] <= 128 * 1024**2:
            raise ValueError("INVALID_OBSERVATION_BINDING")
        names.append(name)
    if names != sorted(set(names)):
        raise ValueError("AMBIGUOUS_OBSERVATIONS")
    proof = record["correctness_evidence"]
    if not isinstance(proof, dict) or set(proof) != {"source_ref", "populations", "unfiltered_suite", "independent_cold", "reports"} or proof["source_ref"] != expected_source or proof["populations"] != expected or proof["unfiltered_suite"] is not True or proof["independent_cold"] is not True or not isinstance(proof["reports"], dict) or set(proof["reports"]) != set(expected):
        raise ValueError("INCOMPLETE_CORRECTNESS_EVIDENCE")
    observed = {o["id"]: o["digest"] for o in observations}
    if any(not exact_digest(proof["reports"][name]) or observed.get(name) != proof["reports"][name] for name in expected):
        raise ValueError("MISSING_INDEPENDENT_REPORT_REFERENCE")
    limitations = record["limitations"]
    if not isinstance(limitations, list) or not 1 <= len(limitations) <= 32 or any(not isinstance(s, str) or not 1 <= len(s) <= 2048 for s in limitations):
        raise ValueError("INVALID_LIMITATIONS")
    payload = {k: v for k, v in record.items() if k != "record_id"}
    if digest(canonical(payload)) != record["record_id"]:
        raise ValueError("TAMPERED_RECORD")
    return {"integrity": "VALID", "authenticity": "UNVERIFIED", "execution": "NOT_INDEPENDENTLY_ESTABLISHED", "semantic_correctness": "NOT_REEVALUATED", "numerical_certification": False}


def compose(source_ref, certificate_stamp, workload_bytes, observations, limitations, correctness_evidence, *, selection_manifest_digest=None):
    """Record already-qualified evidence references; never turn timings into gates."""
    manifest = workload_manifest(workload_bytes)
    version = manifest["schema_version"]
    record = {"$schema": f"urn:fortress:qualification:v{version}:performance-equivalence", "schema_version": version,
        "claim": "RECORDED_CORRECTNESS_EVIDENCE_AND_DIAGNOSTICS",
        "source_domain": "QUALITY_CERTIFICATE_SOURCE_FINGERPRINT", "source_ref": source_ref,
        "correctness_certificate": certificate_stamp, "workload_manifest_digest": digest(canonical(manifest)),
        "required_qualification": population(version).copy(), "independent_cold_proof": True,
        "unfiltered_required_suite": True, "numeric_performance_certification": False,
        "observations": sorted(observations, key=lambda o: o["id"]), "correctness_evidence": correctness_evidence, "limitations": list(limitations), "authenticity": "UNVERIFIED"}
    if version == 2:
        record["selection_manifest_digest"] = selection_manifest_digest
    record["record_id"] = digest(canonical(record))
    check(record, source_ref)
    return record
