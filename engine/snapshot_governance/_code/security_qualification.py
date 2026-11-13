"""Exact-source boundary qualification records, never grants or issuer authentication."""
import hashlib
import json
import platform
import re
import sys

from bounded_io import strict_json

SCHEMA = "urn:fortress:qualification:v1:security-boundaries"
SURFACES = ["AUTHORITY", "CONTROL", "MIGRATE", "ONBOARD", "OPS", "OVERLAY", "PARSERS", "PORTABLE", "PROVIDER", "RPC", "SNAPSHOT"]
LIMITATIONS = ["ACTIVE_HOSTILE_OS_UNSUPPORTED", "ARBITRARY_POWER_LOSS_UNSUPPORTED", "EXTERNAL_PROTECTION_UNVERIFIED", "NO_GENERAL_SANDBOX", "NO_ISSUER_AUTHENTICATION", "NO_NUMERIC_PERFORMANCE_CERTIFICATION"]


def canonical(value):
    # This record's schema contains only ASCII strings, booleans and exact integers.
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def compose(source, gates, control_bytes, threat_bytes):
    """Compose only after the existing canonical issuer validates all actual gates."""
    if sys.platform not in {"win32", "linux"}:
        raise ValueError("UNSUPPORTED_PLATFORM: boundary qualification requires a qualified host")
    control = strict_json(control_bytes, maximum=64 * 1024)
    if control != {"schema_version": 1, "status": "PASS", "tests_run": 15, "failures": 0, "errors": 0, "skipped": 0}:
        raise ValueError("incomplete independent boundary controls")
    if not gates or gates != sorted(set(gates)) or not {"WORKSPACE_TESTS", "SECURITY_BOUNDARIES", "FULL_PROFILE_CERTIFICATION"}.issubset(gates):
        raise ValueError("incomplete canonical gate qualification")
    result = {"$schema": SCHEMA, "schema_version": 1, "claim": "TESTED_BOUNDARY_CONTROLS_PASS", "source_ref": source, "source_domain": "QUALITY_CERTIFICATE_SOURCE_FINGERPRINT",
        "gate_ids": gates, "control_report_digest": digest(control_bytes), "threat_model_digest": digest(threat_bytes), "threat_model_path": "engine/snapshot_governance/_docs/code_docs.md",
        "tested_host": {"os": sys.platform, "architecture": platform.machine(), "python": platform.python_version()},
        "surfaces": SURFACES, "limitations": LIMITATIONS, "authenticity": "UNVERIFIED", "external_protection": "UNVERIFIED"}
    result["record_id"] = digest(canonical(result))
    check(result, source, gates)
    return result


def check(record, expected_source, required_gates):
    """Check public record integrity and a separately supplied source binding.

    This cannot establish that tests ran, that the producer is trusted, or that
    an independently supplied current repository has the asserted source bytes.
    """
    fields = {"$schema", "schema_version", "claim", "source_ref", "source_domain", "gate_ids", "control_report_digest", "threat_model_digest", "threat_model_path", "tested_host", "surfaces", "limitations", "authenticity", "external_protection", "record_id"}
    if not isinstance(record, dict) or set(record) != fields:
        raise ValueError("invalid security qualification fields")
    if record["$schema"] != SCHEMA or type(record["schema_version"]) is not int or record["schema_version"] != 1 or record["claim"] != "TESTED_BOUNDARY_CONTROLS_PASS":
        raise ValueError("unsupported security qualification")
    if record["source_domain"] != "QUALITY_CERTIFICATE_SOURCE_FINGERPRINT" or record["source_ref"] != expected_source or any(not isinstance(record[key], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", record[key]) for key in ["source_ref", "record_id", "control_report_digest", "threat_model_digest"]):
        raise ValueError("security qualification source or digest mismatch")
    if record["authenticity"] != "UNVERIFIED" or record["external_protection"] != "UNVERIFIED" or record["limitations"] != LIMITATIONS or record["surfaces"] != SURFACES:
        raise ValueError("unsupported security qualification scope")
    gates = record["gate_ids"]
    if not isinstance(gates, list) or len(gates) > 128 or not all(isinstance(value, str) and re.fullmatch(r"[A-Z_]+", value) for value in gates) or gates != sorted(set(gates)) or gates != list(required_gates):
        raise ValueError("incomplete gate manifest")
    if record["threat_model_path"] != "engine/snapshot_governance/_docs/code_docs.md":
        raise ValueError("unsupported threat-model source")
    host = record["tested_host"]
    if not isinstance(host, dict) or set(host) != {"os", "architecture", "python"} or any(not isinstance(value, str) or not value.isascii() or not value or len(value) > 128 for value in host.values()):
        raise ValueError("invalid tested host")
    if host["os"] not in {"win32", "linux"}:
        raise ValueError("unsupported qualified operating system")
    payload = {key: value for key, value in record.items() if key != "record_id"}
    if digest(canonical(payload)) != record["record_id"]:
        raise ValueError("security qualification digest mismatch")
    return record
