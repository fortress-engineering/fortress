"""Reference collector serving one retained JUnit report over the public wire."""
import hashlib
import json
import sys

SCHEMA = "urn:fortress:schema:v1:evidence-adapter-exchange"
PAYLOAD = '<testsuite name="unit" package="parcel"><testcase name="test_grams"/></testsuite>'


def response(request):
    """Serve capabilities and a fixture report without executing repository code."""
    if request["$schema"] != SCHEMA or request["schema_version"] != 1:
        raise ValueError("unsupported exchange")
    operation = request["operation"]
    result = {
        "$schema": SCHEMA, "schema_version": 1, "request_id": request["request_id"],
        "provider": "example.parcel-junit", "provider_version": "1.0.0",
        "protocol_version": 1, "format": "JUNIT_XML", "capability": "TEST_REPORTS",
        "outcome": {"HELLO": "CAPABILITIES", "CANCEL": "CANCELLED", "COLLECT": "UNAVAILABLE"}[operation],
        "raw_utf8": None, "manifest": None,
    }
    if operation == "COLLECT" and request["invocation_scope"] == "parcel.unit":
        identity = {"namespace": "NATIVE_QUALIFIED", "package": "parcel", "target": "unit",
                    "qualified_name": "test_grams"}
        result.update(outcome="REPORTED", raw_utf8=PAYLOAD, manifest={
            "binding": request["binding"], "provider": result["provider"],
            "provider_version": result["provider_version"], "invocation_scope": "parcel.unit",
            "payload_digest": "sha256:" + hashlib.sha256(PAYLOAD.encode()).hexdigest(),
            "execution": {"binary_digest": None, "tool_digest": None, "arguments": None,
                          "working_directory": None, "inputs": [], "environment_dependencies": [],
                          "dependencies_complete": False},
            "inventory": [{"key": identity, "enabled": True}], "inventory_complete": False,
            "filters": [], "filtering_known": False, "attempts_complete": False, "attempts": [],
            "invocation": {"succeeded": None, "exit_code": None}, "assumptions": [],
        })
    return result


if __name__ == "__main__":
    incoming = sys.stdin.buffer.read(64 * 1024 + 1)
    if len(incoming) > 64 * 1024:
        raise ValueError("request exceeds byte quota")
    print(json.dumps(response(json.loads(incoming)), separators=(",", ":"), ensure_ascii=True))
