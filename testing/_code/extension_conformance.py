"""Run a standalone layout or evidence extension kit against a Fortress-compatible CLI."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import time
import unittest

LAYOUT_SCHEMA = "urn:fortress:schema:v1:layout-extension"
EXCHANGE_SCHEMA = "urn:fortress:schema:v1:evidence-adapter-exchange"
ADAPTER_SCHEMA = "urn:fortress:schema:v1:evidence-adapter"
CAPTURE = 16 * 1024 * 1024


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(content):
    return "sha256:" + hashlib.sha256(content).hexdigest()


def data(path):
    return json.loads(path.read_bytes())


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


class Kit:
    def __init__(self, executable, scratch):
        self.executable = executable
        self.scratch = scratch
        self.results = []
        self.sequence = 0

    def put(self, name, content):
        spelling = PurePosixPath(name)
        require(not spelling.is_absolute() and spelling.as_posix() == name and
                not set(spelling.parts).intersection({".", ".."}) and
                "\\" not in name and ":" not in name, "unsafe fixture path")
        path = self.scratch.joinpath(*spelling.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as out:
            out.write(content)
        return path

    def write(self, name, document):
        return self.put(name, encode(document))

    def check(self, case, condition, detail=None):
        self.results.append({"id": case, "status": "PASS" if condition else "FAIL", "detail": detail})

    def invoke(self, *arguments):
        self.sequence += 1
        stdout = self.scratch / f"stdout-{self.sequence}"
        stderr = self.scratch / f"stderr-{self.sequence}"
        with stdout.open("xb") as out, stderr.open("xb") as err:
            with subprocess.Popen([self.executable, *arguments], cwd=self.scratch,
                                  stdin=subprocess.DEVNULL, stdout=out, stderr=err) as child:
                try:
                    deadline = time.monotonic() + 45
                    while child.poll() is None:
                        require(time.monotonic() < deadline, "kit child did not terminate")
                        require(max(stdout.stat().st_size, stderr.stat().st_size) <= CAPTURE,
                                "kit child exceeded output budget")
                        time.sleep(0.01)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait()
        require(max(stdout.stat().st_size, stderr.stat().st_size) <= CAPTURE, "excessive final output")
        return child.returncode, stdout.read_bytes(), stderr.read_bytes()

    def accepts(self, *arguments):
        code, output, error = self.invoke(*arguments)
        require(code == 0, f"unexpected tool status {code}: {error[:2048]!r}")
        reported = json.loads(output)
        require(output.rstrip(b"\n") == encode(reported), "unstable public wire bytes")
        return reported

    def refuses(self, case, expected, *arguments):
        code, output, error = self.invoke(*arguments)
        self.check(case, code == 2 and not output and expected.encode() in error,
                   None if code == 2 and expected.encode() in error else error[:512].decode(errors="replace"))


def layout(kit, fixtures, example):
    cases = data(fixtures / "layout_extension_cases_v1.json")
    roots = {}
    for name, text in cases["fixture"].items():
        roots[name] = kit.put(f"project/{name}", text.encode())
    project = kit.scratch / "project"
    definition = data(example)
    profile = kit.put("native.json", example.read_bytes())
    pin = digest(profile.read_bytes())
    args = ("layout", "inspect", project, "--profile", profile, pin)
    original = kit.accepts(*args)
    expected = cases["expected"]
    classified = {row["path"]: row["role"] for row in original["entries"] if row["state"] == "CLASSIFIED"}
    remainder = [row["path"] for row in original["entries"] if row["state"] == "UNCLASSIFIED"]
    kit.check("independent-layout", classified == expected["classified"] and remainder == expected["unclassified"]
              and original["authority"] == expected["authority"] and original["profiles"][0]["digest"] == pin)
    kit.check("deterministic-layout", original == kit.accepts(*args))
    kit.check("read-only-layout", {file.relative_to(project).as_posix(): file.read_bytes()
              for file in project.rglob("*") if file.is_file()} ==
              {name: text.encode() for name, text in cases["fixture"].items()})
    for negative in cases["negative"]:
        candidate = copy.deepcopy(definition)
        if "field" in negative:
            candidate[negative["field"]] = negative["value"]
        else:
            next(row for row in candidate["entries"] if row["path"] == negative["entry"])["path"] = negative["replacement"]
        file = kit.write(negative["id"] + ".json", candidate)
        kit.refuses(negative["id"], negative["error"], *args[:3], "--profile", file, digest(file.read_bytes()))
    kit.refuses("disagreeing-layout-pin", "LAYOUT_EXTENSION_DIGEST_MISMATCH", *args[:-1], "sha256:" + "0" * 64)
    kit.refuses("missing-layout", "", *args[:-2], kit.scratch / "does-not-exist", pin)
    kit.refuses("duplicate-profile", "DUPLICATE_LAYOUT_ID", *args, *args[3:])
    extra = copy.deepcopy(definition)
    extra.update(id="example.native-licenses", ecosystem="compliance", marker="NOTICE.txt", entries=[
        {"path": "NOTICE.txt", "kind": "FILE", "role": "DOCUMENTATION", "opaque": False},
    ])
    kit.put("project/NOTICE.txt", b"Fixture notice")
    second = kit.write("notice.json", extra)
    more = ("--profile", second, digest(second.read_bytes()))
    left = kit.accepts(*args, *more)
    right = kit.accepts(*args[:3], *more, *args[3:])
    kit.check("deterministic-composition", left == right and len(left["profiles"]) == 2
              and any(row["path"] == "NOTICE.txt" and row["role"] == "DOCUMENTATION" for row in left["entries"]))
    extra["marker"] = definition["marker"]
    extra["entries"] = copy.deepcopy(definition["entries"][:1])
    conflict = kit.write("conflict.json", extra)
    kit.refuses("conflicting-ownership", "CONFLICTING_LAYOUT_ENTRY",
                *args, "--profile", conflict, digest(conflict.read_bytes()))
    duplicate = kit.put("duplicate.json", encode(definition).replace(b'{', b'{"id":"duplicate",', 1))
    kit.refuses("duplicate-layout-member", "duplicate", *args[:3], "--profile", duplicate, digest(duplicate.read_bytes()))
    oversized = kit.put("oversized-profile.json", example.read_bytes() + b" " * 65536)
    kit.refuses("oversized-layout", "resource bound", *args[:3], "--profile", oversized, digest(oversized.read_bytes()))
    kit.put("project/component/contract.json", b"{}")
    old = kit.accepts(*args)
    version = copy.deepcopy(definition)
    version["version"] = "1.0.1"
    upgraded = kit.write("profile-upgrade.json", version)
    fresh = kit.accepts(*args[:3], "--profile", upgraded, digest(upgraded.read_bytes()))
    kit.check("layout-upgrade-preserves-module-index",
              old["canonical_module_paths"] == fresh["canonical_module_paths"] == ["", "component"]
              and old["observation_digest"] == fresh["observation_digest"])
    roots[definition["marker"]].unlink()
    missing = kit.accepts(*args)
    kit.check("missing-ecosystem-marker", any(row["state"] == "UNESTABLISHED_MARKER" for row in missing["entries"])
              and not any(row["state"] == "CLASSIFIED" for row in missing["entries"]))
    kit.put("project/" + definition["marker"], cases["fixture"][definition["marker"]].encode())
    kit.put("project/src/contract.json", b"{}")
    kit.refuses("canonical-ownership-shadow", "LAYOUT_SHADOWS_CANONICAL_MODULE", *args)
    (project / "src/contract.json").unlink()
    (project / "tests").rename(project / "relocated-tests")
    kit.put("project/tests", b"wrong filesystem kind")
    unsupported = kit.accepts(*args)
    kit.check("unsupported-observed-structure",
              any(row["path"] == "tests" and row["state"] == "UNSUPPORTED_ENTRY_KIND"
                  for row in unsupported["entries"]))
    try:
        (project / "src/linked.py").symlink_to(roots["README.md"])
    except OSError:
        kit.results.append({"id": "unfollowed-link", "status": "UNAVAILABLE", "detail": "host refused link fixture"})
    else:
        linked = kit.accepts(*args)
        kit.check("unfollowed-link", any(row["path"] == "src/linked.py" and row["state"] == "NOT_OBSERVED"
                                       and row["role"] is None for row in linked["entries"]))


def exchange_case(operation, case, binding):
    return {
        "$schema": EXCHANGE_SCHEMA, "schema_version": 1, "request_id": case,
        "operation": operation["operation"], "invocation_scope": operation["scope"],
        "binding": binding if operation["scope"] else None,
    }


def replay_retained(kit, fixtures, reference):
    controls = unittest.defaultTestLoader.loadTestsFromModule(reference)
    result = unittest.TextTestRunner().run(controls)
    kit.check("independent-requirement-controls", result.wasSuccessful(), {"tests": result.testsRun})
    vectors = data(fixtures / "provider_vectors_v1.json")["vectors"]
    for vector in vectors:
        folder = "protocol/" + vector["id"]
        raw = vector["raw_utf8"].encode()
        args = ["evidence", vector["format"], kit.put(folder + "/payload", raw)]
        if vector["manifest"] is not None:
            manifest = vector["manifest"]
            provider = kit.write(folder + "/adapter.json", {
                "$schema": ADAPTER_SCHEMA, "schema_version": 1, "protocol_version": 1,
                "provider": manifest["provider"], "provider_version": manifest["provider_version"],
                "format": "JUNIT_XML" if vector["format"] == "junit" else "SARIF210",
                "capability": "TEST_REPORTS" if vector["format"] == "junit" else "ANALYSIS_REPORTS",
            })
            args.extend(("--manifest", kit.write(folder + "/manifest.json", manifest),
                         "--adapter", provider, digest(provider.read_bytes())))
        if vector["accepted"]:
            reference.ref.verify(vector["expected"], raw)
            first = kit.accepts(*args)
            kit.check(vector["id"], first == vector["expected"] and first == kit.accepts(*args))
        else:
            kit.refuses(vector["id"], "", *args)


def provider(kit, fixtures, example, collector, support):
    sys.path.insert(0, str(support))
    import provider_controls

    cases = data(fixtures / "evidence_adapter_cases_v1.json")
    project = kit.scratch / "project"
    project.mkdir()
    executable = Path(sys.executable).resolve(strict=True)
    record = kit.put("host/adapter.json", example.read_bytes())
    registration_schema = "urn:fortress:host:v1:evidence-collector-registration"
    config = {"$schema": registration_schema, "schema_version": 1, "executable": str(executable),
              "executable_digest": digest(executable.read_bytes()), "adapter": str(record),
              "adapter_digest": digest(record.read_bytes()), "script": None}

    def register(case, code):
        script = kit.put(f"host/{case}.py", code)
        return kit.write(f"host/{case}.json",
                         {**config, "script": {"path": str(script), "digest": digest(code)}})

    reference_code = collector.read_bytes()
    registered = register("reference", reference_code)
    requests = []
    reported = None
    for index, operation in enumerate(cases["operations"]):
        case = f"exchange-{index}"
        req = kit.write(case + ".json", exchange_case(operation, case, cases["binding"]))
        requests.append(req)
        args = ("evidence", "collect", registered, req, project)
        reply = kit.accepts(*args)
        kit.check(case, reply["result"]["outcome"] == operation["outcome"]
                  and reply["producer_authenticity"] == reply["evidence_admission"] == "UNVERIFIED"
                  and reply["request_digest"] == digest(req.read_bytes()) and reply == kit.accepts(*args))
        if operation["outcome"] == "REPORTED":
            reported = reply["result"]
            envelope = reply["result"]["envelope"]
            raw = reply["result"]["raw_utf8"].encode()
            observation = cases["expected_observation"]
            requirement = {"requirement_id": "AF-PARCEL-0001-R01", "provider": "example.parcel-junit",
                           "invocation_scope": "parcel.unit", "selectors": [observation["key"]],
                           "authenticated_producer_required": False}
            proof = provider_controls.ref.resolve(envelope, raw, cases["binding"], requirement,
                                                  provider_controls.host(envelope))
            paths = reply["result"]["retained_paths"]
            expected_prefix = "__fortress/evidence/imports/" + digest(encode(envelope)).split(":")[1]
            kit.check("bound-unverified-only", envelope["observations"] == [observation]
                      and proof == cases["expected_requirement_outcome"]
                      and paths == [expected_prefix + "/envelope.json", expected_prefix + "/payload.bin"])
    kit.check("read-only-provider", not list(project.iterdir()))

    # These tiny test children use literal fixture replies. They do not import the reference adapter.
    base_reply = {"$schema": EXCHANGE_SCHEMA, "schema_version": 1, "request_id": "exchange-0",
                  "provider": "example.parcel-junit", "provider_version": "1.0.0",
                  "protocol_version": 1, "format": "JUNIT_XML", "capability": "TEST_REPORTS",
                  "outcome": "CAPABILITIES", "raw_utf8": None, "manifest": None}
    for negative in cases["negative_replies"]:
        value = {**base_reply, negative["field"]: negative["value"]}
        code = "import sys\nsys.stdin.read()\nprint(" + repr(encode(value).decode()) + ")\n"
        registration = register(negative["id"], code.encode())
        kit.refuses(negative["id"], negative["error"], "evidence", "collect", registration, requests[0], project)
    require(reported is not None, "roundtrip did not retain the bound report")
    published = {**base_reply, "outcome": "REPORTED", "raw_utf8": reported["raw_utf8"],
                 "manifest": reported["envelope"]["run_manifest"]}
    for axis in ("subject_ref", "context_ref", "authority_ref"):
        candidate = copy.deepcopy(published)
        candidate["manifest"]["binding"][axis] = "sha256:" + "f" * 64
        driver = ("import json,sys\nq=json.load(sys.stdin)\n"
                  + "reply=json.loads(" + repr(encode(candidate).decode()) + ")\n"
                  + "if q['operation']=='HELLO': reply.update(outcome='CAPABILITIES',raw_utf8=None,manifest=None)\n"
                  + "reply['request_id']=q['request_id']\nprint(json.dumps(reply))\n")
        registration = register("wrong-" + axis, driver.encode())
        kit.refuses("wrong-" + axis, "EVIDENCE_ADAPTER_BINDING_MISMATCH",
                    "evidence", "collect", registration, requests[1], project)
    timeout = register("timeout", b"import sys, time\nsys.stdin.read()\ntime.sleep(20)\n")
    kit.refuses("bounded-provider-timeout", "COLLECTOR_RESOURCE_LIMIT", "evidence", "collect", timeout, requests[0], project)
    overflow = register("overflow", b"import sys\nsys.stdin.read()\nprint('x' * 1100000)\n")
    kit.refuses("bounded-provider-output", "COLLECTOR_RESOURCE_LIMIT", "evidence", "collect", overflow, requests[0], project)
    inside = kit.write("project/host-input.json", data(registered))
    kit.refuses("candidate-cannot-register-executable", "COLLECTOR_TRUST_REQUIRED", "evidence", "collect", inside, requests[0], project)
    tampered = kit.write("host/wrong-executable.json", {**data(registered), "executable_digest": "sha256:" + "0" * 64})
    kit.refuses("pinned-executable-mismatch", "COLLECTOR_VERIFIER_UNAVAILABLE",
                "evidence", "collect", tampered, requests[0], project)
    wrong = kit.write("host/wrong-script.json", {**data(registered), "script": {
        **data(registered)["script"], "digest": "sha256:" + "0" * 64,
    }})
    kit.refuses("pinned-script-mismatch", "COLLECTOR_SCRIPT_DIGEST_MISMATCH",
                "evidence", "collect", wrong, requests[0], project)
    replay_retained(kit, fixtures, provider_controls)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kit", choices=("layout", "provider"))
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--example", required=True, type=Path)
    parser.add_argument("--collector", type=Path)
    parser.add_argument("--support", type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    exe = args.executable.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="fortress-extension-", dir=args.work_root.resolve(strict=True)) as folder:
        kit = Kit(exe, Path(folder))
        initial = digest(exe.read_bytes())
        try:
            if args.kit == "layout":
                layout(kit, args.fixtures, args.example)
            elif args.collector is not None and args.support is not None:
                provider(kit, args.fixtures, args.example, args.collector, args.support.resolve())
            else:
                raise ValueError("provider kit requires --collector and --support")
        except (AssertionError, OSError, ValueError, KeyError) as error:
            kit.check("invocation", False, str(error))
        kit.check("unchanged-executable", digest(exe.read_bytes()) == initial)
    totals = {state: sum(row["status"] == state for row in kit.results) for state in ("PASS", "FAIL", "UNAVAILABLE")}
    case_file = ("layout_extension_cases_v1.json" if args.kit == "layout"
                 else "evidence_adapter_cases_v1.json")
    inputs = {"runner": digest(Path(__file__).read_bytes()),
              "example": digest(args.example.read_bytes()),
              "cases": digest((args.fixtures / case_file).read_bytes())}
    if args.kit == "provider" and args.collector is not None:
        inputs["collector"] = digest(args.collector.read_bytes())
        inputs["normalization_vectors"] = digest((args.fixtures / "provider_vectors_v1.json").read_bytes())
    report = {"version": 1, "kit": args.kit, "status": "FAIL" if totals["FAIL"] else "PASS",
              "executable": initial, "inputs": inputs, "counts": totals, "results": kit.results}
    with args.report.open("xb") as result:
        result.write(encode(report) + b"\n")
    print(f"{args.kit}: {report['status']} ({totals['PASS']} passed, {totals['FAIL']} failed, "
          f"{totals['UNAVAILABLE']} unavailable)")
    for row in kit.results:
        if row["status"] != "PASS":
            print(f"{row['id']}: {row['status']} ({row['detail']})")
    return bool(totals["FAIL"])


if __name__ == "__main__":
    sys.exit(main())
