"""Exercise the verified package from isolated directories with no Cargo on PATH."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from queue import Queue
import shutil
import subprocess
import sys
from threading import Thread

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "cli/_code"))
sys.path.insert(0, str(ROOT / "editor/testing/_code"))
import package_install as distribution
from host_runner import sample


def protocol(exe, root, cwd, environment):
    child = subprocess.Popen([str(exe),"serve","--mcp",str(root)], cwd=cwd, env=environment,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    replies = Queue(2)

    def collect():
        while line := child.stdout.readline(2 * 1024**2 + 1):
            replies.put(line)

    reader = Thread(target=collect, daemon=True)
    reader.start()

    def send(request):
        child.stdin.write(json.dumps(request, ensure_ascii=True).encode() + b"\n")
        child.stdin.flush()
        if "id" not in request:
            return None
        line = replies.get(timeout=90)
        assert len(line) <= 2 * 1024**2
        response = json.loads(line)
        assert response["id"] == request["id"]
        return response

    try:
        init = send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"installed-qualification","version":"1"}}})
        assert init["result"]["protocolVersion"] == "2025-11-25"
        send({"jsonrpc":"2.0","method":"notifications/initialized"})
        tools = send({"jsonrpc":"2.0","id":2,"method":"tools/list"})
        only, = tools["result"]["tools"]
        assert only["name"]=="fortress_inspect" and only["annotations"]["readOnlyHint"] is True
        raw = send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"fortress_inspect","arguments":{"request":{"protocol_version":5,
            "request_id":"installed-status","method":"status","parameters":{}}}}})["result"]
        refused = send({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
            "name":"migrate_apply","arguments":{"approval":"not-an-authorization"}}})
        assert refused["error"]["data"]["code"] == "TOOL_UNAVAILABLE"
        assert json.loads(raw["content"][0]["text"]) == raw["structuredContent"]
        child.stdin.close()
        assert child.wait(timeout=10) == 0
        return raw["structuredContent"]
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=15)


def snapshot(root):
    return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


def selected_external_evidence(run, exe, slot, results):
    """Exercise a real explicitly selected import and the standalone public consumer."""
    root = results / "external evidence project"
    sample(root)
    binding = json.loads(run(exe, "declare", root))["binding"]
    authority = results / "host collector"
    authority.mkdir()
    sdk = slot / "share/fortress/sdk/provider"
    adapter = sdk / "evidence_adapter_example_v1.json"
    collector = sdk / "example_evidence_collector.py"
    executable = Path(sys.executable).resolve(strict=True)

    def encode(value):
        # These fixture DTOs have ASCII keys and exact integers, while the
        # trusted host selectors must retain Unicode path spelling.
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()

    def write(name, value):
        path = authority / name
        path.write_bytes(encode(value))
        return path

    registration = write("registration.json", {
        "$schema": "urn:fortress:host:v1:evidence-collector-registration", "schema_version": 1,
        "executable": str(executable), "executable_digest": "sha256:" + distribution.hash_file(executable)[1],
        "adapter": str(adapter), "adapter_digest": "sha256:" + distribution.hash_file(adapter)[1],
        "script": {"path": str(collector), "digest": "sha256:" + distribution.hash_file(collector)[1]},
    })
    request = write("request.json", {
        "$schema": "urn:fortress:schema:v1:evidence-adapter-exchange", "schema_version": 1,
        "request_id": "installed-example", "operation": "COLLECT", "binding": binding,
        "invocation_scope": "parcel.unit",
    })
    response = json.loads(run(exe, "evidence", "collect", registration, request, root))
    assert response["evidence_admission"] == response["producer_authenticity"] == "UNVERIFIED"
    reported = response["result"]
    assert reported["outcome"] == "REPORTED"
    envelope = encode(reported["envelope"])
    identifier = "sha256:" + distribution.digest(envelope)
    raw_payload = reported["raw_utf8"].encode()
    directory = root / "__fortress/evidence/imports" / identifier.split(":")[1]
    directory.mkdir(parents=True)
    (directory / "envelope.json").write_bytes(envelope)
    (directory / "payload.bin").write_bytes(raw_payload)
    inventory = reported["envelope"]["run_manifest"]["inventory"]
    selection = write("selection.json", {
        "$schema": "urn:fortress:derived:v1:evidence-input-set", "schema_version": 1,
        "binding": binding, "selected": [{"envelope_digest": identifier,
            "payload_digest": "sha256:" + distribution.digest(raw_payload),
            "inventory_digest": "sha256:" + distribution.digest(encode(inventory))}],
    })
    state = authority / "state.json"
    run(exe, "state-view", root, "--evidence-inputs", selection, "--output", state)
    portable = authority / "portable"
    predicate = "https://example.invalid/fortress/assurance/v1"
    exported = json.loads(run(exe, "bundle", "export", root, "--state", state,
                              "--output", portable, "--predicate-type", predicate))
    assert {"provider-envelope:" + identifier,
            "provider-payload:sha256:" + distribution.digest(raw_payload)} <= {
        artifact["id"] for artifact in exported["manifest"]["artifacts"]}
    verified = json.loads(run(sys.executable, "-I", "-B", slot/"share/verify_bundle.py", portable,
                              "--predicate-type", predicate))
    assert verified["integrity"] == "VERIFIED" and verified["authenticity"] == "UNVERIFIED"
    assert json.loads(run(exe, "declare", root))["binding"] == binding
    return {"envelope": identifier, "integrity": verified["integrity"],
            "authenticity": verified["authenticity"]}


def selected_python_worker(run, exe, slot, manifest, results):
    """Exercise the explicitly selected compile-only worker from the installed archive."""
    path = "share/fortress/workers/python_lexical_worker.py"
    worker = slot / path
    _, worker_sha = distribution.hash_file(worker)
    assert worker_sha == next(row["sha256"] for row in manifest["files"] if row["path"] == path)
    if sys.implementation.name != "cpython" or sys.version_info[:2] not in ((3, 12), (3, 13)):
        return {"status": "UNAVAILABLE", "reason": "Qualified CPython 3.12 or 3.13 is unavailable"}
    interpreter = Path(sys.executable).resolve(strict=True)
    descriptor = run(interpreter, "-I", "-S", "-B", worker, "--describe-runtime")
    assert descriptor.endswith(b"\n")
    descriptor_ref = "sha256:" + distribution.digest(descriptor[:-1])
    root = results / "isolated python project"
    root.mkdir()
    member = root / "source.py"
    member.write_bytes(b"def count(value):\n    return value + 1\n")
    before = snapshot(root)
    registration = results / "python-registration.json"
    registration.write_text(json.dumps({
        "$schema": "urn:fortress:host:v1:python-lexical-registration",
        "schema_version": 1,
        "interpreter": str(interpreter),
        "interpreter_sha256": "sha256:" + distribution.hash_file(interpreter)[1],
        "worker": str(worker),
        "runtime_ref": descriptor_ref,
        "grammar": f"cpython{sys.version_info.major}.{sys.version_info.minor}",
    }), encoding="utf-8")
    mode = ("source-artifacts", "--observe-python", root, registration, "source.py", "lexical")
    emitted = run(exe, *mode)
    assert emitted == run(exe, *mode)
    observed = json.loads(emitted)
    report = observed["observation"]["report"]
    assert report["outcome"] == "LEXICAL" and report["target_execution"] == "NOT_RUN"
    assert report["source_ref"] == "sha256:" + before["source.py"]
    assert report["worker_ref"] == "sha256:" + worker_sha
    assert report["runtime_ref"] == descriptor_ref
    assert {scope["name"] for scope in report["observations"]["scopes"]} == {"top", "count"}
    assert snapshot(root) == before
    return {"status": "PASS", "worker": report["worker_ref"], "runtime": descriptor_ref,
            "observation": "sha256:" + distribution.digest(emitted), "source_unchanged": True}


def execute(package, results, history=None):
    results.mkdir()
    transfer = results / "received"
    transfer.mkdir()
    archive, = sorted(package.glob("fortress-*.zip"))
    for asset in (archive,package/"manifest.json",package/"manifest.sha256",package/"install.py"):
        shutil.copyfile(asset,transfer/asset.name)
    archive = transfer / archive.name
    manifest_file = transfer / "manifest.json"
    raw = manifest_file.read_bytes()
    expected = (transfer/"manifest.sha256").read_text().strip()
    assert distribution.digest(raw) == expected
    m = distribution.verify(archive, raw)
    assert distribution.hash_file(transfer/"install.py")[1] == m["build"]["installer_sha256"]
    store = results / "User applications - 安装"
    cwd = results / "unrelated working dir"
    cwd.mkdir()
    root = results / "independent project"
    sample(root)
    starting = snapshot(root)
    # Windows system DLL resolution and Linux glibc do not require development tools.
    env = {key:os.environ[key] for key in ("SystemRoot","WINDIR","TEMP","TMP","TMPDIR","USERPROFILE","HOME")
           if key in os.environ}
    env["PATH"] = str(cwd)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    def run(executable,*args,success=(0,),environment=env):
        r = subprocess.run([str(executable),*map(str,args)],cwd=cwd,env=environment,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,check=False)
        assert r.returncode in success,(r.returncode,r.stderr[-4000:],r.stdout[-3000:])
        return r.stdout

    args = ("-I","-B", transfer/"install.py", "install", archive, manifest_file, store,
            "--manifest-sha256", expected)
    slot = Path(json.loads(run(sys.executable,*args))["slot"])
    assert json.loads(run(sys.executable,*args))["slot"] == str(slot)
    exe = slot / "bin" / distribution.executable_name()
    assert distribution.hash_file(exe)[1] == next(x["sha256"] for x in m["files"] if x["path"]==exe.relative_to(slot).as_posix())
    assert run(exe,"--version").decode().strip() == "fortress " + m["product_version"]
    sdk = slot / "share/fortress/sdk"
    extensions = {}
    for family, example in (
        ("layout", "layout_extension_example_v1.json"),
        ("provider", "evidence_adapter_example_v1.json"),
    ):
        fixtures = sdk / family
        report = results / f"{family}-extension-kit.json"
        options = () if family == "layout" else ("--collector", fixtures/"example_evidence_collector.py",
                                                 "--support", fixtures)
        run(sys.executable, "-I", "-B", sdk/"extension_conformance.py", family, "--executable", exe,
            "--fixtures", fixtures, "--example", fixtures/example, "--work-root", results,
            "--report", report, *options)
        tested = json.loads(report.read_bytes())
        assert tested["status"] == "PASS" and tested["executable"] == "sha256:" + distribution.hash_file(exe)[1]
        extensions[family] = tested["counts"]
    cli = json.loads(run(exe,"status","--format","json",root))
    observed = protocol(exe,root,cwd,env)
    assert cli["state_ref"] == observed["state_ref"] and cli["result"]==observed["result"]
    assert cli["result"]["data"]["actual_authority"]["configuration"] == "DECLARED"
    doctor = json.loads(run(exe,"doctor","--format","json",root))
    assert doctor["operational_state"]=="COMPLETED"
    explanation = json.loads(run(exe,"explain","rule:ARCH-SEMANTIC-001","--format","json",root,success=(0,1,2)))
    assert explanation["actual_source_ref"] == observed["actual_source_ref"]
    audit = json.loads(run(exe,"audit","--format","json",root,success=(0,1,2)))
    assert "filesystem.read" in json.dumps(audit)
    edition = json.loads(run(exe,"upgrade","inspect","--root",root,"--format","json"))
    assert edition["edition"]["edition"] == json.loads((root/"contract.json").read_bytes())["ecosystem"]["standard"]["edition"]
    assert edition == json.loads(run(exe,"upgrade","inspect","--root",root,"--format","json"))
    malformed = cwd/"malformed-bundle.zip"
    malformed.write_bytes(b"invalid portable evidence")
    predicate = "https://example.invalid/fortress/assurance/v1"
    verified = run(exe,"bundle","verify",malformed,"--predicate-type",predicate,
                   environment=env | {"FORTRESS_VERIFIER_PYTHON":sys.executable},success=(1,2))
    assert json.loads(verified).get("integrity") != "VERIFIED"
    no_python = run(exe,"bundle","verify",malformed,"--predicate-type",predicate,
                    environment=env | {"FORTRESS_VERIFIER_PYTHON":str(cwd/"absent-python")},success=(1,2))
    assert json.loads(no_python)["error"]["code"] == "VERIFIER_UNAVAILABLE"
    independent = run(sys.executable,"-I","-B",slot/"share/verify_bundle.py",malformed,
                      "--predicate-type",predicate,success=(1,2))
    assert json.loads(independent).get("integrity") != "VERIFIED"
    evidence_state = "malformed or unavailable refused"
    if history is not None:
        portable = cwd / "selected-history"
        shutil.copytree(history, portable)
        checked = json.loads(run(sys.executable,"-I","-B",slot/"share/verify_bundle.py",portable,
                                 "--predicate-type",predicate))
        through_cli = json.loads(run(exe,"bundle","verify",portable,"--predicate-type",predicate,
                                     environment=env | {"FORTRESS_VERIFIER_PYTHON":sys.executable}))
        assert checked == through_cli and checked["integrity"] == "VERIFIED" and checked["authenticity"] == "UNVERIFIED"
        evidence_state = "selected historical integrity verified and malformed or unavailable refused"
    external_evidence = selected_external_evidence(run, exe, slot, results)
    python_worker = selected_python_worker(run, exe, slot, m, results)
    native = results / "uninitialized project"
    (native/"src").mkdir(parents=True)
    (native/"src/lib.rs").write_bytes(b"pub fn original() -> u8 { 7 }\n")
    (native/"Cargo.toml").write_bytes(b'[package]\nname = "distribution_fixture"\nversion = "0.1.0"\nedition = "2024"\n')
    native_bytes = snapshot(native)
    proposal = cwd/"bootstrap.json"
    run(exe,"init",native,"--project-id","PF-DISTRIBUTION-FIXTURE","--display-name","Distribution Fixture","--output",proposal)
    # The system temp directory can be on a different volume from the fixture.
    storage = env | {"FORTRESS_EXECUTION_STORAGE_DIR": str(results / "migration-storage")}
    observed_bootstrap = json.loads(run(exe,"init","apply",native,"--proposal",proposal,environment=storage))
    assert observed_bootstrap["certification"] == "NOT_ESTABLISHED"
    assert all(snapshot(native)[name] == digest for name,digest in native_bytes.items())
    assert snapshot(root)==starting
    (store/"unrelated-user-notes.txt").write_bytes(b"keep")
    (results/"installed-path.txt").write_text(str(exe),encoding="utf-8")
    (results/"result.json").write_text(json.dumps({"status":"PASS","manifest_sha256":expected,
        "source_commit":m["source_commit"],"target":m["target"],"installed_executable_sha256":distribution.hash_file(exe)[1],
        "fixture_source_ref":edition["source_ref"],"runtime_path":"isolated empty working directory",
        "source_unchanged":True,"bootstrap_preserved_source":True,"mcp":"PASS","optional_verifier":evidence_state,
        "extension_kits":extensions,"external_evidence":external_evidence,
        "python_lexical_worker":python_worker},indent=2),encoding="utf-8")
    return slot


def retire(results):
    installed = Path((results/"installed-path.txt").read_text(encoding="utf-8"))
    slot = installed.parent.parent
    store = slot.parent
    manifest = (results/"received/manifest.sha256").read_text().strip()
    subprocess.run([sys.executable,"-I","-B",str(results/"received/install.py"),"remove",str(store),slot.name,
                    "--manifest-sha256",manifest],check=True,timeout=120)
    assert not slot.exists() and (store/"unrelated-user-notes.txt").read_bytes()==b"keep"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("results", type=Path)
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--history", type=Path)
    args = parser.parse_args()
    if args.remove:
        retire(args.results.resolve(strict=True))
    else:
        slot = execute(args.package.resolve(strict=True), args.results.resolve(), args.history)
        print(json.dumps({"status": "PASS", "slot": str(slot)}))
