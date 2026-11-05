#!/usr/bin/env python3
"""Publish/replay application declarations through the existing OPS/control boundary.

The Rust composer owns every judgment. This adapter only builds the actual tool,
captures its canonical StateView, and binds immutable payloads/index selections.
Reporting a negative application never fabricates Rust execution or local quality.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
import quality_certificate as quality
from execution_storage import RunWorkspace, StoragePolicy, StorageError, recover_owned_orphans

PRODUCT = Path(__file__).resolve().parents[3]
MAX_REPORT_BYTES = 64 * 1024 * 1024


def canonical(value: object) -> bytes:
    # All numbers are bounded exact integers in these closed Rust-owned records.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def application_selection_key(project: str, profile: str, context: str) -> str:
    return quality.sha256_bytes(canonical(["application-selection-v1", project, profile, "repository", context]))


def capture(root: Path, executable: Path, environment: dict[str, str], workspace: RunWorkspace) -> dict:
    destination = workspace.staging / "state-view.json"
    quality.run_command(PRODUCT, [str(executable), "state-view", str(root), "--format", "json", "--output", str(destination)], environment, workspace=workspace)
    if destination.stat().st_size > MAX_REPORT_BYTES:
        raise quality.CertificateError("application report exceeds 64 MiB bound")
    content = destination.read_bytes()
    report = json.loads(content)
    if canonical(report) != content or report.get("$schema") != "urn:fortress:derived:v1:state-view" or report.get("schema_version") != 1:
        raise quality.CertificateError("tool emitted an invalid/noncanonical StateView")
    application = report.get("application")
    if not isinstance(application, dict):
        raise quality.CertificateError(f"application authority unavailable: {report.get('status')}")
    declaration, assessment = application["declaration"], application["assessment"]
    if assessment["declaration_digest"] != quality.sha256_bytes(canonical(declaration)) or declaration["binding"] != assessment["binding"] or declaration["binding"]["subject_ref"] != report["source_ref"]:
        raise quality.CertificateError("application cross-artifact binding differs")
    return report


def generation(root: Path, report: dict, file_count: int) -> tuple[dict, dict[str, bytes]]:
    application = report["application"]
    declaration, assessment = application["declaration"], application["assessment"]
    # The project is the exact root authority, not an inferred display name.
    project = application["project"]
    profile = assessment["profile_digest"]
    context = declaration["binding"]["context_ref"]
    payloads = {
        "conformance-declaration": canonical(declaration),
        "profile-assessment": canonical(assessment),
    }
    descriptors = []
    for identifier, content in sorted(payloads.items()):
        record = next(r for r in quality.INSTALLED_ARTIFACT_RECORDS if r["id"] == identifier)
        descriptors.append(dict(id=identifier, producer_id=record["owner"], schema_ref=record["schema_ref"],
            producer_semantic_version=record["producer_semantic_version"], content_digest=quality.sha256_bytes(content),
            byte_count=len(content), disposition="REQUIRED", storage=dict(kind="INCLUDED",member_name=record["member_name"])))
    manifest = {
        "$schema":"urn:fortress:derived:v3:assessment-generation-manifest", "schema_version":3,
        "generation_kind":"APPLICATION", "project":project, "profile":profile,
        "selection_key":application_selection_key(project,profile,context),
        "selection_context":dict(profile_digest=profile,scope="repository",context_ref=context),
        "source":dict(fingerprint=report["source_ref"],file_count=file_count),
        "control_layout":dict(id="fortress-control-layout-v3",digest=quality.control_layout_digest(PRODUCT)),
        "artifacts":descriptors,
    }
    return manifest, payloads


def publish(root: Path, report: dict, frozen: tuple[str,int], workspace: RunWorkspace) -> str:
    manifest, payloads = generation(root,report,frozen[1])
    identity = quality.manifest_digest(manifest)
    directory = root / quality.GENERATIONS_PATH / identity.removeprefix("sha256:")
    files = {directory / "manifest.json":quality.canonical_pretty_json(manifest)}
    for artifact in manifest["artifacts"]:
        files[directory / artifact["storage"]["member_name"]] = payloads[artifact["id"]]
    old, pointer = quality.updated_selection_index(root,identity,manifest["selection_key"])
    index = root / quality.CURRENT_INDEX_PATH
    # Refuse immutable collisions before recording intent or changing any file.
    for path,content in files.items():
        if path.exists() and (not path.is_file() or path.read_bytes() != content):
            raise quality.CertificateError("immutable application generation collision")
    if quality.repository_fingerprint(root) != frozen:
        raise quality.CertificateError("application source changed during composition")
    workspace.set_lifecycle("VALIDATING")
    workspace.prepare_publication(index,pointer,files)
    for path,content in sorted(files.items()):
        if not path.exists(): quality.atomic_write(path,content)
        if path.read_bytes() != content: raise quality.CertificateError("application member readback differs")
    if quality.repository_fingerprint(root) != frozen or (index.read_bytes() if index.is_file() else None) != old:
        raise quality.CertificateError("application source/index changed before publication")
    quality.atomic_write(index,pointer)
    if index.read_bytes() != pointer: raise quality.CertificateError("application index readback differs")
    workspace.publish(identity)
    return identity


def verify(root: Path, report: dict, file_count: int) -> str:
    expected,payloads = generation(root,report,file_count)
    index_bytes = (root / quality.CURRENT_INDEX_PATH).read_bytes()
    index = json.loads(index_bytes)
    if quality.canonical_pretty_json(index) != index_bytes: raise quality.CertificateError("noncanonical selection index")
    selected = quality.selection_entries(index).get(expected["selection_key"])
    if selected is None: raise quality.CertificateError("exact application selection is MISSING")
    if re.fullmatch(r"sha256:[0-9a-f]{64}",selected) is None: raise quality.CertificateError("invalid selected digest")
    directory = root / quality.GENERATIONS_PATH / selected.removeprefix("sha256:")
    actual_bytes = (directory / "manifest.json").read_bytes()
    actual = json.loads(actual_bytes)
    if quality.canonical_pretty_json(actual) != actual_bytes or quality.manifest_digest(actual) != selected:
        raise quality.CertificateError("INVALID application manifest")
    if actual != expected: raise quality.CertificateError("application generation is STALE or incompatible")
    for artifact in expected["artifacts"]:
        if (directory / artifact["storage"]["member_name"]).read_bytes() != payloads[artifact["id"]]:
            raise quality.CertificateError("application artifact differs from independently replayed result")
    return selected


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation",choices=("issue","verify"))
    parser.add_argument("repository",nargs="?",default=".")
    args=parser.parse_args()
    root=Path(args.repository).resolve()
    try:
        quality.validate_control_artifact_registry(PRODUCT)
        frozen=quality.repository_fingerprint(root)
        tool_source=quality.repository_fingerprint(PRODUCT)
        storage=quality.execution_storage_root()
        recover_owned_orphans(root,storage,quality.publication_paths(root))
        with RunWorkspace(root,storage,StoragePolicy.from_environment()) as workspace:
            environment=os.environ.copy()
            environment["CARGO_TARGET_DIR"]=str(workspace.target)
            environment["CARGO_RESOLVER_LOCKFILE_PATH"]=str(PRODUCT/"_info/Cargo.lock")
            transient=PRODUCT/"_data/Cargo.lock"
            preexisting=transient.read_bytes() if transient.is_file() else None
            executable=quality.certification_executable(PRODUCT,quality.cargo_base(),environment,workspace)
            quality.remove_transient_cargo_lock(PRODUCT,preexisting)
            report=capture(root,executable,environment,workspace)
            if quality.repository_fingerprint(PRODUCT) != tool_source or quality.repository_fingerprint(root) != frozen:
                raise quality.CertificateError("tool or application source changed during assessment")
            if args.operation == "issue": identity=publish(root,report,frozen,workspace)
            else:
                identity=verify(root,report,frozen[1]);workspace.set_lifecycle("VALIDATING");workspace.publish(identity)
            print(json.dumps(dict(generation=identity,decision=report["application"]["assessment"]["decision"],authenticity="UNVERIFIED",rust_suite_execution_required=False)))
        return 0
    except (quality.CertificateError,StorageError,OSError,ValueError,KeyError) as error:
        print(f"application assessment error: {error}",file=sys.stderr);return 1


if __name__ == "__main__":
    raise SystemExit(main())
