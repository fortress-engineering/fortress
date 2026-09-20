#!/usr/bin/env python3
"""Issue and verify the deterministic local Fortress quality certificate.

Issuance executes every canonical local quality gate. Verification is deliberately
lightweight: it validates the PASS claims, certificate stamp, authoritative-source
fingerprint, and durable derived-artifact evidence without executing Rust. Large,
deterministic projections may be materialized in an execution-local cache without
becoming authored repository authority.

The SHA-256 stamp is tamper-evident, not an authenticated signature. A repository
writer can recompute it. Authenticity therefore remains explicitly UNVERIFIED until
an external trusted signing identity is configured.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Iterator
import uuid

# Verification must not create an untracked bytecode input before it checks the
# repository fingerprint. Keep the storage adapter import side-effect free.
sys.dont_write_bytecode = True
from execution_storage import (
    RunWorkspace,
    StorageError,
    StoragePolicy,
    recover_owned_orphans,
)


CERTIFICATE_PATH = "_info/quality_certificate.json"
SCHEMA_ID = "urn:fortress:derived:v2:local-quality-certificate"
SEMANTIC_VERSION = "quality-certificate-v2.2"
PROFILE_ID = "fortress-complete-local-v1"
TOOLCHAIN = "1.97.1"
TRACKED_EVIDENCE = "TRACKED_EVIDENCE"
LOCAL_MATERIALIZATION = "LOCAL_MATERIALIZATION"

SEMANTIC_ARTIFACTS = (
    ("ccg", "_info/contract_coherency_graph.json", LOCAL_MATERIALIZATION),
    ("bfg", "_info/behavioral_flow_graph.json", TRACKED_EVIDENCE),
    ("psm", "_info/program_semantic_model.json", LOCAL_MATERIALIZATION),
    ("semantic", "_info/semantic_analysis.json", LOCAL_MATERIALIZATION),
    (
        "semantic-conformance",
        "_info/semantic_conformance.json",
        LOCAL_MATERIALIZATION,
    ),
    ("state-effect", "_info/state_effect_analysis.json", LOCAL_MATERIALIZATION),
    ("information-flow", "_info/information_flow_analysis.json", LOCAL_MATERIALIZATION),
    ("environmental", "_info/environmental_analysis.json", TRACKED_EVIDENCE),
    ("realized-bfg", "_info/realized_behavioral_flow_graph.json", LOCAL_MATERIALIZATION),
    ("references", "_info/component_resolution_index.json", TRACKED_EVIDENCE),
    ("source-artifacts", "_info/source_artifact_model.json", LOCAL_MATERIALIZATION),
)

CERTIFICATION_ARTIFACTS = (
    ("evidence-graph", "_info/evidence_graph.json", TRACKED_EVIDENCE),
    ("certification", "_info/certification.json", TRACKED_EVIDENCE),
    ("verified-bfg", "_info/verified_behavioral_flow_graph.json", TRACKED_EVIDENCE),
)

ARTIFACTS = SEMANTIC_ARTIFACTS + CERTIFICATION_ARTIFACTS

REQUIRED_GATE_IDS = (
    "ARTIFACT_BFG",
    "ARTIFACT_CCG",
    "ARTIFACT_CERTIFICATION",
    "ARTIFACT_ENVIRONMENTAL",
    "ARTIFACT_EVIDENCE_GRAPH",
    "ARTIFACT_INFORMATION_FLOW",
    "ARTIFACT_PSM",
    "ARTIFACT_REALIZED_BFG",
    "ARTIFACT_REFERENCES",
    "ARTIFACT_SEMANTIC",
    "ARTIFACT_SEMANTIC_CONFORMANCE",
    "ARTIFACT_SOURCE_ARTIFACTS",
    "ARTIFACT_STATE_EFFECT",
    "ARTIFACT_VERIFIED_BFG",
    "AUDIT_JSON_DETERMINISM",
    "CLIPPY",
    "DERIVED_ARTIFACT_STORAGE",
    "EXECUTION_STORAGE",
    "FORMAT",
    "FULL_PROFILE_CERTIFICATION",
    "PROJECT_FILING_SYSTEM",
    "RUSTDOC",
    "SCHEMA_AND_STANDARD",
    "SCHEMA_ARTIFACTS",
    "SELF_AUDIT",
    "SELF_MODEL",
    "SOURCE_ARCHITECTURE",
    "WORKSPACE_TESTS",
)


class CertificateError(RuntimeError):
    """Raised when issuance or verification cannot establish the certificate."""


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def certificate_stamp(payload: dict[str, Any]) -> str:
    return sha256_bytes(canonical_payload_bytes(payload))


def derived_artifact_paths() -> tuple[str, ...]:
    """Return the canonical logical projection registry."""
    return tuple(sorted(path for _, path, _ in ARTIFACTS))


def excluded_source_paths() -> set[str]:
    """Return generated paths excluded from authoritative source identity."""
    return {CERTIFICATE_PATH, *derived_artifact_paths()}


def repository_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = result.stdout.decode("utf-8").split("\0")
    excluded = excluded_source_paths()
    normalized = sorted(
        normalized
        for path in paths
        if path
        if (normalized := path.replace("\\", "/")) not in excluded
    )
    if not normalized:
        raise CertificateError("repository input set is empty")
    return normalized


def repository_fingerprint(root: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    paths = repository_files(root)
    for relative in paths:
        path = root / Path(relative)
        if not path.is_file():
            raise CertificateError(f"certificate input is not a file: {relative}")
        content = path.read_bytes()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
        digest.update(b"\n")
    return "sha256:" + digest.hexdigest(), len(paths)


def derived_cache_root(root: Path) -> Path:
    """Resolve the execution-local projection cache without persisting its path."""
    configured = os.environ.get("FORTRESS_DERIVED_CACHE_DIR")
    base = Path(configured) if configured else Path(tempfile.gettempdir()) / "fortress-derived"
    cache = (base / "PF-FORTRESS").resolve()
    if cache == root or cache.is_relative_to(root):
        raise CertificateError("derived projection cache must remain outside the repository")
    return cache


def execution_storage_root() -> Path:
    """Resolve the machine-local storage registry shared by Python jobs."""
    return Path(
        os.environ.get(
            "FORTRESS_EXECUTION_STORAGE_DIR", str(Path(tempfile.gettempdir()) / "fx")
        )
    )


def publication_paths(root: Path) -> set[Path]:
    """List only the derived tracked paths the issuer may restore."""
    return {
        (root / CERTIFICATE_PATH).resolve(),
        *(
            (root / logical_path).resolve()
            for _, logical_path, storage in ARTIFACTS
            if storage == TRACKED_EVIDENCE
        ),
    }


def cache_subject_directory(root: Path, source_fingerprint: str) -> Path:
    """Map an exact source fingerprint to its machine-local cache directory."""
    algorithm, separator, value = source_fingerprint.partition(":")
    if algorithm != "sha256" or not separator or len(value) != 64:
        raise CertificateError("invalid source fingerprint for derived cache")
    return derived_cache_root(root) / value


def cache_artifact_path(root: Path, source_fingerprint: str, logical_path: str) -> Path:
    """Resolve one logical projection inside its exact-subject cache."""
    return cache_subject_directory(root, source_fingerprint) / Path(logical_path).name


def atomic_write(path: Path, content: bytes) -> None:
    """Write generated bytes atomically within their destination directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".pending")
    temporary.write_bytes(content)
    os.replace(temporary, path)


def write_projection_with_budget(
    workspace: RunWorkspace, path: Path, content: bytes
) -> None:
    """Reject a cache write that would exceed the selected local budget."""
    previous = path.stat().st_size if path.is_file() else 0
    workspace.check_projection_budget(max(0, len(content) - previous))
    atomic_write(path, content)


@contextmanager
def issuance_directory(parent: Path) -> Iterator[Path]:
    """Create child-process-accessible staging with inherited host permissions."""
    directory = parent / f"fortress-issuance-{os.getpid()}-{uuid.uuid4().hex}"
    directory.mkdir(mode=0o777)
    try:
        yield directory
    finally:
        shutil.rmtree(directory)


def cargo_base() -> list[str]:
    configured = os.environ.get("CARGO")
    cargo = configured or shutil.which("cargo")
    if cargo is None:
        candidate = Path.home() / ".cargo" / "bin" / (
            "cargo.exe" if os.name == "nt" else "cargo"
        )
        cargo = str(candidate)
    return [
        cargo,
        f"+{TOOLCHAIN}",
        "--config",
        "_data/cargo_config.toml",
    ]


def remove_transient_cargo_lock(root: Path, preexisting: bytes | None) -> None:
    """Remove only a newly generated copy of the canonical Cargo lock."""
    transient = root / "_data" / "Cargo.lock"
    canonical = root / "_info" / "Cargo.lock"
    if preexisting is not None:
        if not transient.is_file() or transient.read_bytes() != preexisting:
            raise CertificateError("pre-existing _data/Cargo.lock changed during issuance")
        return
    if not transient.exists():
        return
    if not canonical.is_file() or transient.read_bytes() != canonical.read_bytes():
        raise CertificateError("uncertain _data/Cargo.lock ownership; retaining file")
    transient.unlink()


def command_text(parts: Iterable[str]) -> str:
    displayed = list(parts)
    if displayed and Path(displayed[0]).name.lower() in {"cargo", "cargo.exe"}:
        displayed[0] = "cargo"
    elif displayed and Path(displayed[0]).name.lower().startswith("python"):
        displayed[0] = "python"
    for index, part in enumerate(displayed[1:], start=1):
        if Path(part).is_absolute():
            displayed[index] = "<machine-local-path>"
    return " ".join(displayed)


def run_command(
    root: Path,
    command: list[str],
    environment: dict[str, str],
    *,
    capture: bool = False,
    workspace: RunWorkspace | None = None,
) -> bytes:
    print(f"[local-certificate] {command_text(command)}", flush=True)
    process = subprocess.Popen(
        command,
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE if capture else None,
    )
    recorded = False
    descendants_uncertain = False
    try:
        if workspace is not None:
            workspace.record_child(process.pid)
            recorded = True
        while True:
            try:
                output, _ = process.communicate(timeout=1)
                break
            except subprocess.TimeoutExpired:
                if workspace is not None:
                    workspace.check_budget()
    except BaseException:
        # Terminating Cargo does not prove its compiler or test descendants
        # have exited. Retain the child record for next-start review.
        descendants_uncertain = True
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        raise
    finally:
        if (
            recorded
            and not descendants_uncertain
            and workspace is not None
            and process.poll() is not None
        ):
            workspace.clear_child(process.pid)
    if process.returncode != 0:
        raise CertificateError(
            f"quality gate exited {process.returncode}: {command_text(command)}"
        )
    return output if capture else b""


def pass_gate(gates: list[dict[str, str]], gate_id: str, command: list[str]) -> None:
    gates.append(
        {
            "id": gate_id,
            "status": "PASS",
            "command": command_text(command),
        }
    )


def issue(root: Path) -> dict[str, Any]:
    """Run a bounded issuer without changing a prior certificate on failure."""
    root = root.resolve()
    storage_root = execution_storage_root()
    recovered = recover_owned_orphans(root, storage_root, publication_paths(root))
    for item in recovered:
        print(f"[local-certificate] recovery {item['status']}: {item['journal']}")
    with RunWorkspace(root, storage_root, StoragePolicy.from_environment()) as workspace:
        return _issue(root, workspace)


def _issue(root: Path, workspace: RunWorkspace) -> dict[str, Any]:
    root = root.resolve()
    if not (root / ".git").exists():
        raise CertificateError(f"not a Fortress Git repository: {root}")

    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["CARGO_RESOLVER_LOCKFILE_PATH"] = str(
        (root / "_info" / "Cargo.lock").resolve()
    )
    gates: list[dict[str, str]] = []
    destination = root / CERTIFICATE_PATH
    initial_fingerprint, initial_file_count = repository_fingerprint(root)
    workspace.track_projection_root(derived_cache_root(root))
    transient_lock = root / "_data" / "Cargo.lock"
    preexisting_lock = transient_lock.read_bytes() if transient_lock.is_file() else None
    workspace.record_preexisting(transient_lock)

    temporary_root = workspace.staging
    if temporary_root.is_relative_to(root):
        raise CertificateError("certificate temporary output must remain outside the repository")
    temporary_root.mkdir(parents=True, exist_ok=True)
    environment["CARGO_TARGET_DIR"] = str(workspace.target)
    if Path(environment["CARGO_TARGET_DIR"]).resolve().is_relative_to(root):
        raise CertificateError("certificate build target must remain outside the repository")

    with nullcontext(temporary_root) as temporary:
        base = cargo_base()

        storage_test = [
            sys.executable,
            "engine/snapshot_governance/testing/_code/derived_artifact_storage.py",
        ]
        run_command(root, storage_test, environment, workspace=workspace)
        pass_gate(gates, "DERIVED_ARTIFACT_STORAGE", storage_test)

        execution_storage_test = [
            sys.executable,
            "engine/snapshot_governance/testing/_code/execution_storage.py",
        ]
        run_command(root, execution_storage_test, environment, workspace=workspace)
        pass_gate(gates, "EXECUTION_STORAGE", execution_storage_test)

        formatting = base + [
            "fmt",
            "--manifest-path",
            "_data/Cargo.toml",
            "--all",
            "--check",
        ]
        run_command(root, formatting, environment, workspace=workspace)
        pass_gate(gates, "FORMAT", formatting)

        clippy = base + [
            "clippy",
            "--manifest-path",
            "_data/Cargo.toml",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ]
        run_command(root, clippy, environment, workspace=workspace)
        remove_transient_cargo_lock(root, preexisting_lock)
        pass_gate(gates, "CLIPPY", clippy)

        schema = base + [
            "test",
            "--manifest-path",
            "_data/Cargo.toml",
            "--all-features",
            "--test",
            "schema_registry",
        ]
        run_command(root, schema, environment, workspace=workspace)
        pass_gate(gates, "SCHEMA_AND_STANDARD", schema)

        filing_system = base + [
            "test",
            "--manifest-path",
            "_data/Cargo.toml",
            "--all-features",
            "--test",
            "filing_system",
            "--test",
            "repo_module_001",
            "--test",
            "repo_docs_001",
        ]
        run_command(root, filing_system, environment, workspace=workspace)
        pass_gate(gates, "PROJECT_FILING_SYSTEM", filing_system)

        source_architecture = base + [
            "test",
            "--manifest-path",
            "_data/Cargo.toml",
            "--all-features",
            "--test",
            "source_architecture",
        ]
        run_command(root, source_architecture, environment, workspace=workspace)
        pass_gate(gates, "SOURCE_ARCHITECTURE", source_architecture)

        self_model = base + [
            "test",
            "--manifest-path",
            "_data/Cargo.toml",
            "--all-features",
            "--test",
            "self_model",
        ]
        run_command(root, self_model, environment, workspace=workspace)
        pass_gate(gates, "SELF_MODEL", self_model)

        artifact_records: list[dict[str, Any]] = []
        pending_artifacts: dict[str, bytes] = {}
        projection_directory = temporary / "projections"
        audit_output = temporary / "audit.json"
        certification_outputs = {
            "evidence-graph": temporary / "evidence-graph.json",
            "certification": temporary / "certification.json",
            "verified-bfg": temporary / "verified-bfg.json",
        }
        certify = base + [
            "run",
            "--quiet",
            "--all-features",
            "--manifest-path",
            "_data/Cargo.toml",
            "-p",
            "fortress-cli",
            "--",
            "certify",
            ".",
            "--format",
            "json",
            "--evidence-output",
            str(certification_outputs["evidence-graph"]),
            "--certification-output",
            str(certification_outputs["certification"]),
            "--verified-bfg-output",
            str(certification_outputs["verified-bfg"]),
            "--projection-output-dir",
            str(projection_directory),
            "--audit-output",
            str(audit_output),
        ]
        run_command(root, certify, environment, capture=True, workspace=workspace)
        remove_transient_cargo_lock(root, preexisting_lock)
        # The certify boundary executes the canonical unfiltered workspace suite.
        # Governed generator tests prove repeatability; routine issuance binds one
        # exact semantic stack and every resulting canonical digest.
        pass_gate(gates, "WORKSPACE_TESTS", certify)

        for command_name, logical_path, storage in SEMANTIC_ARTIFACTS:
            projection = projection_directory / logical_path
            projection_bytes = projection.read_bytes()
            pending_artifacts[logical_path] = projection_bytes
            pass_gate(
                gates,
                f"ARTIFACT_{command_name.upper().replace('-', '_')}",
                certify,
            )
            artifact_records.append(
                {
                    "path": logical_path,
                    "digest": sha256_bytes(projection_bytes),
                    "bytes": len(projection_bytes),
                    "storage": storage,
                }
            )

        for command_name, logical_path, storage in CERTIFICATION_ARTIFACTS:
            artifact_bytes = certification_outputs[command_name].read_bytes()
            if storage != TRACKED_EVIDENCE:
                raise CertificateError("certification evidence must remain tracked")
            pending_artifacts[logical_path] = artifact_bytes
            pass_gate(
                gates,
                f"ARTIFACT_{command_name.upper().replace('-', '_')}",
                certify,
            )
            artifact_records.append(
                {
                    "path": logical_path,
                    "digest": sha256_bytes(artifact_bytes),
                    "bytes": len(artifact_bytes),
                    "storage": storage,
                }
            )

        artifact_files = {
            logical_path: str((projection_directory / logical_path).resolve())
            for _, logical_path, _ in SEMANTIC_ARTIFACTS
        }
        artifact_files.update(
            {
                logical_path: str(certification_outputs[command_name].resolve())
                for command_name, logical_path, _ in CERTIFICATION_ARTIFACTS
            }
        )
        artifact_manifest = temporary / "schema-artifacts.json"
        artifact_manifest.write_bytes(
            json.dumps(artifact_files, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        schema_artifacts = base + [
            "test",
            "--manifest-path",
            "_data/Cargo.toml",
            "--all-features",
            "--test",
            "artifact_schemas",
        ]
        schema_environment = environment.copy()
        schema_environment["FORTRESS_SCHEMA_ARTIFACT_MANIFEST"] = str(artifact_manifest)
        run_command(root, schema_artifacts, schema_environment, workspace=workspace)
        pass_gate(gates, "SCHEMA_ARTIFACTS", schema_artifacts)

        certification_document = json.loads(
            certification_outputs["certification"].read_text(encoding="utf-8")
        )
        if (
            certification_document.get("status") != "PASS"
            or certification_document.get("profile", {}).get("id")
            != "CERT-FULL-SNAPSHOT-V1"
        ):
            raise CertificateError("full-snapshot Certification is not PASS")
        pass_gate(gates, "FULL_PROFILE_CERTIFICATION", certify)

        first_audit = audit_output.read_bytes()
        audit_document = json.loads(first_audit)
        if audit_document.get("outcome") != "PASS":
            raise CertificateError("self-audit from certification stack is not PASS")
        pass_gate(gates, "SELF_AUDIT", certify)
        pass_gate(gates, "AUDIT_JSON_DETERMINISM", certify)

        documentation = base + [
            "doc",
            "--manifest-path",
            "_data/Cargo.toml",
            "--workspace",
            "--all-features",
            "--no-deps",
        ]
        documentation_environment = environment.copy()
        documentation_environment["RUSTDOCFLAGS"] = "-D warnings"
        run_command(root, documentation, documentation_environment, workspace=workspace)
        pass_gate(gates, "RUSTDOC", documentation)

    gates.sort(key=lambda gate: gate["id"])
    artifact_records.sort(key=lambda artifact: artifact["path"])
    source_fingerprint, source_file_count = repository_fingerprint(root)
    if (
        source_fingerprint != initial_fingerprint
        or source_file_count != initial_file_count
    ):
        raise CertificateError(
            "repository inputs changed while local quality gates were executing: "
            f"before={initial_fingerprint}/{initial_file_count} "
            f"after={source_fingerprint}/{source_file_count}"
        )
    payload: dict[str, Any] = {
        "$schema": SCHEMA_ID,
        "schema_version": 2,
        "semantic_version": SEMANTIC_VERSION,
        "project": "PF-FORTRESS",
        "profile": PROFILE_ID,
        "claim": "LOCAL_QUALITY_GATES_PASS",
        "trust": {
            "level": "untrusted-local",
            "tamper_evidence": "SHA-256",
            "authenticity": "UNVERIFIED",
            "limitation": (
                "Digest stamps detect mutation and staleness but are not signatures; "
                "authenticated antiforgery requires an external trusted signing identity."
            ),
        },
        "source": {
            "fingerprint": source_fingerprint,
            "file_count": source_file_count,
            "excluded_self": CERTIFICATE_PATH,
            "excluded_derived_artifacts": list(derived_artifact_paths()),
        },
        "toolchain": {
            "rust": TOOLCHAIN,
            "cargo_config": "_data/cargo_config.toml",
            "resolver_lockfile": "_info/Cargo.lock",
            "build_artifacts": "external-temporary-directory",
            "derived_projections": "external-subject-addressed-cache",
        },
        "gates": gates,
        "artifacts": artifact_records,
        "audit_json_digest": sha256_bytes(first_audit),
    }
    document = dict(payload)
    document["certificate_stamp"] = certificate_stamp(payload)
    workspace.set_lifecycle("VALIDATING")
    certificate_bytes = (
        json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    workspace.prepare_publication(
        destination,
        certificate_bytes,
        {
            root / logical_path: pending_artifacts[logical_path]
            for _, logical_path, storage in ARTIFACTS
            if storage == TRACKED_EVIDENCE
        },
    )
    prior_bytes: dict[Path, bytes | None] = {}
    try:
        for _, logical_path, storage in ARTIFACTS:
            path = (
                root / logical_path
                if storage == TRACKED_EVIDENCE
                else cache_artifact_path(root, source_fingerprint, logical_path)
            )
            prior_bytes[path] = path.read_bytes() if path.is_file() else None
            if storage == LOCAL_MATERIALIZATION:
                write_projection_with_budget(
                    workspace, path, pending_artifacts[logical_path]
                )
            else:
                atomic_write(path, pending_artifacts[logical_path])
        prior_bytes[destination] = destination.read_bytes() if destination.is_file() else None
        atomic_write(destination, certificate_bytes)
    except BaseException:
        try:
            for path, original in reversed(list(prior_bytes.items())):
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, original)
        except BaseException:
            workspace.set_lifecycle("RECOVERY_REQUIRED")
            raise
        raise
    workspace.publish(document["certificate_stamp"])
    print(f"issued {CERTIFICATE_PATH} {document['certificate_stamp']}")
    return document


def require_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        raise CertificateError(
            f"{context} fields differ: missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def load_certificate(root: Path) -> tuple[bytes, dict[str, Any]]:
    """Load canonical certificate bytes and validate their digest stamp."""
    certificate_path = root / CERTIFICATE_PATH
    try:
        certificate_bytes = certificate_path.read_bytes()
        document = json.loads(certificate_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CertificateError(f"cannot load {CERTIFICATE_PATH}: {error}") from error
    if not isinstance(document, dict):
        raise CertificateError("quality certificate root must be an object")
    canonical_document = (
        json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    if certificate_bytes != canonical_document:
        raise CertificateError("quality certificate bytes are not canonical UTF-8/LF JSON")
    if "certificate_stamp" not in document:
        raise CertificateError("quality certificate stamp is absent")
    payload = dict(document)
    stamp = payload.pop("certificate_stamp")
    expected_stamp = certificate_stamp(payload)
    if stamp != expected_stamp:
        raise CertificateError(
            f"certificate stamp mismatch: {stamp!r} != {expected_stamp!r}"
        )
    return certificate_bytes, document


def artifact_records(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate and return the complete canonical artifact registry."""
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise CertificateError("certificate contains no derived artifacts")
    paths: list[str] = []
    expected_storage = {path: storage for _, path, storage in ARTIFACTS}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise CertificateError("artifact stamp must be an object")
        require_exact_keys(artifact, {"path", "digest", "bytes", "storage"}, "artifact")
        relative = artifact["path"]
        if relative not in expected_storage:
            raise CertificateError(f"unknown artifact path: {relative!r}")
        if artifact["storage"] != expected_storage[relative]:
            raise CertificateError(f"artifact storage mismatch: {relative}")
        if not isinstance(artifact["bytes"], int) or artifact["bytes"] <= 0:
            raise CertificateError(f"invalid artifact byte count: {relative}")
        digest = artifact["digest"]
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise CertificateError(f"invalid artifact digest: {relative}")
        paths.append(relative)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise CertificateError("artifact stamps must be sorted and unique")
    if paths != list(derived_artifact_paths()):
        raise CertificateError("certificate does not bind the complete derived artifact set")
    return artifacts


def local_materialization_states(
    root: Path,
    document: dict[str, Any],
    actual_fingerprint: str,
) -> list[dict[str, str]]:
    """Classify local projection bytes relative to the current source subject."""
    recorded_fingerprint = document["source"]["fingerprint"]
    states: list[dict[str, str]] = []
    for artifact in artifact_records(document):
        if artifact["storage"] != LOCAL_MATERIALIZATION:
            continue
        if recorded_fingerprint != actual_fingerprint:
            state = "STALE"
        else:
            path = cache_artifact_path(root, recorded_fingerprint, artifact["path"])
            if not path.is_file():
                state = "MISSING"
            else:
                content = path.read_bytes()
                state = (
                    "CURRENT"
                    if len(content) == artifact["bytes"]
                    and sha256_bytes(content) == artifact["digest"]
                    else "INVALID"
                )
        states.append({"path": artifact["path"], "status": state})
    return states


def verify(root: Path) -> dict[str, Any]:
    root = root.resolve()
    certificate_bytes, document = load_certificate(root)
    require_exact_keys(
        document,
        {
            "$schema",
            "schema_version",
            "semantic_version",
            "project",
            "profile",
            "claim",
            "trust",
            "source",
            "toolchain",
            "gates",
            "artifacts",
            "audit_json_digest",
            "certificate_stamp",
        },
        "certificate",
    )
    if document["$schema"] != SCHEMA_ID or document["schema_version"] != 2:
        raise CertificateError("unsupported quality certificate schema")
    if document["semantic_version"] != SEMANTIC_VERSION:
        raise CertificateError("unsupported quality certificate semantic version")
    if document["project"] != "PF-FORTRESS" or document["profile"] != PROFILE_ID:
        raise CertificateError("quality certificate project/profile mismatch")
    if document["claim"] != "LOCAL_QUALITY_GATES_PASS":
        raise CertificateError("quality certificate does not claim passing local gates")
    trust = document["trust"]
    if not isinstance(trust, dict):
        raise CertificateError("certificate trust must be an object")
    require_exact_keys(
        trust,
        {"level", "tamper_evidence", "authenticity", "limitation"},
        "trust",
    )
    if (
        trust["level"] != "untrusted-local"
        or trust["tamper_evidence"] != "SHA-256"
        or trust["authenticity"] != "UNVERIFIED"
    ):
        raise CertificateError("certificate overstates local evidence trust")

    toolchain = document["toolchain"]
    if not isinstance(toolchain, dict):
        raise CertificateError("certificate toolchain must be an object")
    require_exact_keys(
        toolchain,
        {
            "rust",
            "cargo_config",
            "resolver_lockfile",
            "build_artifacts",
            "derived_projections",
        },
        "toolchain",
    )
    if toolchain != {
        "rust": TOOLCHAIN,
        "cargo_config": "_data/cargo_config.toml",
        "resolver_lockfile": "_info/Cargo.lock",
        "build_artifacts": "external-temporary-directory",
        "derived_projections": "external-subject-addressed-cache",
    }:
        raise CertificateError("quality certificate toolchain is not canonical")
    stamp = document["certificate_stamp"]

    source = document["source"]
    if not isinstance(source, dict):
        raise CertificateError("certificate source must be an object")
    require_exact_keys(
        source,
        {
            "fingerprint",
            "file_count",
            "excluded_self",
            "excluded_derived_artifacts",
        },
        "source",
    )
    if source["excluded_self"] != CERTIFICATE_PATH:
        raise CertificateError("certificate self-exclusion is not canonical")
    if source["excluded_derived_artifacts"] != list(derived_artifact_paths()):
        raise CertificateError("certificate derived-artifact exclusions are not canonical")
    actual_fingerprint, actual_count = repository_fingerprint(root)
    if source["fingerprint"] != actual_fingerprint or source["file_count"] != actual_count:
        raise CertificateError(
            "quality certificate is stale: "
            f"recorded={source['fingerprint']}/{source['file_count']} "
            f"actual={actual_fingerprint}/{actual_count}"
        )

    gates = document["gates"]
    if not isinstance(gates, list) or not gates:
        raise CertificateError("quality certificate contains no gates")
    gate_ids: list[str] = []
    for gate in gates:
        if not isinstance(gate, dict):
            raise CertificateError("certificate gate must be an object")
        require_exact_keys(gate, {"id", "status", "command"}, "gate")
        if gate["status"] != "PASS":
            raise CertificateError(f"quality gate is not PASS: {gate['id']}")
        if not isinstance(gate["id"], str) or not gate["id"]:
            raise CertificateError("quality gate identity is empty")
        if not isinstance(gate["command"], str) or not gate["command"]:
            raise CertificateError(f"quality gate command is empty: {gate['id']}")
        gate_ids.append(gate["id"])
    if gate_ids != sorted(gate_ids) or len(gate_ids) != len(set(gate_ids)):
        raise CertificateError("quality gates must be sorted and unique")
    if tuple(gate_ids) != REQUIRED_GATE_IDS:
        raise CertificateError("quality certificate does not bind every required gate")

    for artifact in artifact_records(document):
        if artifact["storage"] != TRACKED_EVIDENCE:
            continue
        relative = artifact["path"]
        path = root / relative
        if not path.is_file():
            raise CertificateError(f"certified tracked artifact is missing: {relative}")
        content = path.read_bytes()
        if len(content) != artifact["bytes"] or sha256_bytes(content) != artifact["digest"]:
            raise CertificateError(f"certified tracked artifact is stale: {relative}")

    materialization = local_materialization_states(root, document, actual_fingerprint)
    counts = {
        state: sum(1 for item in materialization if item["status"] == state)
        for state in ("CURRENT", "MISSING", "STALE", "INVALID")
    }

    print(
        "quality certificate PASS "
        f"source={actual_fingerprint} stamp={stamp} "
        "authenticity=UNVERIFIED "
        f"local_materialization={counts}"
    )
    return document


def materialize(root: Path) -> None:
    """Reconstruct exact certified bulk projections in the local subject cache."""
    root = root.resolve()
    recovered = recover_owned_orphans(
        root, execution_storage_root(), publication_paths(root)
    )
    for item in recovered:
        print(f"[materialize] recovery {item['status']}: {item['journal']}")
    with RunWorkspace(
        root, execution_storage_root(), StoragePolicy.from_environment()
    ) as workspace:
        _materialize(root, workspace)


def _materialize(root: Path, workspace: RunWorkspace) -> None:
    """Execute one leased materialization without changing declaration truth."""
    document = verify(root)
    workspace.track_projection_root(derived_cache_root(root))
    source_fingerprint = document["source"]["fingerprint"]
    expected = {artifact["path"]: artifact for artifact in artifact_records(document)}
    environment = os.environ.copy()
    environment["CARGO_RESOLVER_LOCKFILE_PATH"] = str(
        (root / "_info" / "Cargo.lock").resolve()
    )
    environment["CARGO_TARGET_DIR"] = str(workspace.target)
    if Path(environment["CARGO_TARGET_DIR"]).resolve().is_relative_to(root):
        raise CertificateError("materialization build target must remain outside the repository")

    temporary_root = workspace.staging
    if temporary_root.is_relative_to(root):
        raise CertificateError("materialization temporary output must remain outside the repository")
    temporary_root.mkdir(parents=True, exist_ok=True)
    temporary_outputs: list[Path] = []
    try:
        base = cargo_base()
        for command_name, logical_path, storage in SEMANTIC_ARTIFACTS:
            if storage != LOCAL_MATERIALIZATION:
                continue
            first = temporary_root / f"materialize-{os.getpid()}-{command_name}-first.json"
            second = temporary_root / f"materialize-{os.getpid()}-{command_name}-second.json"
            temporary_outputs.extend((first, second))
            first.unlink(missing_ok=True)
            second.unlink(missing_ok=True)
            generator = base + [
                "run",
                "--quiet",
                "--manifest-path",
                "_data/Cargo.toml",
                "-p",
                "fortress-cli",
                "--",
                command_name,
                ".",
                "--format",
                "json",
                "--output",
            ]
            run_command(root, generator + [str(first)], environment, workspace=workspace)
            run_command(root, generator + [str(second)], environment, workspace=workspace)
            content = first.read_bytes()
            if content != second.read_bytes():
                raise CertificateError(f"nondeterministic derived artifact: {command_name}")
            record = expected[logical_path]
            if len(content) != record["bytes"] or sha256_bytes(content) != record["digest"]:
                raise CertificateError(
                    f"generated projection does not match certified digest: {logical_path}"
                )
            write_projection_with_budget(
                workspace,
                cache_artifact_path(root, source_fingerprint, logical_path),
                content,
            )
    finally:
        for output in temporary_outputs:
            output.unlink(missing_ok=True)

    states = local_materialization_states(root, document, source_fingerprint)
    if any(item["status"] != "CURRENT" for item in states):
        raise CertificateError("local projection materialization is incomplete")
    workspace.set_lifecycle("VALIDATING")
    workspace.publish(source_fingerprint)
    print(f"materialized {len(states)} certified projections for {source_fingerprint}")


def artifact_status(root: Path) -> bool:
    """Report local projection state without conflating absence with conformance."""
    root = root.resolve()
    _, document = load_certificate(root)
    actual_fingerprint, _ = repository_fingerprint(root)
    states = local_materialization_states(root, document, actual_fingerprint)
    priorities = {"CURRENT": 0, "MISSING": 1, "STALE": 2, "INVALID": 3}
    overall = max((item["status"] for item in states), key=priorities.__getitem__)
    output = {
        "source_fingerprint": actual_fingerprint,
        "certificate_source_fingerprint": document["source"]["fingerprint"],
        "status": overall,
        "artifacts": states,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2) + "\n", end="")
    return overall == "CURRENT"


def clean_materializations(root: Path) -> None:
    """Remove idle Python-owned subject projections, retaining unknown cache data."""
    root = root.resolve()
    recovered = recover_owned_orphans(
        root, execution_storage_root(), publication_paths(root)
    )
    for item in recovered:
        print(f"[clean] recovery {item['status']}: {item['journal']}")
    cache = derived_cache_root(root)
    if cache.name != "PF-FORTRESS" or cache == Path(cache.anchor):
        raise CertificateError("refusing to remove an unexpected cache target")
    allowed = {
        Path(logical_path).name
        for _, logical_path, storage in ARTIFACTS
        if storage == LOCAL_MATERIALIZATION
    }
    removed = 0
    retained: list[str] = []
    with RunWorkspace(
        root, execution_storage_root(), StoragePolicy.from_environment()
    ) as workspace:
        workspace.track_projection_root(cache)
        if cache.is_dir():
            for subject in cache.iterdir():
                if (
                    subject.is_symlink()
                    or not subject.is_dir()
                    or re.fullmatch(r"[0-9a-f]{64}", subject.name) is None
                ):
                    retained.append(subject.name)
                    continue
                entries = list(subject.iterdir())
                if any(
                    entry.is_symlink() or not entry.is_file() or entry.name not in allowed
                    for entry in entries
                ):
                    retained.append(subject.name)
                    continue
                shutil.rmtree(subject)
                removed += 1
        workspace.set_lifecycle("VALIDATING")
        workspace.publish(f"cleaned-subjects:{removed}")
    print(f"removed {removed} idle subject caches; retained {len(retained)} unknown entries")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation",
        choices=("issue", "verify", "materialize", "artifact-status", "clean"),
    )
    parser.add_argument("repository", nargs="?", default=".")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.operation == "issue":
            issue(Path(arguments.repository))
        elif arguments.operation == "verify":
            verify(Path(arguments.repository))
        elif arguments.operation == "materialize":
            materialize(Path(arguments.repository))
        elif arguments.operation == "artifact-status":
            return 0 if artifact_status(Path(arguments.repository)) else 2
        else:
            clean_materializations(Path(arguments.repository))
    except (CertificateError, StorageError, OSError, subprocess.SubprocessError) as error:
        print(f"quality certificate error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
