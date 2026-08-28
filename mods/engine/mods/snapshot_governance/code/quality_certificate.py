#!/usr/bin/env python3
"""Issue and verify the deterministic local Fortress quality certificate.

Issuance executes every canonical local quality gate. Verification is deliberately
lightweight: it validates the PASS claims, certificate stamp, complete repository
input fingerprint, and committed derived-artifact digests without executing Rust.

The SHA-256 stamp is tamper-evident, not an authenticated signature. A repository
writer can recompute it. Authenticity therefore remains explicitly UNVERIFIED until
an external trusted signing identity is configured.
"""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable


CERTIFICATE_PATH = "info/quality_certificate.json"
SCHEMA_ID = "urn:fortress:derived:v1:local-quality-certificate"
SEMANTIC_VERSION = "quality-certificate-v1"
PROFILE_ID = "fortress-complete-local-v1"
TOOLCHAIN = "1.97.1"

ARTIFACTS = (
    ("ccg", "info/contract_coherency_graph.json"),
    ("bfg", "info/behavioral_flow_graph.json"),
    ("psm", "info/program_semantic_model.json"),
    ("semantic", "info/semantic_analysis.json"),
    ("state-effect", "info/state_effect_analysis.json"),
    ("information-flow", "info/information_flow_analysis.json"),
    ("environmental", "info/environmental_analysis.json"),
    ("realized-bfg", "info/realized_behavioral_flow_graph.json"),
)

REQUIRED_GATE_IDS = (
    "ARTIFACT_BFG",
    "ARTIFACT_CCG",
    "ARTIFACT_ENVIRONMENTAL",
    "ARTIFACT_INFORMATION_FLOW",
    "ARTIFACT_PSM",
    "ARTIFACT_REALIZED_BFG",
    "ARTIFACT_SEMANTIC",
    "ARTIFACT_STATE_EFFECT",
    "AUDIT_JSON_DETERMINISM",
    "CLIPPY",
    "FORMAT",
    "RUSTDOC",
    "SCHEMA_AND_STANDARD",
    "SELF_AUDIT",
    "SELF_MODEL",
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


def repository_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = result.stdout.decode("utf-8").split("\0")
    normalized = sorted(
        path.replace("\\", "/")
        for path in paths
        if path and path.replace("\\", "/") != CERTIFICATE_PATH
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
        "data/cargo_config.toml",
    ]


def command_text(parts: Iterable[str]) -> str:
    displayed = list(parts)
    if displayed and Path(displayed[0]).name.lower() in {"cargo", "cargo.exe"}:
        displayed[0] = "cargo"
    return " ".join(displayed)


def run_command(
    root: Path,
    command: list[str],
    environment: dict[str, str],
    *,
    capture: bool = False,
) -> bytes:
    print(f"[local-certificate] {command_text(command)}", flush=True)
    result = subprocess.run(
        command,
        cwd=root,
        env=environment,
        check=False,
        stdout=subprocess.PIPE if capture else None,
    )
    if result.returncode != 0:
        raise CertificateError(
            f"quality gate exited {result.returncode}: {command_text(command)}"
        )
    return result.stdout if capture else b""


def pass_gate(gates: list[dict[str, str]], gate_id: str, command: list[str]) -> None:
    gates.append(
        {
            "id": gate_id,
            "status": "PASS",
            "command": command_text(command),
        }
    )


def issue(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not (root / ".git").exists():
        raise CertificateError(f"not a Fortress Git repository: {root}")

    environment = os.environ.copy()
    environment["CARGO_RESOLVER_LOCKFILE_PATH"] = str(
        (root / "info" / "Cargo.lock").resolve()
    )
    gates: list[dict[str, str]] = []
    destination = root / CERTIFICATE_PATH
    destination.write_text(
        json.dumps(
            {
                "$schema": SCHEMA_ID,
                "schema_version": 1,
                "semantic_version": SEMANTIC_VERSION,
                "project": "PF-FORTRESS",
                "profile": PROFILE_ID,
                "claim": "PENDING_LOCAL_QUALITY_GATES",
                "trust": {
                    "level": "untrusted-local",
                    "tamper_evidence": "NONE",
                    "authenticity": "UNVERIFIED",
                    "limitation": "No PASS evidence exists until local issuance completes.",
                },
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    initial_fingerprint, initial_file_count = repository_fingerprint(root)

    temporary_root = Path(
        os.environ.get(
            "FORTRESS_CERTIFICATE_TEMP_DIR",
            str(Path(tempfile.gettempdir()) / "fortress-quality-certificate"),
        )
    )
    temporary_root.mkdir(parents=True, exist_ok=True)
    environment["CARGO_TARGET_DIR"] = os.environ.get(
        "FORTRESS_CERTIFICATE_TARGET_DIR",
        str(Path(tempfile.gettempdir()) / "fortress-target-quality-certificate"),
    )
    if Path(environment["CARGO_TARGET_DIR"]).resolve().is_relative_to(root):
        raise CertificateError("certificate build target must remain outside the repository")

    with nullcontext(temporary_root) as temporary:
        base = cargo_base()

        formatting = base + [
            "fmt",
            "--manifest-path",
            "data/Cargo.toml",
            "--all",
            "--check",
        ]
        run_command(root, formatting, environment)
        pass_gate(gates, "FORMAT", formatting)

        clippy = base + [
            "clippy",
            "--manifest-path",
            "data/Cargo.toml",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ]
        run_command(root, clippy, environment)
        pass_gate(gates, "CLIPPY", clippy)

        schema = base + [
            "test",
            "--manifest-path",
            "data/Cargo.toml",
            "--all-features",
            "--test",
            "schema_registry",
        ]
        run_command(root, schema, environment)
        pass_gate(gates, "SCHEMA_AND_STANDARD", schema)

        self_model = base + [
            "test",
            "--manifest-path",
            "data/Cargo.toml",
            "--all-features",
            "--test",
            "self_model",
        ]
        run_command(root, self_model, environment)
        pass_gate(gates, "SELF_MODEL", self_model)

        tests = base + [
            "test",
            "--manifest-path",
            "data/Cargo.toml",
            "--workspace",
            "--all-targets",
            "--all-features",
        ]
        run_command(root, tests, environment)
        pass_gate(gates, "WORKSPACE_TESTS", tests)

        artifact_records: list[dict[str, str]] = []
        for command_name, committed_relative in ARTIFACTS:
            first = temporary / f"{command_name}-first.json"
            second = temporary / f"{command_name}-second.json"
            generator = base + [
                "run",
                "--quiet",
                "--manifest-path",
                "data/Cargo.toml",
                "-p",
                "fortress-cli",
                "--",
                command_name,
                ".",
                "--format",
                "json",
                "--output",
            ]
            run_command(root, generator + [str(first)], environment)
            run_command(root, generator + [str(second)], environment)
            first_bytes = first.read_bytes()
            if first_bytes != second.read_bytes():
                raise CertificateError(f"nondeterministic derived artifact: {command_name}")
            committed = root / committed_relative
            if first_bytes != committed.read_bytes():
                raise CertificateError(f"stale committed artifact: {committed_relative}")
            pass_gate(gates, f"ARTIFACT_{command_name.upper().replace('-', '_')}", generator)
            artifact_records.append(
                {
                    "path": committed_relative,
                    "digest": sha256_bytes(first_bytes),
                }
            )

        audit = base + [
            "run",
            "--quiet",
            "--manifest-path",
            "data/Cargo.toml",
            "-p",
            "fortress-cli",
            "--",
            "audit",
            ".",
        ]
        run_command(root, audit, environment)
        pass_gate(gates, "SELF_AUDIT", audit)

        audit_json = audit + ["--format", "json"]
        first_audit = run_command(root, audit_json, environment, capture=True)
        second_audit = run_command(root, audit_json, environment, capture=True)
        if first_audit != second_audit:
            raise CertificateError("audit JSON is not byte-deterministic")
        pass_gate(gates, "AUDIT_JSON_DETERMINISM", audit_json)

        documentation = base + [
            "doc",
            "--manifest-path",
            "data/Cargo.toml",
            "--workspace",
            "--all-features",
            "--no-deps",
        ]
        documentation_environment = environment.copy()
        documentation_environment["RUSTDOCFLAGS"] = "-D warnings"
        run_command(root, documentation, documentation_environment)
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
        "schema_version": 1,
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
        },
        "toolchain": {
            "rust": TOOLCHAIN,
            "cargo_config": "data/cargo_config.toml",
            "resolver_lockfile": "info/Cargo.lock",
            "build_artifacts": "external-temporary-directory",
        },
        "gates": gates,
        "artifacts": artifact_records,
        "audit_json_digest": sha256_bytes(first_audit),
    }
    document = dict(payload)
    document["certificate_stamp"] = certificate_stamp(payload)
    destination.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"issued {CERTIFICATE_PATH} {document['certificate_stamp']}")
    return document


def require_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        raise CertificateError(
            f"{context} fields differ: missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def verify(root: Path) -> dict[str, Any]:
    root = root.resolve()
    certificate_path = root / CERTIFICATE_PATH
    try:
        certificate_bytes = certificate_path.read_bytes()
        document = json.loads(certificate_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CertificateError(f"cannot load {CERTIFICATE_PATH}: {error}") from error
    if not isinstance(document, dict):
        raise CertificateError("quality certificate root must be an object")
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
    if document["$schema"] != SCHEMA_ID or document["schema_version"] != 1:
        raise CertificateError("unsupported quality certificate schema")
    if document["semantic_version"] != SEMANTIC_VERSION:
        raise CertificateError("unsupported quality certificate semantic version")
    if document["project"] != "PF-FORTRESS" or document["profile"] != PROFILE_ID:
        raise CertificateError("quality certificate project/profile mismatch")
    if document["claim"] != "LOCAL_QUALITY_GATES_PASS":
        raise CertificateError("quality certificate does not claim passing local gates")
    canonical_document = (
        json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    if certificate_bytes != canonical_document:
        raise CertificateError("quality certificate bytes are not canonical UTF-8/LF JSON")

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
        {"rust", "cargo_config", "resolver_lockfile", "build_artifacts"},
        "toolchain",
    )
    if toolchain != {
        "rust": TOOLCHAIN,
        "cargo_config": "data/cargo_config.toml",
        "resolver_lockfile": "info/Cargo.lock",
        "build_artifacts": "external-temporary-directory",
    }:
        raise CertificateError("quality certificate toolchain is not canonical")

    payload = dict(document)
    stamp = payload.pop("certificate_stamp")
    expected_stamp = certificate_stamp(payload)
    if stamp != expected_stamp:
        raise CertificateError(
            f"certificate stamp mismatch: {stamp!r} != {expected_stamp!r}"
        )

    source = document["source"]
    if not isinstance(source, dict):
        raise CertificateError("certificate source must be an object")
    require_exact_keys(source, {"fingerprint", "file_count", "excluded_self"}, "source")
    if source["excluded_self"] != CERTIFICATE_PATH:
        raise CertificateError("certificate self-exclusion is not canonical")
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

    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise CertificateError("certificate contains no derived artifacts")
    artifact_paths: list[str] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise CertificateError("artifact stamp must be an object")
        require_exact_keys(artifact, {"path", "digest"}, "artifact")
        relative = artifact["path"]
        if not isinstance(relative, str) or not relative.startswith("info/"):
            raise CertificateError(f"invalid artifact path: {relative!r}")
        path = root / relative
        if not path.is_file():
            raise CertificateError(f"certified artifact is missing: {relative}")
        actual_digest = sha256_bytes(path.read_bytes())
        if artifact["digest"] != actual_digest:
            raise CertificateError(
                f"certified artifact is stale: {relative} "
                f"{artifact['digest']} != {actual_digest}"
            )
        artifact_paths.append(relative)
    if artifact_paths != sorted(artifact_paths) or len(artifact_paths) != len(set(artifact_paths)):
        raise CertificateError("artifact stamps must be sorted and unique")
    expected_artifacts = sorted(path for _, path in ARTIFACTS)
    if artifact_paths != expected_artifacts:
        raise CertificateError("certificate does not bind the complete derived artifact set")

    print(
        "quality certificate PASS "
        f"source={actual_fingerprint} stamp={stamp} "
        "authenticity=UNVERIFIED"
    )
    return document


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("issue", "verify"))
    parser.add_argument("repository", nargs="?", default=".")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.operation == "issue":
            issue(Path(arguments.repository))
        else:
            verify(Path(arguments.repository))
    except (CertificateError, OSError, subprocess.SubprocessError) as error:
        print(f"quality certificate error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
