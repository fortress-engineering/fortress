#!/usr/bin/env python3
"""Perform the one-time, role-aware migration into the fixed control namespace.

This adapter accepts only the inventoried v1 locations. It copies immutable
historical output bytes into a content-addressed generation before removing old
paths, refuses every destination conflict, and never treats history as current.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any
import uuid


INPUT_MOVES = (
    ("_data/project.json", "__fortress/.fsconfig"),
    ("_data/finding_governance.json", "__fortress/governance/finding_governance.json"),
    ("_data/information_flow_policy.json", "__fortress/governance/information_flow_policy.json"),
)

OUTPUTS = (
    ("bfg", "_info/behavioral_flow_graph.json", "behavioral_flow_graph.json", "behavioral_semantics", "urn:fortress:derived:v1:behavioral-flow-graph", "1.0.0"),
    ("certification", "_info/certification.json", "certification.json", "certification", "urn:fortress:derived:v1:certification-result", "2.0.0"),
    ("references", "_info/component_resolution_index.json", "component_resolution_index.json", "reference_resolution", "urn:fortress:derived:v1:component-resolution-index", "1.0.0"),
    ("environmental", "_info/environmental_analysis.json", "environmental_analysis.json", "environmental_semantics", "urn:fortress:derived:v1:environmental-analysis", "1.0.0"),
    ("evidence-graph", "_info/evidence_graph.json", "evidence_graph.json", "certification", "urn:fortress:derived:v2:evidence-graph", "2.0.0"),
    ("quality-certificate", "_info/quality_certificate.json", "quality_certificate.json", "snapshot_governance", "urn:fortress:derived:v2:local-quality-certificate", "quality-certificate-v2.2"),
    ("verified-bfg", "_info/verified_behavioral_flow_graph.json", "verified_behavioral_flow_graph.json", "certification", "urn:fortress:derived:v1:verified-behavioral-flow-graph", "2.0.0"),
)


class MigrationError(RuntimeError):
    """Raised when the narrow migration cannot preserve exact authority."""


def digest(content: bytes) -> str:
    """Return one lowercase SHA-256 identifier."""
    return "sha256:" + hashlib.sha256(content).hexdigest()


def canonical(value: dict[str, Any]) -> bytes:
    """Serialize digest material with sorted compact JSON keys."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pretty(value: dict[str, Any]) -> bytes:
    """Serialize a repository record as deterministic UTF-8/LF JSON."""
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def atomic_write(path: Path, content: bytes) -> None:
    """Create one file atomically in its destination directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".migration-" + uuid.uuid4().hex)
    temporary.write_bytes(content)
    os.replace(temporary, path)


def migrate_inputs(root: Path) -> list[str]:
    """Move only the three registered active inputs, refusing dual authority."""
    moved: list[str] = []
    for old_name, new_name in INPUT_MOVES:
        old = root / old_name
        new = root / new_name
        if old.exists() and new.exists():
            raise MigrationError(f"dual authority conflict: {old_name} and {new_name}")
        if old.is_file():
            content = old.read_bytes()
            atomic_write(new, content)
            if new.read_bytes() != content:
                raise MigrationError(f"migrated bytes differ: {new_name}")
            old.unlink()
            moved.append(f"{old_name} -> {new_name}")
        elif not new.is_file():
            raise MigrationError(f"required authority is absent: {old_name} / {new_name}")
    return moved


def historical_manifest(root: Path, payloads: dict[str, bytes]) -> dict[str, Any]:
    """Describe exact old output bytes without asserting current freshness."""
    try:
        old_certificate = json.loads(payloads["quality-certificate"].decode("utf-8"))
        source = old_certificate["source"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise MigrationError(f"historical quality certificate is invalid: {error}") from error
    layout_bytes = (root / "engine/project_model/_data/control_layout_v1.json").read_bytes()
    artifacts: list[dict[str, Any]] = []
    origins: list[dict[str, str]] = []
    for identifier, old_name, member, owner, schema, version in OUTPUTS:
        content = payloads[identifier]
        artifacts.append(
            {
                "id": identifier,
                "producer_id": owner,
                "schema_ref": schema,
                "producer_semantic_version": version,
                "content_digest": digest(content),
                "byte_count": len(content),
                "disposition": "REQUIRED",
                "storage": {"kind": "INCLUDED", "member_name": member},
            }
        )
        origins.append({"id": identifier, "path": old_name, "content_digest": digest(content)})
    artifacts.sort(key=lambda item: item["id"])
    origins.sort(key=lambda item: item["id"])
    return {
        "$schema": "urn:fortress:derived:v1:assessment-generation-manifest",
        "schema_version": 1,
        "generation_kind": "HISTORICAL_MIGRATION",
        "project": old_certificate.get("project", "PF-FORTRESS"),
        "profile": old_certificate.get("profile", "fortress-complete-local-v1"),
        "selection_key": digest(canonical({"historical_origin": "legacy-root-info-v1"})),
        "source": {"fingerprint": source["fingerprint"], "file_count": source["file_count"]},
        "control_layout": {"id": "fortress-control-layout-v1", "digest": digest(layout_bytes)},
        "artifacts": artifacts,
        "origin_provenance": origins,
    }


def migrate_outputs(root: Path) -> tuple[str | None, list[str]]:
    """Archive the exact seven old output files as an unselected generation."""
    present = [(record, root / record[1]) for record in OUTPUTS if (root / record[1]).is_file()]
    if not present:
        return None, []
    if len(present) != len(OUTPUTS):
        missing = sorted(record[1] for record in OUTPUTS if not (root / record[1]).is_file())
        raise MigrationError(f"partial legacy output set; missing={missing}")
    payloads = {record[0]: path.read_bytes() for record, path in present}
    manifest = historical_manifest(root, payloads)
    generation_digest = digest(canonical(manifest))
    generation = root / "__fortress/evidence/generations" / generation_digest.removeprefix("sha256:")
    files = {generation / "manifest.json": pretty(manifest)}
    for identifier, _, member, *_ in OUTPUTS:
        files[generation / member] = payloads[identifier]
    for path, content in files.items():
        if path.exists() and (not path.is_file() or path.read_bytes() != content):
            raise MigrationError(f"immutable generation conflict: {path.relative_to(root)}")
    for path, content in files.items():
        if not path.exists():
            atomic_write(path, content)
    for record, old_path in present:
        if digest(old_path.read_bytes()) != next(
            item["content_digest"] for item in manifest["origin_provenance"] if item["id"] == record[0]
        ):
            raise MigrationError(f"legacy output changed during migration: {record[1]}")
    removed: list[str] = []
    for record, old_path in present:
        old_path.unlink()
        removed.append(record[1])
    return generation_digest, removed


def migrate(root: Path) -> dict[str, Any]:
    """Run the bounded migration and report exact actions."""
    root = root.resolve()
    if not (root / ".git").exists():
        raise MigrationError("migration root is not a Git repository")
    inputs = migrate_inputs(root)
    generation, outputs = migrate_outputs(root)
    return {
        "status": "MIGRATED",
        "input_moves": inputs,
        "historical_generation": generation,
        "removed_legacy_outputs": outputs,
        "current_selection_created": False,
    }


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", nargs="?", default=".")
    arguments = parser.parse_args()
    try:
        print(json.dumps(migrate(Path(arguments.repository)), indent=2))
    except (MigrationError, OSError) as error:
        print(f"control migration error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
