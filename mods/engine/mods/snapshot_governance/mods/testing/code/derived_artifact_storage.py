#!/usr/bin/env python3
"""Verify subject-addressed derived-projection storage invariants."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[3] / "code" / "quality_certificate.py"
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("fortress_quality_certificate", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("quality certificate module cannot be loaded")
quality = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(quality)


class DerivedArtifactStorageTests(unittest.TestCase):
    """Exercise storage classification without running semantic generators."""

    def certificate(self, fingerprint: str) -> dict[str, object]:
        content = b"canonical projection\n"
        artifacts = [
            {
                "path": path,
                "digest": quality.sha256_bytes(content),
                "bytes": len(content),
                "storage": storage,
            }
            for _, path, storage in quality.ARTIFACTS
        ]
        artifacts.sort(key=lambda artifact: artifact["path"])
        return {
            "source": {"fingerprint": fingerprint},
            "artifacts": artifacts,
        }

    def workspace(self, name: str) -> Path:
        base = Path.cwd().parent / f".fortress-derived-test-{os.getpid()}-{name}"
        if base.exists():
            shutil.rmtree(base)
        base.mkdir()
        self.addCleanup(shutil.rmtree, base, True)
        return base

    def test_registry_is_complete_sorted_and_authority_excluded(self) -> None:
        paths = quality.derived_artifact_paths()
        self.assertEqual(paths, tuple(sorted(paths)))
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(set(paths), quality.excluded_source_paths() - {quality.CERTIFICATE_PATH})
        self.assertTrue(
            all(
                storage in {quality.TRACKED_EVIDENCE, quality.LOCAL_MATERIALIZATION}
                for _, _, storage in quality.ARTIFACTS
            )
        )

    def test_missing_current_invalid_and_stale_are_distinct(self) -> None:
        fingerprint = "sha256:" + "a" * 64
        stale_fingerprint = "sha256:" + "b" * 64
        content = b"canonical projection\n"
        base = self.workspace("states")
        root = base / "repository"
        root.mkdir()
        with patch.dict(os.environ, {"FORTRESS_DERIVED_CACHE_DIR": str(base / "cache")}):
            document = self.certificate(fingerprint)
            missing = quality.local_materialization_states(root, document, fingerprint)
            self.assertTrue(missing)
            self.assertEqual({item["status"] for item in missing}, {"MISSING"})

            for artifact in document["artifacts"]:
                if artifact["storage"] == quality.LOCAL_MATERIALIZATION:
                    quality.atomic_write(
                        quality.cache_artifact_path(root, fingerprint, artifact["path"]),
                        content,
                    )
            current = quality.local_materialization_states(root, document, fingerprint)
            self.assertEqual({item["status"] for item in current}, {"CURRENT"})

            first = current[0]["path"]
            quality.cache_artifact_path(root, fingerprint, first).write_bytes(b"corrupt")
            invalid = quality.local_materialization_states(root, document, fingerprint)
            self.assertIn("INVALID", {item["status"] for item in invalid})

            stale = quality.local_materialization_states(root, document, stale_fingerprint)
            self.assertEqual({item["status"] for item in stale}, {"STALE"})

    def test_cache_must_remain_outside_repository(self) -> None:
        fingerprint = "sha256:" + "c" * 64
        base = self.workspace("boundary")
        root = base / "repository"
        root.mkdir()
        with patch.dict(os.environ, {"FORTRESS_DERIVED_CACHE_DIR": str(root / "cache")}):
            with self.assertRaises(quality.CertificateError):
                quality.cache_subject_directory(root, fingerprint)

    def test_materialization_writes_directly_to_external_temporary_root(self) -> None:
        fingerprint = "sha256:" + "d" * 64
        content = b"canonical projection\n"
        logical_path = "info/contract_coherency_graph.json"
        artifact_registry = (
            ("ccg", logical_path, quality.LOCAL_MATERIALIZATION),
        )
        document = {
            "source": {"fingerprint": fingerprint},
            "artifacts": [
                {
                    "path": logical_path,
                    "digest": quality.sha256_bytes(content),
                    "bytes": len(content),
                    "storage": quality.LOCAL_MATERIALIZATION,
                }
            ],
        }
        base = self.workspace("materialize")
        root = base / "repository"
        root.mkdir()
        temporary = base / "temporary"

        def generate(_root: Path, command: list[str], _environment: dict[str, str]) -> None:
            output = Path(command[-1])
            self.assertEqual(output.parent.resolve(), temporary.resolve())
            output.write_bytes(content)

        environment = {
            "FORTRESS_DERIVED_CACHE_DIR": str(base / "cache"),
            "FORTRESS_CERTIFICATE_TEMP_DIR": str(temporary),
            "FORTRESS_CERTIFICATE_TARGET_DIR": str(base / "target"),
        }
        with (
            patch.dict(os.environ, environment),
            patch.object(quality, "ARTIFACTS", artifact_registry),
            patch.object(quality, "SEMANTIC_ARTIFACTS", artifact_registry),
            patch.object(quality, "verify", return_value=document),
            patch.object(quality, "cargo_base", return_value=["cargo"]),
            patch.object(quality, "run_command", side_effect=generate) as runner,
        ):
            quality.materialize(root)
            self.assertEqual(runner.call_count, 2)
            self.assertEqual(
                quality.cache_artifact_path(root, fingerprint, logical_path).read_bytes(),
                content,
            )
            self.assertEqual(list(temporary.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
