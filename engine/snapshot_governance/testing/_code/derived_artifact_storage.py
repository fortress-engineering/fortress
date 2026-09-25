#!/usr/bin/env python3
"""Verify subject-addressed derived-projection storage invariants."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch


MODULE_PATH = Path(__file__).resolve().parents[2] / "_code" / "quality_certificate.py"
ROOT = MODULE_PATH.parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("fortress_quality_certificate", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("quality certificate module cannot be loaded")
quality = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(quality)

MIGRATION_PATH = MODULE_PATH.parent / "control_migration.py"
MIGRATION_SPEC = importlib.util.spec_from_file_location(
    "fortress_control_migration", MIGRATION_PATH
)
if MIGRATION_SPEC is None or MIGRATION_SPEC.loader is None:
    raise RuntimeError("control migration module cannot be loaded")
migration = importlib.util.module_from_spec(MIGRATION_SPEC)
MIGRATION_SPEC.loader.exec_module(migration)


class DerivedArtifactStorageTests(unittest.TestCase):
    """Exercise storage classification without running semantic generators."""

    def test_shared_control_registry_matches_python_contract(self) -> None:
        quality.validate_control_artifact_registry(ROOT)

    def test_fingerprint_binds_ignored_governance_and_excludes_evidence(self) -> None:
        base = self.workspace("fingerprint-partition")
        root = base / "repository"
        governance = root / "__fortress" / "governance"
        governance.mkdir(parents=True)
        (root / "__fortress" / ".fsconfig").write_text(
            json.dumps(
                {
                    "$schema": "urn:fortress:schema:v3:project-configuration",
                    "schema_version": 3,
                    "observation_exclusions": [".git", "target"],
                    "logical_modules": [],
                }
            ),
            encoding="utf-8",
        )
        finding = governance / "finding_governance.json"
        finding.write_text("{}\n", encoding="utf-8")
        (governance / "information_flow_policy.json").write_text("{}\n", encoding="utf-8")
        (root / ".gitignore").write_text("__fortress/\n", encoding="utf-8")
        first, count = quality.repository_fingerprint(root)
        evidence = root / quality.GENERATIONS_PATH / ("a" * 64) / "manifest.json"
        evidence.parent.mkdir(parents=True)
        evidence.write_text("generated\n", encoding="utf-8")
        second, second_count = quality.repository_fingerprint(root)
        self.assertEqual((first, count), (second, second_count))
        finding.write_text("{\"changed\":true}\n", encoding="utf-8")
        third, third_count = quality.repository_fingerprint(root)
        self.assertNotEqual(first, third)
        self.assertEqual(count, third_count)

    def test_dual_configuration_authority_is_rejected(self) -> None:
        base = self.workspace("dual-config")
        root = base / "repository"
        (root / "__fortress").mkdir(parents=True)
        (root / "__fortress" / ".fsconfig").write_text("{}\n", encoding="utf-8")
        (root / "_data").mkdir()
        (root / quality.LEGACY_CONFIG_PATH).write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(quality.CertificateError, "dual"):
            quality.repository_files(root)

    def test_selection_never_falls_back_to_an_unselected_generation(self) -> None:
        base = self.workspace("no-selection-fallback")
        root = base / "repository"
        current = root / quality.CURRENT_INDEX_PATH
        current.parent.mkdir(parents=True)
        selected = "sha256:" + "a" * 64
        current.write_bytes(
            quality.canonical_pretty_json(
                {
                    "$schema": "urn:fortress:derived:v1:assessment-selection-index",
                    "schema_version": 1,
                    "selections": [
                        {
                            "selection_key": quality.selection_key(),
                            "generation_digest": selected,
                        }
                    ],
                }
            )
        )
        unselected = root / quality.GENERATIONS_PATH / ("b" * 64)
        unselected.mkdir(parents=True)
        (unselected / "manifest.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(
            quality.CertificateError, "cannot load selected generation manifest"
        ):
            quality.load_selected_generation(root)

    def certificate(self, fingerprint: str) -> dict[str, object]:
        content = b"canonical projection\n"
        artifacts = [
            {
                "id": identifier,
                "digest": quality.sha256_bytes(content),
                "bytes": len(content),
                "storage": storage,
            }
            for identifier, _, storage in quality.ARTIFACTS
        ]
        artifacts.sort(key=lambda artifact: artifact["id"])
        return {
            "source": {"fingerprint": fingerprint},
            "artifacts": artifacts,
        }

    def workspace(self, name: str) -> Path:
        base = Path.cwd() / f".fortress-derived-test-{os.getpid()}-{name}"
        if base.exists():
            shutil.rmtree(base)
        base.mkdir()
        self.addCleanup(shutil.rmtree, base, True)
        return base

    def test_verifier_import_does_not_write_source_bytecode(self) -> None:
        base = self.workspace("import-bytecode")
        for name in ("quality_certificate.py", "execution_storage.py"):
            shutil.copyfile(MODULE_PATH.parent / name, base / name)
        environment = os.environ.copy()
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        environment.pop("PYTHONPYCACHEPREFIX", None)
        result = subprocess.run(
            [sys.executable, str(base / "quality_certificate.py"), "--help"],
            cwd=base,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertFalse((base / "__pycache__").exists())

    def test_interrupted_cargo_retains_child_record_for_descendant_review(self) -> None:
        process = Mock()
        process.pid = 12345
        process.communicate.side_effect = subprocess.TimeoutExpired("cargo", 1)
        process.poll.return_value = -1
        workspace = Mock()
        workspace.check_budget.side_effect = quality.StorageError("injected sample failure")
        with patch.object(quality.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(quality.StorageError, "injected"):
                quality.run_command(Path.cwd(), ["cargo"], {}, workspace=workspace)
        process.terminate.assert_called_once()
        workspace.record_child.assert_called_once_with(12345)
        workspace.clear_child.assert_not_called()

    def test_registry_is_complete_sorted_and_authority_excluded(self) -> None:
        paths = quality.derived_artifact_paths()
        self.assertEqual(paths, tuple(sorted(paths)))
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(quality.excluded_source_paths(), {quality.EVIDENCE_ROOT})
        self.assertEqual(len(quality.derived_artifact_ids()), len(paths))
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
                    logical_path = next(
                        path
                        for identifier, path, _ in quality.ARTIFACTS
                        if identifier == artifact["id"]
                    )
                    quality.atomic_write(
                        quality.cache_artifact_path(root, fingerprint, logical_path),
                        content,
                    )
            current = quality.local_materialization_states(root, document, fingerprint)
            self.assertEqual({item["status"] for item in current}, {"CURRENT"})

            first = current[0]["id"]
            first_path = next(path for identifier, path, _ in quality.ARTIFACTS if identifier == first)
            quality.cache_artifact_path(root, fingerprint, first_path).write_bytes(b"corrupt")
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

    def test_selection_index_preserves_unrelated_contexts(self) -> None:
        base = self.workspace("selection-index")
        root = base / "repository"
        current = root / quality.CURRENT_INDEX_PATH
        current.parent.mkdir(parents=True)
        other_key = "sha256:" + "1" * 64
        current.write_bytes(
            quality.canonical_pretty_json(
                {
                    "$schema": "urn:fortress:derived:v1:assessment-selection-index",
                    "schema_version": 1,
                    "selections": [
                        {
                            "selection_key": other_key,
                            "generation_digest": "sha256:" + "2" * 64,
                        }
                    ],
                }
            )
        )
        old, updated = quality.updated_selection_index(root, "sha256:" + "3" * 64)
        self.assertEqual(old, current.read_bytes())
        document = json.loads(updated)
        self.assertEqual(len(document["selections"]), 2)
        self.assertEqual(
            [item["selection_key"] for item in document["selections"]],
            sorted([other_key, quality.selection_key()]),
        )

    def test_legacy_outputs_migrate_byte_exact_without_becoming_current(self) -> None:
        base = self.workspace("legacy-migration")
        root = base / "repository"
        (root / ".git").mkdir(parents=True)
        layout_source = MODULE_PATH.parents[2] / "project_model" / "_data" / "control_layout_v1.json"
        layout_target = root / "engine/project_model/_data/control_layout_v1.json"
        layout_target.parent.mkdir(parents=True)
        shutil.copyfile(layout_source, layout_target)
        for _, target in migration.INPUT_MOVES:
            path = root / target
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
        payloads: dict[str, bytes] = {}
        for identifier, old_name, *_ in migration.OUTPUTS:
            path = root / old_name
            path.parent.mkdir(parents=True, exist_ok=True)
            content = (
                json.dumps(
                    {
                        "project": "PF-FORTRESS",
                        "profile": "fortress-complete-local-v1",
                        "source": {
                            "fingerprint": "sha256:" + "a" * 64,
                            "file_count": 1,
                        },
                    }
                ).encode("utf-8")
                if identifier == "quality-certificate"
                else f"{identifier}\n".encode("utf-8")
            )
            path.write_bytes(content)
            payloads[identifier] = content
        report = migration.migrate(root)
        self.assertIsNotNone(report["historical_generation"])
        self.assertFalse((root / quality.CURRENT_INDEX_PATH).exists())
        generation = root / quality.GENERATIONS_PATH / report["historical_generation"].removeprefix("sha256:")
        manifest = json.loads((generation / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["generation_kind"], "HISTORICAL_MIGRATION")
        for identifier, old_name, member, *_ in migration.OUTPUTS:
            self.assertFalse((root / old_name).exists())
            self.assertEqual((generation / member).read_bytes(), payloads[identifier])

    def test_migration_refuses_dual_configuration_authority(self) -> None:
        base = self.workspace("dual-authority")
        root = base / "repository"
        (root / ".git").mkdir(parents=True)
        for name in (quality.CONFIG_PATH, quality.LEGACY_CONFIG_PATH):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(migration.MigrationError, "dual authority"):
            migration.migrate_inputs(root)

    def test_issuance_directory_is_child_process_accessible(self) -> None:
        base = self.workspace("issuance-directory")
        with quality.issuance_directory(base) as temporary:
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; import sys; "
                        "Path(sys.argv[1], 'child-output').write_bytes(b'accessible')"
                    ),
                    str(temporary),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            self.assertEqual((temporary / "child-output").read_bytes(), b"accessible")
        self.assertFalse(temporary.exists())

    def test_issuance_failure_preserves_prior_certificate_and_user_lock(self) -> None:
        base = self.workspace("prior-certificate")
        root = base / "repository"
        (root / ".git").mkdir(parents=True)
        (root / "_data").mkdir()
        prior_certificate = root / quality.CURRENT_INDEX_PATH
        prior_certificate.parent.mkdir(parents=True)
        prior_certificate.write_bytes(b"prior valid certificate\n")
        user_lock = root / "_data" / "Cargo.lock"
        user_lock.write_bytes(b"user lock bytes")
        environment = {
            "FORTRESS_EXECUTION_STORAGE_DIR": str(base / "execution-storage"),
            "FORTRESS_DISK_RESERVE_BYTES": "0",
            "FORTRESS_DERIVED_CACHE_DIR": str(base / "cache"),
        }
        with (
            patch.dict(os.environ, environment),
            patch.object(quality, "validate_control_artifact_registry"),
            patch.object(quality, "repository_fingerprint", return_value=("sha256:source", 2)),
            patch.object(quality, "run_command", side_effect=quality.CertificateError("injected gate failure")),
        ):
            with self.assertRaisesRegex(quality.CertificateError, "injected"):
                quality.issue(root)
        self.assertEqual(prior_certificate.read_bytes(), b"prior valid certificate\n")
        self.assertEqual(user_lock.read_bytes(), b"user lock bytes")

    def test_transient_lock_cleanup_preserves_preexisting_bytes(self) -> None:
        base = self.workspace("lock")
        root = base / "repository"
        (root / "_data").mkdir(parents=True)
        (root / "_info").mkdir()
        (root / "_info" / "Cargo.lock").write_bytes(b"canonical")
        transient = root / "_data" / "Cargo.lock"
        transient.write_bytes(b"user lock")
        quality.remove_transient_cargo_lock(root, b"user lock")
        self.assertEqual(transient.read_bytes(), b"user lock")
        transient.write_bytes(b"changed")
        with self.assertRaises(quality.CertificateError):
            quality.remove_transient_cargo_lock(root, b"user lock")
        self.assertEqual(transient.read_bytes(), b"changed")

    def test_compile_and_analysis_failures_preserve_prior_bytes(self) -> None:
        for failure_call in (4, 9):
            with self.subTest(failure_call=failure_call):
                base = self.workspace(f"failure-{failure_call}")
                root = base / "repository"
                (root / ".git").mkdir(parents=True)
                (root / "_data").mkdir()
                (root / "_info").mkdir()
                (root / "_info" / "Cargo.lock").write_bytes(b"canonical lock")
                certificate = root / quality.CURRENT_INDEX_PATH
                certificate.parent.mkdir(parents=True)
                certificate.write_bytes(b"prior certificate")
                user_lock = root / "_data" / "Cargo.lock"
                user_lock.write_bytes(b"user lock")
                calls = 0

                def fail_at_gate(*_args: object, **_kwargs: object) -> bytes:
                    nonlocal calls
                    calls += 1
                    if calls == failure_call:
                        raise quality.CertificateError("injected gate failure")
                    return b""

                environment = {
                    "FORTRESS_EXECUTION_STORAGE_DIR": str(base / "storage"),
                    "FORTRESS_DERIVED_CACHE_DIR": str(base / "cache"),
                    "FORTRESS_DISK_RESERVE_BYTES": "0",
                }
                with (
                    patch.dict(os.environ, environment),
                    patch.object(quality, "validate_control_artifact_registry"),
                    patch.object(
                        quality,
                        "repository_fingerprint",
                        return_value=("sha256:source", 2),
                    ),
                    patch.object(quality, "run_command", side_effect=fail_at_gate),
                ):
                    with self.assertRaisesRegex(quality.CertificateError, "injected"):
                        quality.issue(root)
                self.assertEqual(certificate.read_bytes(), b"prior certificate")
                self.assertEqual(user_lock.read_bytes(), b"user lock")

    def test_materialization_writes_directly_to_external_temporary_root(self) -> None:
        fingerprint = "sha256:" + "d" * 64
        content = b"canonical projection\n"
        logical_path = "_info/contract_coherency_graph.json"
        artifact_registry = (
            ("ccg", logical_path, quality.LOCAL_MATERIALIZATION),
        )
        document = {
            "source": {"fingerprint": fingerprint},
            "artifacts": [
                {
                    "id": "ccg",
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

        def generate(
            _root: Path, command: list[str], _environment: dict[str, str], **_kwargs: object
        ) -> None:
            output = Path(command[-1])
            self.assertEqual(output.parent.name, "s")
            output.write_bytes(content)

        environment = {
            "FORTRESS_DERIVED_CACHE_DIR": str(base / "cache"),
            "FORTRESS_CERTIFICATE_TEMP_DIR": str(temporary),
            "FORTRESS_CERTIFICATE_TARGET_DIR": str(base / "target"),
            "FORTRESS_EXECUTION_STORAGE_DIR": str(base / "storage"),
            "FORTRESS_DISK_RESERVE_BYTES": "0",
        }
        with (
            patch.dict(os.environ, environment),
            patch.object(quality, "validate_control_artifact_registry"),
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
            self.assertFalse(temporary.exists())

    def test_clean_preserves_incremental_and_unknown_cache_bytes(self) -> None:
        base = self.workspace("clean")
        root = base / "repository"
        root.mkdir()
        cache = base / "cache" / "PF-FORTRESS"
        subject = cache / ("e" * 64)
        subject.mkdir(parents=True)
        (subject / "contract_coherency_graph.json").write_bytes(b"derived")
        incremental = cache / "incremental-v1" / "active-output"
        incremental.mkdir(parents=True)
        (incremental / "artifact.json").write_bytes(b"IDE bytes")
        unknown = cache / ("f" * 64)
        unknown.mkdir()
        (unknown / "user.bin").write_bytes(b"user bytes")
        environment = {
            "FORTRESS_DERIVED_CACHE_DIR": str(base / "cache"),
            "FORTRESS_EXECUTION_STORAGE_DIR": str(base / "storage"),
            "FORTRESS_DISK_RESERVE_BYTES": "0",
        }
        with (
            patch.dict(os.environ, environment),
            patch.object(quality, "validate_control_artifact_registry"),
        ):
            quality.clean_materializations(root)
        self.assertFalse(subject.exists())
        self.assertEqual((incremental / "artifact.json").read_bytes(), b"IDE bytes")
        self.assertEqual((unknown / "user.bin").read_bytes(), b"user bytes")


if __name__ == "__main__":
    unittest.main()
