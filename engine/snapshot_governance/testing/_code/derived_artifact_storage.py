#!/usr/bin/env python3
"""Verify subject-addressed derived-projection storage invariants."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
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
import application_assessment as application

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

    def test_inconsistent_gate_contract_refuses_before_execution_or_recovery(self) -> None:
        required = quality.REQUIRED_GATE_IDS
        malformed = (
            tuple(reversed(required)),
            required + (required[-1],),
            tuple(gate for gate in required if gate != "ARTIFACT_PROFILE_ASSESSMENT"),
        )
        for gates in malformed:
            with self.subTest(gates=gates), patch.object(quality, "REQUIRED_GATE_IDS", gates), \
                    patch.object(quality, "recover_owned_orphans") as recover, \
                    patch.object(quality, "RunWorkspace") as workspace, \
                    patch.object(quality, "run_command") as execute:
                with self.assertRaises(quality.CertificateError):
                    quality.issue(ROOT)
                recover.assert_not_called()
                workspace.assert_not_called()
                execute.assert_not_called()

    def test_gate_manifest_requires_each_installed_gate_exactly_once_and_passed(self) -> None:
        gates = [dict(id=gate, status="PASS", command="independent gate command")
                 for gate in quality.REQUIRED_GATE_IDS]
        quality.validate_executed_gates(gates)
        for index, gate in enumerate(gates):
            with self.subTest(missing=gate["id"]):
                with self.assertRaises(quality.CertificateError):
                    quality.validate_executed_gates(gates[:index] + gates[index + 1:])
        malformed = [
            [], list(reversed(gates)), gates + [gates[-1]],
            sorted(gates + [dict(id="UNREGISTERED", status="PASS", command="extra")],
                   key=lambda gate: gate["id"]),
        ]
        for field, value in (("status", "FAIL"), ("command", ""), ("id", "")):
            modified = [dict(gate) for gate in gates]
            modified[0][field] = value
            malformed.append(modified)
        malformed.append([dict(gates[0], extra="unregistered")] + gates[1:])
        for candidate in malformed:
            with self.subTest(candidate=candidate):
                with self.assertRaises(quality.CertificateError):
                    quality.validate_executed_gates(candidate)

    def test_negative_application_publication_preserves_quality_selection_and_replays_exactly(self) -> None:
        base=self.workspace("negative-application")
        root=base/"repository"
        config=root/quality.CONFIG_PATH;config.parent.mkdir(parents=True)
        config.write_text(json.dumps(dict(observation_exclusions=[])),encoding="utf-8")
        index=root/quality.CURRENT_INDEX_PATH;index.parent.mkdir(parents=True)
        quality_generation="sha256:"+"a"*64
        prior={"$schema":"urn:fortress:derived:v1:assessment-selection-index","schema_version":1,
            "selections":[dict(selection_key=quality.selection_key(),generation_digest=quality_generation)]}
        index.write_bytes(quality.canonical_pretty_json(prior))
        old=root/quality.GENERATIONS_PATH/("a"*64)/"manifest.json";old.parent.mkdir(parents=True);old.write_bytes(b"retained historical bytes")
        (root/"_data").mkdir()
        (root/"_data/évidence.json").write_text('{"source":"λ"}\n',encoding="utf-8")
        frozen,native_subject=quality.repository_source_identities(root)
        self.assertNotEqual(frozen[0],native_subject)
        declaration=dict(binding=dict(subject_ref=native_subject,context_ref="sha256:"+"c"*64,authority_ref="sha256:"+"d"*64),raw_truth="SUPPORTED_VIOLATION")
        inputs={"$schema":"urn:fortress:derived:v1:evidence-input-set","schema_version":1,"binding":declaration["binding"],"selected":[]}
        input_digest=quality.sha256_bytes(application.canonical(["provider-evidence-input-set-v1",inputs["binding"],inputs["selected"]]))
        report=dict(source_ref=declaration["binding"]["subject_ref"],application=dict(project="PF-FIXTURE",declaration=declaration,evidence_inputs=inputs,
            assessment=dict(binding=declaration["binding"],declaration_digest=quality.sha256_bytes(application.canonical(declaration)),
                evidence_input_digest=input_digest,profile_digest="sha256:"+"e"*64,decision="NOT_SATISFIED")))
        wrong=dict(report,source_ref="sha256:"+"b"*64)
        with self.assertRaisesRegex(application.quality.CertificateError,"differs from frozen source"):
            application.publish(root,wrong,frozen,Mock())
        local_as_native=json.loads(json.dumps(report))
        local_as_native["source_ref"]=frozen[0]
        local_as_native["application"]["declaration"]["binding"]["subject_ref"]=frozen[0]
        with self.assertRaisesRegex(application.quality.CertificateError,"differs from frozen source"):
            application.publish(root,local_as_native,frozen,Mock())
        self.assertEqual(json.loads(index.read_bytes()),prior)
        workspace=Mock()
        selected=application.publish(root,report,frozen,workspace)
        workspace.prepare_publication.assert_called_once()
        self.assertEqual(quality.selection_entries(json.loads(index.read_bytes()))[quality.selection_key()],quality_generation)
        self.assertEqual(old.read_bytes(),b"retained historical bytes")
        self.assertEqual(application.verify(root,report,frozen[1]),selected)
        immutable=(root/quality.GENERATIONS_PATH/selected.removeprefix("sha256:")/"conformance_declaration.json")
        immutable.write_bytes(b"altered")
        with self.assertRaises(application.quality.CertificateError):application.verify(root,report,frozen[1])
        immutable.write_bytes(application.canonical(declaration))
        pointer=index.read_bytes()
        (root/"changed.rs").write_text("changed source",encoding="utf-8")
        with self.assertRaisesRegex(application.quality.CertificateError,"source changed"):
            application.publish(root,report,frozen,Mock())
        self.assertEqual(index.read_bytes(),pointer)

    def test_application_selection_binds_exact_profile_scope_and_context(self) -> None:
        context="sha256:"+"a"*64;profile="sha256:"+"b"*64
        key=application.application_selection_key("PF-FIXTURE",profile,context)
        self.assertNotEqual(key,quality.selection_key())
        self.assertNotEqual(key,application.application_selection_key("PF-FIXTURE",context,profile))
        self.assertNotEqual(key,application.application_selection_key("PF-OTHER",profile,context))

    def test_atomic_publication_preserves_foreign_pending_and_cleans_owned_failure(self) -> None:
        root=self.workspace("owned-publication")
        target=root/"current.json";target.write_bytes(b"old index")
        foreign=root/"current.json.pending";foreign.write_bytes(b"owner work")
        with patch.object(quality.os,"replace",side_effect=OSError("injected replacement failure")):
            with self.assertRaises(OSError):quality.atomic_write(target,b"new index")
        self.assertEqual(target.read_bytes(),b"old index")
        self.assertEqual(foreign.read_bytes(),b"owner work")
        self.assertEqual(sorted(p.name for p in root.iterdir()),["current.json","current.json.pending"])
        quality.atomic_write(target,b"new index")
        self.assertEqual(target.read_bytes(),b"new index")
        self.assertEqual(foreign.read_bytes(),b"owner work")

    def test_current_generation_binds_layout_and_manifest_v7(self) -> None:
        certificate = self.certificate("sha256:" + "a" * 64)
        certificate["source"]["file_count"] = 1
        pending = {
            logical_path: b"canonical projection\n"
            for _, logical_path, storage in quality.ARTIFACTS
            if storage == quality.TRACKED_EVIDENCE
        }
        manifest = quality.build_generation_manifest(ROOT, certificate, b"{}\n", pending)
        self.assertEqual(manifest["$schema"], "urn:fortress:derived:v7:assessment-generation-manifest")
        self.assertEqual(manifest["schema_version"], 7)
        self.assertEqual(
            manifest["control_layout"],
            {"id": "fortress-control-layout-v7", "digest": quality.sha256_bytes(
                (ROOT / "engine/project_model/_data/control_layout_v7.json").read_bytes())},
        )
        root = self.workspace("current-generation-roundtrip") / "repository"
        for version in (6, 7):
            relative = f"engine/project_model/_data/control_layout_v{version}.json"
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / relative).read_bytes())
        content = b"canonical projection\n"
        certificate = self.certificate("sha256:" + "a" * 64)
        certificate["source"]["file_count"] = 1
        certificate["certificate_stamp"] = quality.certificate_stamp(certificate)
        certificate_bytes = quality.canonical_pretty_json(certificate)
        current = quality.build_generation_manifest(root, certificate, certificate_bytes, pending)
        self.publish_fixture_generation(root, current, certificate_bytes, content)
        self.assertEqual(quality.load_selected_generation(root)[1], certificate)
        historical = {**current, "$schema": "urn:fortress:derived:v6:assessment-generation-manifest",
                      "schema_version": 6, "control_layout": {
                          "id": "fortress-control-layout-v6",
                          "digest": quality.control_layout_digest(root, 6)}}
        self.publish_fixture_generation(root, historical, certificate_bytes, content)
        self.assertEqual(quality.load_selected_generation(root, historical=True)[1], certificate)
        with self.assertRaisesRegex(quality.CertificateError, "identity is unsupported"):
            quality.load_selected_generation(root)
        for historical_reader in (False, True):
            future = {**current, "$schema": "urn:fortress:derived:v8:assessment-generation-manifest",
                      "schema_version": 8}
            self.publish_fixture_generation(root, future, certificate_bytes, content)
            with self.assertRaisesRegex(quality.CertificateError, "identity is unsupported"):
                quality.load_selected_generation(root, historical=historical_reader)

    def publish_fixture_generation(self, root, manifest, certificate_bytes, content):
        generation_id = quality.manifest_digest(manifest)
        directory = root / quality.GENERATIONS_PATH / generation_id.removeprefix("sha256:")
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "manifest.json").write_bytes(quality.canonical_pretty_json(manifest))
        for descriptor in manifest["artifacts"]:
            if descriptor["storage"]["kind"] == "INCLUDED":
                data = certificate_bytes if descriptor["id"] == quality.CERTIFICATE_ID else content
                (directory / descriptor["storage"]["member_name"]).write_bytes(data)
        _, index = quality.updated_selection_index(root, generation_id)
        (root / quality.CURRENT_INDEX_PATH).write_bytes(index)

    def test_historical_manifest_cannot_become_current_by_selection(self) -> None:
        base = self.workspace("historical-selection")
        root = base / "repository"
        manifest = {
            "$schema": "urn:fortress:derived:v1:assessment-generation-manifest",
            "schema_version": 1,
            "generation_kind": "LOCAL_QUALITY",
            "project": "PF-FORTRESS",
            "profile": quality.PROFILE_ID,
            "selection_key": quality.selection_key(),
            "source": {"fingerprint": "sha256:" + "a" * 64, "file_count": 1},
            "control_layout": {"id": "fortress-control-layout-v1", "digest": "sha256:" + "b" * 64},
            "artifacts": [],
        }
        generation_id = quality.manifest_digest(manifest)
        generation = root / quality.GENERATIONS_PATH / generation_id.removeprefix("sha256:")
        generation.mkdir(parents=True)
        (generation / "manifest.json").write_bytes(quality.canonical_pretty_json(manifest))
        (root / quality.CURRENT_INDEX_PATH).write_bytes(
            quality.canonical_pretty_json(
                {
                    "$schema": "urn:fortress:derived:v1:assessment-selection-index",
                    "schema_version": 1,
                    "selections": [{"selection_key": quality.selection_key(), "generation_digest": generation_id}],
                }
            )
        )
        with self.assertRaisesRegex(quality.CertificateError, "identity is unsupported"):
            quality.load_selected_generation(root)

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
        for name in ("quality_certificate.py", "execution_storage.py", "heavy_admission.py"):
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

    def test_failed_capture_preserves_assertion_and_original_failure(self) -> None:
        output = b"completed tests\nassertion failed: retained layout\n\xff"
        process = Mock(pid=12345, returncode=101)
        process.communicate.return_value = (output, None)
        process.poll.return_value = 101
        workspace = Mock()
        retained = io.BytesIO()
        error_stream = io.TextIOWrapper(retained, encoding="utf-8")
        with (
            patch.object(quality.subprocess, "Popen", return_value=process),
            patch.object(quality.sys, "stderr", error_stream),
            patch.object(quality.sys, "stdout", io.StringIO()),
        ):
            with self.assertRaisesRegex(quality.CertificateError, "quality gate exited 101"):
                quality.run_command(Path.cwd(), ["cargo"], {}, capture=True, workspace=workspace)
        header, actual = retained.getvalue().split(b"\n", 1)
        record = json.loads(header.removeprefix(b"[local-certificate-failed-capture] "))
        self.assertEqual(actual, output)
        self.assertEqual(record["captured_digest"], quality.sha256_bytes(output))
        self.assertEqual(record["captured_bytes"], len(output))
        self.assertFalse(record["truncated"])
        self.assertFalse(record["qualification_claim"])
        workspace.clear_child.assert_called_once_with(12345)

    def test_oversized_failure_preview_is_explicitly_incomplete(self) -> None:
        maximum = 4 * 1024**2
        output = b"not in preview\n" + b"x" * maximum
        retained = io.BytesIO()
        error_stream = io.TextIOWrapper(retained, encoding="utf-8")
        with patch.object(quality.sys, "stderr", error_stream):
            quality.emit_failed_command_capture(output)
        header, actual = retained.getvalue().split(b"\n", 1)
        record = json.loads(header.removeprefix(b"[local-certificate-failed-capture] "))
        self.assertEqual(actual, output[-maximum:])
        self.assertEqual(record["captured_bytes"], len(output))
        self.assertEqual(record["captured_digest"], quality.sha256_bytes(output))
        self.assertEqual(record["preview_raw_bytes"], maximum)
        self.assertTrue(record["truncated"])
        self.assertFalse(record["qualification_claim"])

    def test_successful_capture_returns_exact_bytes_without_failure_preview(self) -> None:
        output = b'{"result":"PASS"}\n'
        process = Mock(pid=12345, returncode=0)
        process.communicate.return_value = (output, None)
        process.poll.return_value = 0
        with (
            patch.object(quality.subprocess, "Popen", return_value=process),
            patch.object(quality, "emit_failed_command_capture") as diagnostic,
            patch.object(quality.sys, "stdout", io.StringIO()),
        ):
            self.assertEqual(quality.run_command(Path.cwd(), ["cargo"], {}, capture=True), output)
        diagnostic.assert_not_called()

    def test_failure_preview_error_preserves_gate_failure(self) -> None:
        process = Mock(pid=12345, returncode=101)
        process.communicate.return_value = (b"assertion failed\n", None)
        process.poll.return_value = 101
        with (
            patch.object(quality.subprocess, "Popen", return_value=process),
            patch.object(quality, "emit_failed_command_capture", side_effect=OSError("closed")),
            patch.object(quality.sys, "stdout", io.StringIO()),
        ):
            with self.assertRaisesRegex(quality.CertificateError, "quality gate exited 101") as raised:
                quality.run_command(ROOT, ["cargo", "test"], {}, capture=True)
        self.assertEqual(
            raised.exception.__notes__,
            ["Failure capture diagnostic could not be emitted: OSError"],
        )

    def test_registry_is_complete_sorted_and_authority_excluded(self) -> None:
        paths = quality.derived_artifact_paths()
        self.assertEqual(paths, tuple(sorted(paths)))
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(quality.excluded_source_paths(), {
            quality.EVIDENCE_ROOT,
            "__fortress/proposals/migrations",
            "__fortress/proposals/candidates",
            "__fortress/records/migrations",
        })
        self.assertNotIn("__fortress/governance/finding_governance.json", quality.excluded_source_paths())
        self.assertNotIn("__fortress/.fsconfig", quality.excluded_source_paths())
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
        self.assertEqual(
            quality.selection_entries(document),
            {other_key: "sha256:" + "2" * 64, quality.selection_key(): "sha256:" + "3" * 64},
        )
        other = {"selection_key": other_key, "generation_digest": "sha256:" + "2" * 64}
        local = {"selection_key": quality.selection_key(), "generation_digest": "sha256:" + "3" * 64}
        cases = {
            "duplicate unrelated context": [other, {**other, "generation_digest": local["generation_digest"]}, local],
            "duplicate requested context": [other, local, {**local, "generation_digest": other["generation_digest"]}],
            "reverse key order": [local, other],
            "invalid unrelated digest": [{**other, "generation_digest": "sha256:invalid"}, local],
            "extra unrelated field": [{**other, "extra": "invalid"}, local],
            "nonobject entry": [None, local],
        }
        for label, entries in cases.items():
            with self.subTest(label=label):
                malformed = {**document, "selections": entries}
                current.write_bytes(quality.canonical_pretty_json(malformed))
                with self.assertRaisesRegex(quality.CertificateError, "selection index"):
                    quality.updated_selection_index(root, local["generation_digest"])
                with self.assertRaisesRegex(quality.CertificateError, "selection index"):
                    quality.load_selected_generation(root)
        current.write_bytes(updated)
        with self.assertRaisesRegex(quality.CertificateError, "new generation digest"):
            quality.updated_selection_index(root, "sha256:invalid")
        shared = {**document, "selections": [other, {**local, "generation_digest": other["generation_digest"]}]}
        self.assertEqual(set(quality.selection_entries(shared).values()), {other["generation_digest"]})
        self.assertEqual(quality.selection_entries({**document, "selections": []}), {})
        for malformed_version in (True, 1.0):
            with self.subTest(schema_version=malformed_version):
                with self.assertRaisesRegex(quality.CertificateError, "selection index"):
                    quality.selection_entries({**document, "schema_version": malformed_version})

    def test_legacy_outputs_migrate_byte_exact_without_becoming_current(self) -> None:
        base = self.workspace("legacy-migration")
        root = base / "repository"
        (root / ".git").mkdir(parents=True)
        for version in (1, 2):
            layout_name = f"control_layout_v{version}.json"
            layout_source = MODULE_PATH.parents[2] / "project_model" / "_data" / layout_name
            layout_target = root / "engine/project_model/_data" / layout_name
            layout_target.parent.mkdir(parents=True, exist_ok=True)
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
        self.assertEqual(manifest["$schema"], "urn:fortress:derived:v1:assessment-generation-manifest")
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["control_layout"]["id"], "fortress-control-layout-v1")
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
        for failure_call in (4, 9, 10):
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
                    if "build" in _args[1]:
                        workspace = _kwargs["workspace"]
                        executable = workspace.target / "compiled-cli"
                        executable.write_bytes(b"compiler artifact fixture")
                        return self.compiler_report(root, executable)
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

    @staticmethod
    def compiler_report(root: Path, executable: Path) -> bytes:
        return (
            json.dumps({
                "reason": "compiler-artifact",
                "target": {"name": "fortress", "kind": ["bin"],
                           "src_path": str(root / "cli/_code/main.rs")},
                "executable": str(executable),
            }) + "\n" + json.dumps({"reason": "build-finished", "success": True}) + "\n"
        ).encode()

    def compiler_fixture(self, name: str):
        base = self.workspace(name)
        root = base / "repository"
        root.mkdir()
        target = base / "compiler"
        target.mkdir()
        staging = base / "staging"
        staging.mkdir()
        executable = target / ("fortress.exe" if os.name == "nt" else "fortress")
        executable.write_bytes(b"complete compiler artifact\n" * 4096)
        executable.chmod(0o755)
        workspace = Mock(target=target, staging=staging)
        return root, executable, workspace

    def test_issuer_stages_exact_compiled_bytes_without_overwriting_target(self) -> None:
        root, executable, workspace = self.compiler_fixture("staged-compiler")
        before = executable.read_bytes()
        with patch.object(quality, "run_command", return_value=self.compiler_report(
            root, executable
        )) as build:
            staged = quality.certification_executable(root, ["cargo", "+1.97.1"], {}, workspace)
        self.assertEqual(staged.parent, workspace.staging)
        self.assertEqual(staged.read_bytes(), before)
        self.assertEqual(executable.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(staged.stat().st_mode),
                         stat.S_IMODE(executable.stat().st_mode))
        workspace.reserve.assert_called_once_with(len(before))
        self.assertEqual(workspace.check_budget.call_count, 2)
        self.assertIn("--all-features", build.call_args.args[1])
        self.assertIn("--message-format=json-render-diagnostics", build.call_args.args[1])
        self.assertEqual(quality.command_text([str(staged), "certify", "."]),
                         "fortress certify .")

    def test_issuer_refuses_incomplete_or_ambiguous_compiler_reports(self) -> None:
        root, executable, workspace = self.compiler_fixture("bad-compiler-report")
        valid = self.compiler_report(root, executable).splitlines()
        artifact = json.loads(valid[0])
        wrong_owner = dict(artifact, target=dict(artifact["target"], src_path=str(root / "other.rs")))
        reports = [b"not-json\n", b"[]\n", valid[0] + b"\n",
                   valid[0] + b'\n{"reason":"build-finished","success":false}\n',
                   b"\n".join([valid[0], valid[0], valid[1]]),
                   json.dumps(wrong_owner).encode() + b"\n" + valid[1]]
        for report in reports:
            with self.subTest(report=report):
                with patch.object(quality, "run_command", return_value=report):
                    with self.assertRaises(quality.CertificateError):
                        quality.certification_executable(root, ["cargo"], {}, workspace)
        self.assertEqual(list(workspace.staging.iterdir()), [])
        workspace.reserve.assert_not_called()

    def test_issuer_refuses_compiler_artifact_outside_owned_target(self) -> None:
        root, executable, workspace = self.compiler_fixture("foreign-compiler")
        outside = executable.parent.parent / "unowned-cli"
        executable.rename(outside)
        before = outside.read_bytes()
        with patch.object(quality, "run_command", return_value=self.compiler_report(root, outside)):
            with self.assertRaisesRegex(quality.CertificateError, "escapes"):
                quality.certification_executable(root, ["cargo"], {}, workspace)
        self.assertEqual(outside.read_bytes(), before)
        self.assertEqual(list(workspace.staging.iterdir()), [])

    def test_issuer_preserves_existing_staged_bytes_on_collision(self) -> None:
        root, executable, workspace = self.compiler_fixture("staged-collision")
        staged = workspace.staging / ("fortress.exe" if os.name == "nt" else "fortress")
        staged.write_bytes(b"existing owned bytes")
        with patch.object(quality, "run_command", return_value=self.compiler_report(root, executable)):
            with self.assertRaises(FileExistsError):
                quality.certification_executable(root, ["cargo"], {}, workspace)
        self.assertEqual(staged.read_bytes(), b"existing owned bytes")

    def test_issuer_refuses_compiler_artifact_growth_during_copy(self) -> None:
        root, executable, workspace = self.compiler_fixture("compiler-growth")
        original_open = Path.open

        def growing_open(path: Path, mode: str = "r", *args, **kwargs):
            if path == executable and mode == "rb":
                with original_open(executable, "ab") as file:
                    file.write(b"unexpected growth")
            return original_open(path, mode, *args, **kwargs)

        with patch.object(quality, "run_command", return_value=self.compiler_report(root, executable)):
            with patch.object(Path, "open", growing_open):
                with self.assertRaisesRegex(quality.CertificateError, "grew"):
                    quality.certification_executable(root, ["cargo"], {}, workspace)

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
