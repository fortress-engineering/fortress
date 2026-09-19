#!/usr/bin/env python3
"""Exercise local storage ownership without running Cargo."""

from __future__ import annotations

import os
import json
from pathlib import Path
import shutil
import sys
import time
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_code"))
from execution_storage import (  # noqa: E402
    RunWorkspace,
    StorageError,
    StoragePolicy,
    _tree_size,
    recover_owned_orphans,
)


class ExecutionStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = Path.cwd() / f".fortress-storage-test-{uuid.uuid4().hex}"
        self.base.mkdir(mode=0o777)
        self.addCleanup(self.cleanup_base)
        self.root = self.base / "repository"
        self.root.mkdir()
        self.storage = self.base / "storage"
        self.policy = StoragePolicy(reserve_bytes=0)

    def cleanup_base(self) -> None:
        for attempt in range(5):
            try:
                shutil.rmtree(self.base)
                return
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.1)

    def test_compiler_object_disappearing_during_budget_sample_is_tolerated(self) -> None:
        target = self.storage / "target"
        target.mkdir(parents=True)
        object_file = target / "vanishing.o"
        object_file.write_bytes(b"temporary compiler object")
        original_stat = Path.stat
        reads = 0

        def racing_stat(path: Path, *args: object, **kwargs: object) -> os.stat_result:
            nonlocal reads
            if path == object_file:
                reads += 1
                if reads == 2:
                    object_file.unlink()
                    raise FileNotFoundError(object_file)
            return original_stat(path, *args, **kwargs)

        with patch.object(Path, "stat", racing_stat):
            self.assertEqual(_tree_size(target), 0)

    def test_disk_reserve_rejects_before_source_or_evidence_mutation(self) -> None:
        source = self.root / "source.txt"
        evidence = self.root / "evidence.json"
        source.write_bytes(b"user source")
        evidence.write_bytes(b"prior evidence")
        with self.assertRaises(StorageError):
            with RunWorkspace(
                self.root,
                self.storage,
                StoragePolicy(reserve_bytes=2**63),
            ):
                self.fail("storage preflight must reject before job work")
        self.assertEqual(source.read_bytes(), b"user source")
        self.assertEqual(evidence.read_bytes(), b"prior evidence")
        run_root = self.storage / "python" / "r"
        self.assertEqual(list(run_root.glob("**/*")) if run_root.exists() else [], [])

    def test_active_target_lease_prevents_second_heavy_job(self) -> None:
        with RunWorkspace(self.root, self.storage, self.policy) as first:
            with self.assertRaises(StorageError):
                with RunWorkspace(self.root, self.storage, self.policy):
                    self.fail("second heavy job must not start")
            first.target.joinpath("compiler-output").write_bytes(b"owned")
        self.assertFalse(first.run_root.exists())

    def test_failure_cleanup_keeps_preexisting_user_bytes(self) -> None:
        lock = self.root / "Cargo.lock"
        lock.write_bytes(b"pre-existing user lock")
        with self.assertRaisesRegex(RuntimeError, "injected"):
            with RunWorkspace(self.root, self.storage, self.policy) as workspace:
                workspace.record_preexisting(lock)
                workspace.staging.joinpath("partial.json").write_bytes(b"partial")
                raise RuntimeError("injected")
        self.assertEqual(lock.read_bytes(), b"pre-existing user lock")
        self.assertFalse(workspace.run_root.exists())
        journal = workspace.journal_path.read_text(encoding="utf-8")
        self.assertIn('"lifecycle": "FAILED"', journal)
        self.assertIn('"cleanup_status": "COMPLETE"', journal)

    def test_forced_termination_recovery_is_idempotent(self) -> None:
        workspace = RunWorkspace(self.root, self.storage, self.policy)
        workspace.__enter__()
        workspace.set_lifecycle("VALIDATING")
        workspace.target.joinpath("owned").write_bytes(b"owned")
        workspace._unlock()  # Simulate an uncatchable process termination.
        first = recover_owned_orphans(self.root, self.storage)
        second = recover_owned_orphans(self.root, self.storage)
        self.assertEqual(first[0]["status"], "RECOVERED")
        self.assertEqual(second, [])
        self.assertFalse(workspace.run_root.exists())

    def test_child_process_uncertainty_retains_orphan(self) -> None:
        workspace = RunWorkspace(self.root, self.storage, self.policy)
        workspace.__enter__()
        workspace.record_child(os.getpid())
        workspace.target.joinpath("owned").write_bytes(b"owned")
        workspace._unlock()
        result = recover_owned_orphans(self.root, self.storage)
        self.assertEqual(result[0]["status"], "RETAINED_CHILD_UNCERTAIN")
        self.assertTrue(workspace.run_root.exists())
        with self.assertRaises(StorageError):
            with RunWorkspace(self.root, self.storage, self.policy):
                self.fail("uncertain target cannot be reused")

    def test_catchable_exit_retains_staging_while_child_is_recorded(self) -> None:
        with RunWorkspace(self.root, self.storage, self.policy) as workspace:
            workspace.record_child(os.getpid())
            workspace.staging.joinpath("child-output").write_bytes(b"in use")
        journal = json.loads(workspace.journal_path.read_text(encoding="utf-8"))
        self.assertEqual(journal["cleanup_status"], "RETAINED_RECOVERY_REQUIRED")
        self.assertEqual(journal["lifecycle"], "RECOVERY_REQUIRED")
        self.assertTrue(workspace.run_root.exists())

    def test_report_accounts_for_owned_roots_and_cleanup(self) -> None:
        with RunWorkspace(self.root, self.storage, self.policy) as workspace:
            workspace.target.joinpath("compiled").write_bytes(b"1234")
            workspace.staging.joinpath("output").write_bytes(b"56789")
            workspace.publish("sha256:qualified")
        journal = json.loads(workspace.journal_path.read_text(encoding="utf-8"))
        self.assertGreaterEqual(journal["observed_peak_bytes"], 9)
        self.assertGreaterEqual(
            journal["observed_peak_bytes"],
            journal["cleaned_bytes"] + journal["retained_bytes"],
        )
        self.assertGreaterEqual(journal["retained_bytes"], 4)
        self.assertEqual(journal["lifecycle"], "CLEANUP_COMPLETE")

    def test_projection_budget_and_report_cover_cache_root(self) -> None:
        cache = self.base / "cache"
        cache.mkdir()
        (cache / "existing.json").write_bytes(b"1234")
        policy = StoragePolicy(reserve_bytes=0, projection_budget_bytes=5)
        with RunWorkspace(self.root, self.storage, policy) as workspace:
            workspace.track_projection_root(cache)
            workspace.check_projection_budget(1)
            with self.assertRaises(StorageError):
                workspace.check_projection_budget(2)
            workspace.set_lifecycle("VALIDATING")
            workspace.publish("cache-generation")
        journal = json.loads(workspace.journal_path.read_text(encoding="utf-8"))
        self.assertEqual(journal["projection_bytes_before"], 4)
        self.assertEqual(journal["projection_bytes_after"], 4)

    def test_selected_compiler_cleanup_removes_only_marked_target(self) -> None:
        policy = StoragePolicy(
            reserve_bytes=0,
            retention="cleanup-owned-compiler",
        )
        with RunWorkspace(self.root, self.storage, policy) as workspace:
            workspace.target.joinpath("compiled").write_bytes(b"owned compiler bytes")
            workspace.set_lifecycle("VALIDATING")
            workspace.publish("generation")
        journal = json.loads(workspace.journal_path.read_text(encoding="utf-8"))
        self.assertFalse(workspace.target.exists())
        self.assertEqual(journal["retained_bytes"], 0)
        self.assertGreaterEqual(journal["observed_peak_bytes"], journal["cleaned_bytes"])

    def test_publication_pointer_is_last_and_crash_restores_prior_generation(self) -> None:
        evidence = self.root / "evidence.json"
        pointer = self.root / "certificate.json"
        evidence.write_bytes(b"old evidence")
        pointer.write_bytes(b"old certificate")
        workspace = RunWorkspace(self.root, self.storage, self.policy)
        workspace.__enter__()
        workspace.set_lifecycle("VALIDATING")
        workspace.prepare_publication(
            pointer, b"new certificate", {evidence: b"new evidence"}
        )
        self.assertEqual(pointer.read_bytes(), b"old certificate")
        self.assertEqual(evidence.read_bytes(), b"old evidence")
        evidence.write_bytes(b"new evidence")
        workspace._unlock()  # Crash before the pointer is published.
        result = recover_owned_orphans(
            self.root, self.storage, {pointer, evidence}
        )
        self.assertEqual(result[0]["status"], "RECOVERED_ROLLBACK")
        self.assertEqual(evidence.read_bytes(), b"old evidence")
        self.assertEqual(pointer.read_bytes(), b"old certificate")
        self.assertEqual(recover_owned_orphans(self.root, self.storage), [])

    def test_published_pointer_survives_restart_recovery(self) -> None:
        evidence = self.root / "evidence.json"
        pointer = self.root / "certificate.json"
        evidence.write_bytes(b"old evidence")
        pointer.write_bytes(b"old certificate")
        workspace = RunWorkspace(self.root, self.storage, self.policy)
        workspace.__enter__()
        workspace.set_lifecycle("VALIDATING")
        workspace.prepare_publication(
            pointer, b"new certificate", {evidence: b"new evidence"}
        )
        evidence.write_bytes(b"new evidence")
        pointer.write_bytes(b"new certificate")
        workspace._unlock()  # Crash after pointer but before cleanup.
        result = recover_owned_orphans(
            self.root, self.storage, {pointer, evidence}
        )
        self.assertEqual(result[0]["status"], "RECOVERED_PUBLISHED")
        self.assertEqual(evidence.read_bytes(), b"new evidence")
        self.assertEqual(pointer.read_bytes(), b"new certificate")

    def test_publication_recovery_retains_external_mutation(self) -> None:
        evidence = self.root / "evidence.json"
        pointer = self.root / "certificate.json"
        evidence.write_bytes(b"old evidence")
        pointer.write_bytes(b"old certificate")
        workspace = RunWorkspace(self.root, self.storage, self.policy)
        workspace.__enter__()
        workspace.set_lifecycle("VALIDATING")
        workspace.prepare_publication(
            pointer, b"new certificate", {evidence: b"new evidence"}
        )
        evidence.write_bytes(b"unrelated writer")
        workspace._unlock()
        result = recover_owned_orphans(
            self.root, self.storage, {pointer, evidence}
        )
        self.assertEqual(result[0]["status"], "RETAINED_UNCERTAIN")
        self.assertEqual(evidence.read_bytes(), b"unrelated writer")
        self.assertTrue(workspace.run_root.exists())

    def test_cleanup_failure_retains_journal_for_recovery(self) -> None:
        workspace = RunWorkspace(self.root, self.storage, self.policy)
        original_rmtree = shutil.rmtree

        def fail_run_cleanup(path: Path, *args: object, **kwargs: object) -> None:
            if Path(path) == workspace.run_root:
                raise OSError("injected cleanup failure")
            original_rmtree(path, *args, **kwargs)

        with patch("execution_storage.shutil.rmtree", side_effect=fail_run_cleanup):
            with self.assertRaisesRegex(OSError, "injected cleanup failure"):
                with workspace:
                    workspace.set_lifecycle("VALIDATING")
        journal = json.loads(workspace.journal_path.read_text(encoding="utf-8"))
        self.assertEqual(journal["lifecycle"], "RECOVERY_REQUIRED")
        self.assertTrue(workspace.run_root.exists())
        recovered = recover_owned_orphans(self.root, self.storage)
        self.assertEqual(recovered[0]["status"], "RECOVERED")

    def test_released_recovery_journal_with_owned_staging_can_resume(self) -> None:
        workspace = RunWorkspace(self.root, self.storage, self.policy)
        workspace.__enter__()
        workspace.set_lifecycle("RECOVERY_REQUIRED")
        workspace._journal["lease_state"] = "RELEASED"
        workspace._save()
        workspace._unlock()

        recovered = recover_owned_orphans(self.root, self.storage)
        self.assertEqual(recovered[0]["status"], "RECOVERED")
        self.assertFalse(workspace.run_root.exists())
        with RunWorkspace(self.root, self.storage, self.policy):
            pass


if __name__ == "__main__":
    unittest.main()
