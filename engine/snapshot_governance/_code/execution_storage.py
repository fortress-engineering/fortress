"""Machine-local storage ownership for certificate and other heavy jobs.

The journal and leases are operational records. They never enter a source or
semantic digest. Recovery deliberately retains anything whose ownership or
active-use state cannot be proved.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import time
from typing import Any


GIB = 1024**3


class StorageError(RuntimeError):
    """A heavy job cannot safely acquire or use local storage."""


@dataclass(frozen=True)
class StoragePolicy:
    reserve_bytes: int = 10 * GIB
    compiler_budget_bytes: int = 32 * GIB
    projection_budget_bytes: int = 8 * GIB
    max_heavy_jobs: int = 1
    retention: str = "retain-shared-compiler"

    @classmethod
    def from_environment(cls) -> StoragePolicy:
        def size(name: str, default: int) -> int:
            value = int(os.environ.get(name, str(default)))
            if value < 0:
                raise StorageError(f"{name} must be nonnegative")
            return value

        jobs = size("FORTRESS_MAX_HEAVY_JOBS", 1)
        if jobs != 1:
            raise StorageError("the current issuer requires one exclusive heavy job")
        retention = os.environ.get(
            "FORTRESS_STORAGE_RETENTION", "retain-shared-compiler"
        )
        if retention not in {"retain-shared-compiler", "cleanup-owned-compiler"}:
            raise StorageError("invalid FORTRESS_STORAGE_RETENTION")
        return cls(
            reserve_bytes=size("FORTRESS_DISK_RESERVE_BYTES", 10 * GIB),
            compiler_budget_bytes=size("FORTRESS_COMPILER_BUDGET_BYTES", 32 * GIB),
            projection_budget_bytes=size("FORTRESS_PROJECTION_BUDGET_BYTES", 8 * GIB),
            max_heavy_jobs=jobs,
            retention=retention,
        )


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".pending")
    _durable_write(
        temporary, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    )
    os.replace(temporary, path)


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _atomic_bytes(path: Path, content: bytes, nonce: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".pending-{nonce}")
    temporary.write_bytes(content)
    os.replace(temporary, path)


def _durable_write(path: Path, content: bytes) -> None:
    with path.open("wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _tree_size(root: Path) -> int:
    if not root.exists():
        return 0
    total = 0
    for path in root.rglob("*"):
        try:
            if path.is_symlink():
                raise StorageError(f"symbolic link in execution storage: {path}")
            if path.is_file():
                total += path.stat().st_size
        except FileNotFoundError:
            # Compilers routinely replace incremental objects while a budget
            # sample is walking the target. A later sample sees the new state.
            continue
    return total


def _reconcile_publication(
    journal: dict[str, Any], allowed_paths: set[Path] | None
) -> str:
    recovery = journal["publication_recovery"]
    if allowed_paths is None:
        raise StorageError("publication recovery requires an artifact allowlist")
    run_root = Path(journal["run_root"]).resolve()
    pointer = Path(recovery["pointer"]).resolve()
    entries = recovery["replacements"]
    if pointer not in allowed_paths or any(
        Path(entry["path"]).resolve() not in allowed_paths for entry in entries
    ):
        raise StorageError("publication journal names an unauthorized path")

    def prior_bytes(backup_name: str | None, digest: str | None) -> bytes | None:
        if backup_name is None:
            if digest is not None:
                raise StorageError("missing publication preimage")
            return None
        backup = Path(backup_name).resolve()
        if not backup.is_relative_to(run_root):
            raise StorageError("publication preimage escapes owned staging")
        content = backup.read_bytes()
        if _digest(content) != digest:
            raise StorageError("publication preimage digest mismatch")
        return content

    old_pointer = prior_bytes(
        recovery["pointer_backup"], recovery["old_pointer_digest"]
    )
    previous = [
        prior_bytes(entry["backup"], entry["old_digest"]) for entry in entries
    ]
    pointer_content = pointer.read_bytes() if pointer.is_file() else None
    pointer_digest = _digest(pointer_content) if pointer_content is not None else None
    states = []
    for entry in entries:
        path = Path(entry["path"])
        content = path.read_bytes() if path.is_file() else None
        digest = _digest(content) if content is not None else None
        if digest not in {entry["old_digest"], entry["new_digest"]}:
            raise StorageError("publication target changed outside this run")
        states.append(digest)
    if pointer_digest == recovery["new_pointer_digest"]:
        if any(
            digest != entry["new_digest"] for digest, entry in zip(states, entries)
        ):
            raise StorageError("published pointer has incomplete evidence")
        return "RECOVERED_PUBLISHED"
    if pointer_digest != recovery["old_pointer_digest"]:
        raise StorageError("publication pointer changed outside this run")
    for entry, original in zip(entries, previous):
        path = Path(entry["path"])
        if original is None:
            path.unlink(missing_ok=True)
        else:
            _atomic_bytes(path, original, journal["run_nonce"])
    if old_pointer is None:
        pointer.unlink(missing_ok=True)
    else:
        _atomic_bytes(pointer, old_pointer, journal["run_nonce"])
    return "RECOVERED_ROLLBACK"


class RunWorkspace:
    """One exclusive heavy job with a journal and job-owned directories."""

    def __init__(
        self, repository: Path, storage_root: Path, policy: StoragePolicy | None = None
    ) -> None:
        self.repository = repository.resolve()
        self.storage_root = storage_root.resolve()
        self.namespace_root = self.storage_root / "python"
        self.policy = policy or StoragePolicy.from_environment()
        if self.storage_root == self.repository or self.storage_root.is_relative_to(
            self.repository
        ):
            raise StorageError("execution storage must remain outside the repository")
        self.nonce = secrets.token_hex(12)
        self.identity = hashlib.sha256(os.fsencode(self.repository)).hexdigest()
        short_identity = self.identity[:16]
        self.registry = self.namespace_root / "x" / short_identity
        self.lock_path = self.registry / "heavy.lock"
        self.journal_path = self.registry / f"{self.nonce}.json"
        self.run_root = self.namespace_root / "r" / short_identity / self.nonce
        self.target = self.namespace_root / "c" / short_identity
        self.staging = self.run_root / "s"
        self._lease: Any = None
        self._journal: dict[str, Any] = {}
        self._projection_root: Path | None = None
        self._observed_peak = 0

    def _lock(self) -> None:
        self.registry.mkdir(parents=True, exist_ok=True)
        lease = open(self.lock_path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt

                lease.seek(0)
                lease.write(b"\0")
                lease.flush()
                lease.seek(0)
                msvcrt.locking(lease.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lease.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            lease.close()
            raise StorageError("another heavy job owns this repository") from error
        self._lease = lease

    def _unlock(self) -> None:
        if self._lease is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self._lease.seek(0)
                msvcrt.locking(self._lease.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._lease.fileno(), fcntl.LOCK_UN)
        finally:
            self._lease.close()
            self._lease = None

    def _save(self) -> None:
        _atomic_json(self.journal_path, self._journal)

    def reserve(self, bytes_needed: int = 0) -> None:
        free = shutil.disk_usage(self.storage_root).free
        if bytes_needed < 0 or free - bytes_needed < self.policy.reserve_bytes:
            raise StorageError(
                f"insufficient execution storage: free={free}, "
                f"reserve={self.policy.reserve_bytes}, requested={bytes_needed}"
            )

    def check_budget(self) -> None:
        compiler_bytes = _tree_size(self.target)
        if compiler_bytes > self.policy.compiler_budget_bytes:
            raise StorageError(
                f"compiler target exceeded budget: {compiler_bytes} > "
                f"{self.policy.compiler_budget_bytes}"
            )
        staging_bytes = _tree_size(self.run_root)
        projection_bytes = (
            _tree_size(self._projection_root)
            if self._projection_root is not None
            else 0
        )
        self._observed_peak = max(
            self._observed_peak, compiler_bytes + staging_bytes + projection_bytes
        )
        self.reserve()

    def __enter__(self) -> RunWorkspace:
        self._lock()
        try:
            for prior_path in self.registry.glob("*.json"):
                try:
                    prior = json.loads(prior_path.read_text(encoding="utf-8"))
                    if (
                        prior["root_identity"] == self.identity
                        and Path(prior["run_root"]).exists()
                        and (
                            prior.get("lease_state") != "RELEASED"
                            or prior.get("lifecycle") == "RECOVERY_REQUIRED"
                            or prior.get("child_processes")
                        )
                    ):
                        raise StorageError("unresolved prior run retains the shared target")
                except (OSError, ValueError, KeyError, TypeError) as error:
                    raise StorageError("uncertain prior execution journal") from error
            self.reserve()
            free = shutil.disk_usage(self.storage_root).free
            self.target.mkdir(parents=True, exist_ok=True)
            target_marker = self.target / "_owner.json"
            if target_marker.exists():
                try:
                    marker = json.loads(target_marker.read_text(encoding="utf-8"))
                except (OSError, ValueError) as error:
                    raise StorageError("uncertain compiler target owner") from error
                if marker != {"root_identity": self.identity, "namespace": "python"}:
                    raise StorageError("compiler target owner mismatch")
            elif any(self.target.iterdir()):
                raise StorageError("unmarked compiler target is not owned by this adapter")
            else:
                _atomic_json(
                    target_marker,
                    {"root_identity": self.identity, "namespace": "python"},
                )
            self.check_budget()
            self.run_root.mkdir(parents=True)
            marker = self.run_root / "owner.json"
            _atomic_json(
                marker,
                {"run_nonce": self.nonce, "root_identity": self.identity},
            )
            self.staging.mkdir()
            self._journal = {
                "run_nonce": self.nonce,
                "owner_identity": f"{socket.gethostname()}:{os.getpid()}",
                "root_identity": self.identity,
                "lease_state": "ACTIVE",
                "resource_kinds": ["shared_compiler", "owned_staging"],
                "preexisting_files": {},
                "lifecycle": "PREPARED",
                "child_processes": [],
                "publication_intent": None,
                "run_root": str(self.run_root),
                "disk_free_before": free,
                "started_at": time.time(),
            }
            self._save()
            self.set_lifecycle("RUNNING")
            return self
        except BaseException:
            self._unlock()
            raise

    def set_lifecycle(self, state: str) -> None:
        if state not in {
            "PREPARED", "RUNNING", "VALIDATING", "PUBLISHED",
            "CLEANUP_COMPLETE", "FAILED", "CANCELLED", "RECOVERY_REQUIRED",
        }:
            raise StorageError(f"invalid execution lifecycle: {state}")
        self._journal["lifecycle"] = state
        self._save()

    def record_preexisting(self, path: Path) -> None:
        self._journal["preexisting_files"][str(path.resolve())] = (
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        )
        self._save()

    def record_owned(self, path: Path, digest: str) -> None:
        """Record exact job-created staging bytes, never a repository path."""
        path = path.resolve()
        if not path.is_relative_to(self.staging):
            raise StorageError("owned output must remain in this run's staging")
        if _digest(path.read_bytes()) != digest:
            raise StorageError("owned output digest mismatch")
        self._journal.setdefault("owned", []).append(
            {"path": str(path), "digest": digest}
        )
        self._save()

    def prepare_publication(
        self,
        pointer: Path,
        pointer_bytes: bytes,
        replacements: dict[Path, bytes],
    ) -> None:
        """Persist preimages before any tracked evidence replacement."""
        pointer = pointer.resolve()
        if not pointer.is_relative_to(self.repository):
            raise StorageError("publication pointer must be in the repository")
        backup_dir = self.staging / "publication-backups"
        backup_dir.mkdir()
        entries = []
        for index, (path, content) in enumerate(
            sorted(replacements.items(), key=lambda item: str(item[0]))
        ):
            path = path.resolve()
            if not path.is_relative_to(self.repository):
                raise StorageError("tracked publication path must be in the repository")
            original = path.read_bytes() if path.is_file() else None
            backup = backup_dir / f"{index:03}.bin"
            if original is not None:
                _durable_write(backup, original)
            entries.append(
                {
                    "path": str(path),
                    "backup": str(backup) if original is not None else None,
                    "old_digest": _digest(original) if original is not None else None,
                    "new_digest": _digest(content),
                }
            )
        old_pointer = pointer.read_bytes() if pointer.is_file() else None
        pointer_backup = backup_dir / "pointer.bin"
        if old_pointer is not None:
            _durable_write(pointer_backup, old_pointer)
        self._journal["publication_recovery"] = {
            "pointer": str(pointer),
            "pointer_backup": str(pointer_backup) if old_pointer is not None else None,
            "old_pointer_digest": _digest(old_pointer) if old_pointer is not None else None,
            "new_pointer_digest": _digest(pointer_bytes),
            "replacements": entries,
        }
        self._save()

    def track_projection_root(self, path: Path) -> None:
        """Account for the projection cache without making it semantic input."""
        path = path.resolve()
        if path == self.repository or path.is_relative_to(self.repository):
            raise StorageError("projection cache must remain outside the repository")
        self._projection_root = path
        self._journal["projection_root"] = str(path)
        self._journal["projection_bytes_before"] = _tree_size(path)
        self._observed_peak = max(
            self._observed_peak,
            _tree_size(self.target)
            + _tree_size(self.run_root)
            + self._journal["projection_bytes_before"],
        )
        self._save()

    def check_projection_budget(self, added_bytes: int = 0) -> None:
        if self._projection_root is None:
            raise StorageError("projection root was not registered")
        if _tree_size(self._projection_root) + added_bytes > self.policy.projection_budget_bytes:
            raise StorageError("projection cache exceeded local budget")

    def record_child(self, pid: int) -> None:
        self._journal["child_processes"].append(pid)
        self._save()

    def clear_child(self, pid: int) -> None:
        self._journal["child_processes"].remove(pid)
        self._save()

    def publish(self, generation: str) -> None:
        self._journal["publication_intent"] = generation
        self.set_lifecycle("PUBLISHED")

    def __exit__(self, exception_type: Any, _exception: Any, _traceback: Any) -> None:
        try:
            if exception_type is not None and self._journal["lifecycle"] != "RECOVERY_REQUIRED":
                self.set_lifecycle(
                    "CANCELLED" if exception_type is KeyboardInterrupt else "FAILED"
                )
            staging_bytes = _tree_size(self.run_root)
            compiler_bytes = _tree_size(self.target)
            projection_bytes = (
                _tree_size(self._projection_root)
                if self._projection_root is not None
                else 0
            )
            self._journal["observed_peak_bytes"] = max(
                self._observed_peak,
                staging_bytes + compiler_bytes + projection_bytes,
            )
            self._journal["compiler_bytes"] = compiler_bytes
            self._journal["staging_bytes"] = staging_bytes
            if self._projection_root is not None:
                self._journal["projection_bytes_after"] = projection_bytes
            self._journal["disk_free_after_work"] = shutil.disk_usage(
                self.storage_root
            ).free
            if (
                self._journal["child_processes"]
                or self._journal["lifecycle"] == "RECOVERY_REQUIRED"
            ):
                self._journal["cleaned_bytes"] = 0
                self._journal["retained_bytes"] = staging_bytes + compiler_bytes
                self._journal["retention_reason"] = "recovery required"
                self._journal["cleanup_status"] = "RETAINED_RECOVERY_REQUIRED"
                self._journal["lifecycle"] = "RECOVERY_REQUIRED"
            else:
                shutil.rmtree(self.run_root)
                if self.policy.retention == "cleanup-owned-compiler":
                    shutil.rmtree(self.target)
                    self._journal["cleaned_bytes"] = staging_bytes + compiler_bytes
                    self._journal["retained_bytes"] = 0
                    self._journal["retention_reason"] = "selected owned compiler cleanup"
                else:
                    self._journal["cleaned_bytes"] = staging_bytes
                    self._journal["retained_bytes"] = compiler_bytes
                    self._journal["retention_reason"] = "leased shared compiler reuse"
                self._journal["cleanup_status"] = "COMPLETE"
                if exception_type is None:
                    self._journal["lifecycle"] = "CLEANUP_COMPLETE"
            self._journal["lease_state"] = "RELEASED"
            self._journal["disk_free_after_cleanup"] = shutil.disk_usage(
                self.storage_root
            ).free
            self._save()
        except (OSError, StorageError):
            self._journal["lifecycle"] = "RECOVERY_REQUIRED"
            self._journal["cleanup_status"] = "RETAINED_UNCERTAIN"
            self._save()
            raise
        finally:
            self._unlock()


def recover_owned_orphans(
    repository: Path,
    storage_root: Path,
    allowed_publication_paths: set[Path] | None = None,
) -> list[dict[str, str]]:
    """Inspect orphan journals; preserve uncertain or potentially active runs."""
    probe = RunWorkspace(repository, storage_root)
    allowed = (
        {path.resolve() for path in allowed_publication_paths}
        if allowed_publication_paths is not None
        else None
    )
    probe._lock()
    results: list[dict[str, str]] = []
    try:
        for journal_path in sorted(probe.registry.glob("*.json")):
            try:
                journal = json.loads(journal_path.read_text(encoding="utf-8"))
                run_root = Path(journal["run_root"]).resolve()
                expected = probe.namespace_root / "r" / probe.identity[:16] / journal["run_nonce"]
                if run_root != expected or journal["root_identity"] != probe.identity:
                    results.append({"journal": str(journal_path), "status": "RETAINED_UNCERTAIN"})
                    continue
                if not run_root.exists():
                    continue
                marker = json.loads((run_root / "owner.json").read_text(encoding="utf-8"))
                if marker != {
                    "run_nonce": journal["run_nonce"],
                    "root_identity": probe.identity,
                }:
                    results.append({"journal": str(journal_path), "status": "RETAINED_UNCERTAIN"})
                    continue
                # A process may have outlived the issuer. A recorded live child
                # prevents cleanup even after the heavy-job lease was released.
                if journal.get("child_processes"):
                    results.append({"journal": str(journal_path), "status": "RETAINED_CHILD_UNCERTAIN"})
                    continue
                if journal.get("lifecycle") == "RUNNING":
                    results.append({"journal": str(journal_path), "status": "RETAINED_CHILD_UNCERTAIN"})
                    continue
                publication_result = None
                if journal.get("publication_recovery") is not None:
                    publication_result = _reconcile_publication(journal, allowed)
                size = _tree_size(run_root)
                shutil.rmtree(run_root)
                journal["lifecycle"] = "CLEANUP_COMPLETE"
                journal["lease_state"] = "RELEASED"
                journal["cleaned_bytes"] = size
                journal["retained_bytes"] = 0
                journal["cleanup_status"] = "RECOVERED"
                if publication_result is not None:
                    journal["publication_recovery_result"] = publication_result
                _atomic_json(journal_path, journal)
                results.append(
                    {
                        "journal": str(journal_path),
                        "status": publication_result or "RECOVERED",
                    }
                )
            except (OSError, StorageError, KeyError, ValueError, TypeError):
                results.append({"journal": str(journal_path), "status": "RETAINED_UNCERTAIN"})
        return results
    finally:
        probe._unlock()
