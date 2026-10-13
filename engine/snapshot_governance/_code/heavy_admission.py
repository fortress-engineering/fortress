"""Cross-adapter admission; owner journals alone authorize their cleanup."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OSError("duplicate operational JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise OSError("non-finite operational JSON number")


def _read_json(path: Path, limit: int) -> dict[str, Any]:
    _plain_file(path)
    with path.open("rb") as handle:
        content = handle.read(limit + 1)
    if len(content) > limit:
        raise OSError("oversized admission record")
    try:
        value = json.loads(content, object_pairs_hook=_strict_object,
                           parse_constant=_reject_constant)
    except (ValueError, UnicodeError) as error:
        raise OSError("invalid admission record") from error
    if not isinstance(value, dict):
        raise OSError("admission record is not an object")
    return value


def _hex(value: Any, length: int) -> bool:
    return (isinstance(value, str) and len(value) == length
            and all(char in "0123456789abcdef" for char in value))


def _fixed_anchor() -> Path:
    if os.name == "nt":
        return Path(r"\\?\GLOBALROOT\SystemRoot\Temp")
    if os.name == "posix":
        return Path("/tmp")
    raise OSError("fixed native admission anchor is unavailable")


def _linked(metadata: os.stat_result) -> bool:
    return (stat.S_ISLNK(metadata.st_mode)
            or bool(getattr(metadata, "st_file_attributes", 0) & 0x400))


def _plain_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    metadata = path.lstat()
    if _linked(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError("admission registry component is not an ordinary directory")


def _plain_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if _linked(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise OSError("admission record is not an ordinary file")


def _lease_file(path: Path) -> Any:
    if os.name != "nt":
        return path.open("a+b")
    import ctypes
    from ctypes import wintypes
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    # Retain the persistent lock file without delete sharing. No adapter ever
    # unlinks this file, so a second lease cannot name a replacement inode.
    handle = kernel.CreateFileW(str(path), 0xC0000000, 3, None, 4, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    try:
        return os.fdopen(descriptor, "r+b")
    except BaseException:
        os.close(descriptor)
        raise


class DirectoryIdentity:
    """Retain the native directory handle for the lifetime of admission."""

    def __init__(self, path: Path, deny_delete: bool = False) -> None:
        self._handle: Any = None
        self._kernel: Any = None
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            class Information(ctypes.Structure):
                _fields_ = [
                    ("attributes", wintypes.DWORD),
                    ("created", wintypes.FILETIME), ("accessed", wintypes.FILETIME),
                    ("written", wintypes.FILETIME), ("volume", wintypes.DWORD),
                    ("size_high", wintypes.DWORD), ("size_low", wintypes.DWORD),
                    ("links", wintypes.DWORD), ("index_high", wintypes.DWORD),
                    ("index_low", wintypes.DWORD),
                ]

            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                          wintypes.DWORD, ctypes.c_void_p,
                                          wintypes.DWORD, wintypes.DWORD,
                                          wintypes.HANDLE]
            kernel.CreateFileW.restype = wintypes.HANDLE
            kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE,
                                                          ctypes.POINTER(Information)]
            kernel.GetFileInformationByHandle.restype = wintypes.BOOL
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle.restype = wintypes.BOOL
            handle = kernel.CreateFileW(str(path), 0x80, 3 if deny_delete else 7,
                                        None, 3, 0x02000000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            self._handle, self._kernel = handle, kernel
            info = Information()
            if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
                error = ctypes.WinError(ctypes.get_last_error())
                self.close()
                raise error
            device, index = info.volume, (info.index_high << 32) | info.index_low
            if not info.attributes & 0x10 or device == 0 or index == 0:
                self.close()
                raise OSError("unavailable native directory identifier")
            platform = "windows"
        elif os.name == "posix":
            handle = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            self._handle = handle
            info = os.fstat(handle)
            if not stat.S_ISDIR(info.st_mode):
                self.close()
                raise OSError("admission subject is not a directory")
            device, index, platform = info.st_dev, info.st_ino, "unix"
        else:
            raise OSError("native directory admission is not qualified on this platform")
        material = f"fortress-physical-directory-v1\0{platform}\0{device}\0{index}"
        self.key = hashlib.sha256(material.encode("ascii")).hexdigest()

    def matches(self, path: Path) -> bool:
        current = DirectoryIdentity(path)
        try:
            return current.key == self.key
        finally:
            current.close()

    def close(self) -> None:
        if self._handle is not None:
            if self._kernel is not None:
                self._kernel.CloseHandle(self._handle)
            else:
                os.close(self._handle)
            self._handle = None

    def __del__(self) -> None:
        self.close()


def _validate(namespace: str, entry: dict[str, Any]) -> None:
    if (namespace not in {"python", "rust"}
            or set(entry) != {"root_identity", "run_nonce", "journal_path",
                              "compiler_path", "completed"}
            or not _hex(entry["root_identity"], 64)
            or not _hex(entry["run_nonce"], 24)
            or type(entry["completed"]) is not bool
            or not isinstance(entry["journal_path"], str)
            or not isinstance(entry["compiler_path"], str)):
        raise OSError("invalid admission registration")
    short = entry["root_identity"][:16]
    journal = Path(entry["journal_path"])
    suffix = Path(namespace) / "x" / short / (entry["run_nonce"] + ".json")
    if not journal.is_absolute() or journal.parts[-4:] != suffix.parts:
        raise OSError("invalid adapter journal path")
    compiler = journal.parents[3] / namespace / "c" / short
    if Path(entry["compiler_path"]) != compiler:
        raise OSError("invalid adapter compiler path")


def _finished(namespace: str, entry: dict[str, Any]) -> bool:
    journal = _read_json(Path(entry["journal_path"]), 1_048_576)
    if (journal.get("root_identity") != entry["root_identity"]
            or journal.get("run_nonce") != entry["run_nonce"]):
        raise OSError("adapter journal binding mismatch")
    return (journal.get("lease_state") == "RELEASED"
            and journal.get("child_processes") == []
            and journal.get("lifecycle") in {"CLEANUP_COMPLETE", "FAILED", "CANCELLED"}
            and (namespace == "rust"
                 or journal.get("cleanup_status") in {"COMPLETE", "RECOVERED"}))


class HeavyAdmissionGuard:
    """An exclusive native lease shared with the installed runtime adapter."""

    def __init__(self, repository: Path, recovery: tuple[str, str] | None = None) -> None:
        self._lease: Any = None
        self.directory: DirectoryIdentity | None = None
        self._anchor: DirectoryIdentity | None = None
        self._registry_directory: DirectoryIdentity | None = None
        lease: Any = None
        try:
            self.directory = DirectoryIdentity(repository)
            fixed = _fixed_anchor()
            self._anchor = DirectoryIdentity(fixed, deny_delete=True)
            root = fixed.resolve(strict=True)
            if not self._anchor.matches(root):
                raise OSError("admission anchor identity changed")
            for component in ("fortress-ops", "admission-v1", self.directory.key):
                root = root / component
                _plain_directory(root)
            self._registry_directory = DirectoryIdentity(root, deny_delete=True)
            self.path = root / "owners.json"
            _plain_file(root / "heavy.lock")
            lease = _lease_file(root / "heavy.lock")
            _plain_file(root / "heavy.lock")
            self._check_root()
            if os.name == "nt":
                import msvcrt
                if lease.seek(0, os.SEEK_END) == 0:
                    lease.write(b"\0")
                    lease.flush()
                lease.seek(0)
                msvcrt.locking(lease.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lease.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lease = lease
            _plain_file(self.path)
            self.registry = (_read_json(self.path, 16_384) if self.path.exists()
                             else {"version": 1, "native_identity": self.directory.key,
                                   "registrations": {}})
            registry = self.registry
            if (set(registry) != {"version", "native_identity", "registrations"}
                    or type(registry["version"]) is not int or registry["version"] != 1
                    or registry["native_identity"] != self.directory.key
                    or not isinstance(registry["registrations"], dict)
                    or len(registry["registrations"]) > 2):
                raise OSError("invalid admission registry identity")
            for namespace, entry in registry["registrations"].items():
                if not isinstance(entry, dict):
                    raise OSError("invalid admission registration")
                _validate(namespace, entry)
                if (not entry["completed"] and not _finished(namespace, entry)
                        and recovery != (namespace, entry["root_identity"])):
                    raise OSError("unresolved adapter retains heavy admission")
        except BaseException:
            if self._lease is None and lease is not None:
                lease.close()
            self.close()
            raise

    def _save(self) -> None:
        self._check_root()
        _plain_file(self.path)
        content = (json.dumps(self.registry, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if len(content) > 16_384:
            raise OSError("oversized admission registry")
        with self.path.open("wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

    def register(self, namespace: str, root_identity: str, run_nonce: str,
                 journal_path: Path, compiler_path: Path) -> None:
        self.validate_target(namespace, compiler_path)
        entry = {"root_identity": root_identity, "run_nonce": run_nonce,
                 "journal_path": str(journal_path), "compiler_path": str(compiler_path),
                 "completed": False}
        _validate(namespace, entry)
        if not journal_path.is_file():
            raise OSError("admission registration requires the owner journal")
        self.registry["registrations"][namespace] = entry
        self._save()

    def validate_target(self, namespace: str, compiler_path: Path) -> None:
        self._check_root()
        previous = self.registry["registrations"].get(namespace)
        if previous is not None and Path(previous["compiler_path"]) != compiler_path:
            try:
                Path(previous["compiler_path"]).lstat()
            except FileNotFoundError:
                return
            raise OSError("retained adapter target must be explicitly cleaned before relocation")

    def complete_owned(self, namespace: str, root_identity: str) -> None:
        entry = self.registry["registrations"].get(namespace)
        if (entry is not None and entry["root_identity"] == root_identity
                and not entry["completed"] and _finished(namespace, entry)):
            entry["completed"] = True
            self._save()

    def compiler_paths(self, own_target: Path) -> set[Path]:
        self._check_root()
        return {own_target} | {Path(entry["compiler_path"])
                               for entry in self.registry["registrations"].values()}

    def _check_root(self) -> None:
        if self._anchor is None or self._registry_directory is None:
            raise OSError("admission registry handles are unavailable")
        metadata = self.path.parent.lstat()
        if (_linked(metadata) or not stat.S_ISDIR(metadata.st_mode)
                or not self._anchor.matches(_fixed_anchor())
                or not self._registry_directory.matches(self.path.parent)):
            raise OSError("admission registry directory changed")

    def close(self) -> None:
        if self._lease is not None:
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
        if self.directory is not None:
            self.directory.close()
            self.directory = None
        if self._registry_directory is not None:
            self._registry_directory.close()
            self._registry_directory = None
        if self._anchor is not None:
            self._anchor.close()
            self._anchor = None

    def __del__(self) -> None:
        self.close()
