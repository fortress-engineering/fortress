"""Observe a pinned isolated CPython source spec without loading the module."""

import sys

if (sys.implementation.name != "cpython" or not sys.flags.isolated
        or not sys.flags.no_site or not sys.flags.dont_write_bytecode
        or not sys.flags.safe_path or not sys.flags.ignore_environment):
    raise SystemExit(3)

from hashlib import sha256
from importlib import machinery, util
import json
import os
import stat
from types import FunctionType
from zipimport import zipimporter


MODULE = "pathlib"
WINDOWS = sys.platform == "win32"
PROFILES = {
    ("win32", (3, 13, 5)): {
        "search": ["python313.zip", "DLLs", "Lib", "."],
        "entry": "Lib/pathlib/__init__.py",
        "package": True,
        "entry_ref": "sha256:62b3b842bda77ca6245f8c8657b8c72540e383fb9aa70e4c3a705947cc8611fd",
    },
    ("linux", (3, 12, 3)): {
        "search": ["lib/python312.zip", "lib/python3.12", "lib/python3.12/lib-dynload"],
        "entry": "lib/python3.12/pathlib.py",
        "package": False,
        "entry_ref": "sha256:b43e134bf7479759838b4ecec3d78e0e67fdfde2d671c5c2d7886a47da93885d",
    },
}
LOADERS = (
    (machinery.ExtensionFileLoader, machinery.EXTENSION_SUFFIXES),
    (machinery.SourceFileLoader, machinery.SOURCE_SUFFIXES),
    (machinery.SourcelessFileLoader, machinery.BYTECODE_SUFFIXES),
)
DEFAULT_HOOK = machinery.FileFinder.path_hook(*LOADERS)
DEFAULT_META = [machinery.BuiltinImporter, machinery.FrozenImporter, machinery.PathFinder]
MAX_MEMBER = 256 * 1024


class Refuse(Exception):
    """A fixed status identifier."""


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def stamp(raw):
    return "sha256:" + sha256(raw).hexdigest()


def present(stats, mode):
    linked = stat.S_ISLNK(stats.st_mode) or (getattr(stats, "st_file_attributes", 0)
                                             & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    if linked or not mode(stats.st_mode):
        raise Refuse("NONORDINARY_RUNTIME_ASSET")


def ordinary_directory(path):
    while True:
        present(os.lstat(path), stat.S_ISDIR)
        parent = os.path.dirname(path)
        if path == parent:
            return
        path = parent


def ordinary_stat(path):
    source = os.lstat(path)
    present(source, stat.S_ISREG)
    return source


def file_identity(item):
    created = item.st_birthtime_ns if WINDOWS else item.st_ctime_ns
    return item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, created


def read_pinned(path, reference):
    ordinary_directory(os.path.dirname(path))
    before = ordinary_stat(path)
    if not 0 < before.st_size <= MAX_MEMBER:
        raise Refuse("RUNTIME_ASSET_LIMIT")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        inode = file_identity(before)
        if file_identity(os.fstat(stream.fileno())) != inode:
            raise Refuse("RUNTIME_ASSET_CHANGED")
        contents = stream.read(MAX_MEMBER + 1)
        if (len(contents) != before.st_size or file_identity(os.fstat(stream.fileno())) != inode
                or file_identity(ordinary_stat(path)) != inode):
            raise Refuse("RUNTIME_ASSET_CHANGED")
    if stamp(contents) != reference:
        raise Refuse("RUNTIME_SOURCE_PIN_MISMATCH")


def refuse_archive(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    raise Refuse("ARCHIVE_ORIGIN_UNSUPPORTED")


def checked_hooks():
    if len(sys.path_hooks) != 2 or sys.path_hooks[0] is not zipimporter:
        raise Refuse("PATH_HOOK_DRIFT")
    actual = sys.path_hooks[1]
    if (type(actual) is not FunctionType or actual.__code__ is not DEFAULT_HOOK.__code__
            or actual.__globals__ is not DEFAULT_HOOK.__globals__
            or tuple(cell.cell_contents for cell in (actual.__closure__ or ()))
            != tuple(cell.cell_contents for cell in (DEFAULT_HOOK.__closure__ or ()))):
        raise Refuse("PATH_HOOK_DRIFT")


def checked_cache(roots):
    loaders = [(suffix, loader) for loader, suffixes in LOADERS for suffix in suffixes]
    for index, root in enumerate(roots):
        if root not in sys.path_importer_cache:
            continue
        entry = sys.path_importer_cache[root]
        if index == 0:
            if entry is not None:
                raise Refuse("PATH_IMPORTER_CACHE_DRIFT")
        elif (type(entry) is not machinery.FileFinder or entry.path != root
              or entry._loaders != loaders):
            raise Refuse("PATH_IMPORTER_CACHE_DRIFT")


def spec_facts(spec, expected, package):
    if (spec is None or spec.name != MODULE or spec.origin != expected
            or type(spec.loader) is not machinery.SourceFileLoader or spec.loader.path != expected
            or spec.loader.name != MODULE or not spec.has_location):
        raise Refuse("INSTALLED_SOURCE_ORIGIN_UNESTABLISHED")
    locations = [os.path.dirname(expected)] if package else None
    if spec.submodule_search_locations != locations:
        raise Refuse("PACKAGE_BOUNDARY_UNESTABLISHED")


def pinned_origin(profile):
    if profile is None:
        raise Refuse("RUNTIME_VERSION_UNAVAILABLE")
    if any(name == MODULE or name.startswith(MODULE + ".") for name in sys.modules):
        raise Refuse("CACHED_MODULE_UNESTABLISHED")
    root = sys.base_prefix
    if sys.prefix != root or sys.base_exec_prefix != root or not os.path.isabs(root):
        raise Refuse("RUNTIME_PREFIX_UNESTABLISHED")
    roots = [os.path.normpath(os.path.join(root, member)) for member in profile["search"]]
    if sys.path != roots:
        raise Refuse("SEARCH_PATH_DRIFT")
    if len(sys.meta_path) != len(DEFAULT_META) or not all(
            actual is expected for actual, expected in zip(sys.meta_path, DEFAULT_META, strict=True)):
        raise Refuse("META_PATH_DRIFT")
    checked_hooks()
    checked_cache(roots)

    ordinary_directory(os.path.dirname(roots[0]))
    refuse_archive(roots[0])
    for directory in roots[1:]:
        ordinary_directory(directory)
    expected = os.path.normpath(os.path.join(root, profile["entry"]))
    read_pinned(expected, profile["entry_ref"])
    dry = [spec for directory in roots[1:]
           if (spec := machinery.FileFinder(directory, *LOADERS).find_spec(MODULE)) is not None]
    if len(dry) != 1:
        raise Refuse("RUNTIME_ORIGIN_AMBIGUOUS")
    spec_facts(dry[0], expected, profile["package"])
    # This comparison runs only for trusted isolated roots with the native
    # finder and caches already checked. It selects a spec but never invokes
    # create_module or exec_module. MODULE is a fixed top-level name.
    native = util.find_spec(MODULE)
    spec_facts(native, expected, profile["package"])
    read_pinned(expected, profile["entry_ref"])
    refuse_archive(roots[0])
    if MODULE in sys.modules:
        raise Refuse("MODULE_WAS_LOADED")
    return {
        "status": "EXACT_INSTALLED_NATIVE_SPEC",
        "selection": {"relative_origin": profile["entry"], "source_ref": profile["entry_ref"],
                      "loader": "SOURCE_FILE_LOADER", "package": profile["package"]},
        "search_members": profile["search"],
    }



def main():
    if len(sys.argv) != 1:
        return 3
    try:
        result = pinned_origin(PROFILES.get((sys.platform, sys.version_info[:3])))
    except (Refuse, OSError, ValueError, ImportError):
        return 3
    result["guarded_external_callbacks"] = 0
    result["project_runtime_import_origin"] = "UNESTABLISHED"
    result["module_execution"] = "NOT_RUN"
    sys.stdout.buffer.write(canonical(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
