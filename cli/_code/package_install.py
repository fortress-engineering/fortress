"""Verify and manage explicit Fortress development packages with Python 3.11+."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import tempfile
import zipfile

SCHEMA = "urn:fortress:schema:v1:package-manifest"
LIMIT = 512 * 1024**2
MANIFEST_LIMIT = 256 * 1024
MAX_MEMBERS = 512
HEX = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}")
SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}")
WINDOWS_NAMES = {"aux", "con", "nul", "prn", *(f"{prefix}{n}" for prefix in ("com", "lpt") for n in range(10))}
FIELDS = {"$schema", "schema_version", "product_version", "target", "archive_sha256",
          "archive_bytes", "source_commit", "source_fingerprint", "files", "build",
          "compatibility", "runtime", "authenticity", "release_authorization"}


# Registered optional preparation recipes. Kept in the standalone installer so
# extraction and verification require neither a Go SDK nor a source checkout.
GO_WORKER_FORMAT = "fortress-native-go-workers-v1"
GO_WORKER_PREFIX = "bin/fortress-go-collector-"
GO_NOTICE_PREFIX = "share/fortress/native/go/"
GO_NOTICE_BYTES_LIMIT = 64 << 10
GO_WORKER_VERSIONS = {"linux-x64": "go1.22.2", "windows-x64": "go1.22.12"}
GO_WORKER_BUILD_FLAGS = ["-trimpath", "-buildvcs=false", "-p=1", "-ldflags=-buildid="]
GO_WORKER_ENVIRONMENT = {
    "CGO_ENABLED": "0", "GO111MODULE": "off", "GOAMD64": "v1", "GOARCH": "amd64",
    "GODEBUG": "gotypesalias=0", "GOENV": "off", "GOEXPERIMENT": "", "GOFLAGS": "",
    "GOMAXPROCS": "2", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local",
    "GOVCS": "*:off", "GOWORK": "off",
}
GO_WORKER_SOURCE_ROOT = "engine/program_semantics/_code/"
GO_WORKERS = {
    "body-v1": (
        ("collector.go", "go_body.go"),
        ["observe-go-v1", "lower-first-order-go-v1"],
    ),
    "tests-v1": (
        ("collector.go", "collector_build_context.go", "go_test_observer.go"),
        ["observe-go-v1", "select-build-go-v2", "observe-go-tests-v1"],
    ),
    "v1": (("collector.go",), ["observe-go-v1"]),
    "v3": (
        ("collector.go", "collector_build_context.go", "collector_local_imports.go"),
        ["observe-go-v1", "select-build-go-v2", "observe-go-module-v3"],
    ),
}
GO_FILESYSTEM_FORMAT = "fortress-native-go-filesystem-v1"
GO_FILESYSTEM_EDITION = "filesystem-v1"
GO_FILESYSTEM_RECIPE = "INSTALLED_STDLIB_GC_NO_CGO_V1"
GO_FILESYSTEM_BASE = "bin/fortress-go-filesystem"
GO_FILESYSTEM_NOTICES = "share/fortress/native/go-filesystem/"
GO_FILESYSTEM_SOURCES = ("collector.go", "go_fs_collector.go")
# SDK inventory, SDK executable, os package source, export set, generated source,
# then exact archive count and byte population for the reviewed target.
GO_FILESYSTEM_PINS = {
    "linux-x64": (
        "d19703cbb634db3ca64f038771db5a5425a98360119c1c546cba7d1ca3b8acdd",
        "38379bebce720e1abb72fa3232d3c7b07a4e71dd1e98fa5fcc6f9a56dd084a06",
        "sha256:f303ff6f8d3d1c289200cd4ec875383db41fa256582cf573e9e24cd02043523f",
        "sha256:ad593385ff54ba4a158d464bc9d9ef87bf9a13f3ad26d63f5f5f26c2452aa377",
        "sha256:cb630e93977f730416bdbe10e597be2c3c766e8155c6f8d4370b970f26b3422e",
        38, 21748252,
    ),
    "windows-x64": (
        "17e7091ad29bb254d5017044cb586f076eba384ba7432127d97494de361b62a3",
        "08cfbe81f1bf519874ce8e6670ea98768d18cc0d16b9ff9d67eb785ec9a15cf9",
        "sha256:8f61ebb242bc4c60ebcaf6a96015ff67d0ac84d3441da63bd6c185eda13fc226",
        "sha256:4ff2871ac521be941d7da0eaef51d1a90a6e30a504774a8b043a03943e1798bc",
        "sha256:780da2322940f92f575718da650e6830a162568ee479da41e580519c12fe6b94",
        40, 22745838,
    ),
}

GO_SDK_FILES_LIMIT = 16_384
GO_SDK_BYTES_LIMIT = 384 * 1024**2
GO_WORKER_BYTES_LIMIT = 32 * 1024**2


class PackageError(ValueError):
    """The package or its requested installation could not be verified."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    # This manifest restricts property names and strings to printable ASCII and
    # numbers to safe integers. This subset has the same encoding under JCS.
    def check(item):
        if isinstance(item, dict):
            for key, val in item.items():
                check(key)
                check(val)
        elif isinstance(item, list):
            for val in item:
                check(val)
        elif type(item) is str and len(item) <= 4096 and all(" " <= ch <= "~" for ch in item):
            return
        elif type(item) is int and 0 <= item < 2**53:
            return
        else:
            raise PackageError("manifest value outside the canonical subset")
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def safe_member(name):
    if not isinstance(name, str) or len(name) > 224:
        return False
    return all(SEGMENT.fullmatch(part) and not part.endswith(".")
               and part.partition(".")[0].casefold() not in WINDOWS_NAMES for part in name.split("/"))


def executable_name(target=None):
    return "fortress.exe" if (target or target_platform()).startswith("windows-") else "fortress"


def target_platform():
    host = platform.system().lower()
    if host not in ("windows", "linux") or platform.machine().lower() not in ("x86_64", "amd64"):
        raise PackageError("host is outside the supported portable installation targets")
    return host + "-x64"


def native_go_path(worker, target):
    suffix = ".exe" if target == "windows-x64" else ""
    return GO_WORKER_PREFIX + worker + suffix


def native_go_environment(target):
    return {**GO_WORKER_ENVIRONMENT, "GOOS": target.removesuffix("-x64")}


def native_go_notice_paths(layout):
    names = ("debian-copyright.txt",) if layout == "debian-go-1.22-split" else ("LICENSE.txt", "PATENTS.txt")
    return [GO_NOTICE_PREFIX + name for name in names]


def validate_native_go_sdk(sdk, target):
    """Validate the installed SDK binding shared by both build attachments."""
    if (not isinstance(sdk, dict)
            or set(sdk) != {"version", "digest", "go_executable_digest", "layout", "files", "bytes"}
            or sdk["version"] != GO_WORKER_VERSIONS[target]
            or not HEX.fullmatch(sdk["digest"])
            or not HEX.fullmatch(sdk["go_executable_digest"])
            or sdk["layout"] not in ("ordinary", "debian-go-1.22-split")
            or (sdk["layout"] == "debian-go-1.22-split" and target != "linux-x64")
            or type(sdk["files"]) is not int or not 1 <= sdk["files"] <= GO_SDK_FILES_LIMIT
            or type(sdk["bytes"]) is not int or not 1 <= sdk["bytes"] <= GO_SDK_BYTES_LIMIT):
        raise PackageError("unsupported native Go SDK binding")


def native_go_members(manifest, files):
    """Validate the optional build attachment and bind its executable members."""
    names = sorted(name for name in files if name.casefold().startswith(GO_WORKER_PREFIX))
    notices = sorted(name for name in files if name.casefold().startswith(GO_NOTICE_PREFIX))
    details = manifest["build"].get("native_go")
    if details is None:
        if names or notices:
            raise PackageError("native Go worker member has no known build attachment")
        return []
    target = manifest["target"]
    if (not isinstance(details, dict)
            or set(details) != {"format", "target", "source_commit", "source_fingerprint",
                               "build_flags", "environment", "sdk", "workers", "notices"}
            or details["format"] != GO_WORKER_FORMAT
            or target not in GO_WORKER_VERSIONS or details["target"] != target
            or details["source_commit"] != manifest["source_commit"]
            or details["source_fingerprint"] != manifest["source_fingerprint"]
            or details["build_flags"] != GO_WORKER_BUILD_FLAGS
            or details["environment"] != native_go_environment(target)):
        raise PackageError("unsupported native Go worker build attachment")
    sdk = details["sdk"]
    validate_native_go_sdk(sdk, target)
    notice_paths = native_go_notice_paths(sdk["layout"])
    if notices != notice_paths or details["notices"] != [files[name] for name in notice_paths] or any(
        not 1 <= files[name]["bytes"] <= GO_NOTICE_BYTES_LIMIT for name in notice_paths
    ):
        raise PackageError("native Go notices do not match exact package membership")
    workers = details["workers"]
    if not isinstance(workers, list) or not 1 <= len(workers) <= len(GO_WORKERS):
        raise PackageError("invalid native Go worker population")
    expected = []
    for worker in workers:
        if (not isinstance(worker, dict)
                or set(worker) != {"edition", "path", "sha256", "bytes", "protocols", "sources"}
                or worker["edition"] not in GO_WORKERS
                or worker["path"] != native_go_path(worker["edition"], target)
                or not HEX.fullmatch(worker["sha256"])
                or type(worker["bytes"]) is not int
                or not 64 <= worker["bytes"] <= GO_WORKER_BYTES_LIMIT):
            raise PackageError("invalid native Go worker identity")
        sources, protocols = GO_WORKERS[worker["edition"]]
        if worker["protocols"] != protocols or not isinstance(worker["sources"], list) or len(worker["sources"]) != len(sources):
            raise PackageError("unrecognized native Go worker recipe")
        for source, name in zip(worker["sources"], sources, strict=True):
            if (not isinstance(source, dict) or set(source) != {"path", "sha256"}
                    or source["path"] != GO_WORKER_SOURCE_ROOT + name or not HEX.fullmatch(source["sha256"])):
                raise PackageError("invalid native Go source identity")
        actual = files.get(worker["path"])
        if actual != {key: worker[key] for key in ("path", "bytes", "sha256")}:
            raise PackageError("native Go worker differs from package membership")
        expected.append(worker["path"])
    if expected != names:
        raise PackageError("native Go worker inventory is incomplete, duplicated, or noncanonical")
    return expected


def native_go_filesystem_path(target):
    return GO_FILESYSTEM_BASE + (".exe" if target == "windows-x64" else "")


def native_go_filesystem_notices(layout):
    return [GO_FILESYSTEM_NOTICES + Path(path).name for path in native_go_notice_paths(layout)]


def native_go_filesystem_members(manifest, files):
    reserved = {native_go_filesystem_path(target) for target in GO_FILESYSTEM_PINS}
    names = sorted(name for name in files if name.casefold() in reserved)
    notices = sorted(name for name in files if name.casefold().startswith(GO_FILESYSTEM_NOTICES))
    details = manifest["build"].get("native_go_filesystem")
    if details is None:
        if names or notices:
            raise PackageError("Go filesystem member has no matching build attachment")
        return []
    target = manifest["target"]
    if (not isinstance(details, dict)
            or set(details) != {"format", "target", "source_commit", "source_fingerprint", "build_flags",
                               "environment", "sdk", "worker", "sources", "notices", "library"}
            or details["format"] != GO_FILESYSTEM_FORMAT
            or target not in GO_FILESYSTEM_PINS or details["target"] != target
            or details["source_commit"] != manifest["source_commit"]
            or details["source_fingerprint"] != manifest["source_fingerprint"]
            or details["build_flags"] != GO_WORKER_BUILD_FLAGS
            or details["environment"] != native_go_environment(target)):
        raise PackageError("unsupported Go filesystem build attachment")
    sdk = details["sdk"]
    validate_native_go_sdk(sdk, target)
    sdk_ref, executable_ref, package_ref, export_ref, generated_ref, exports, export_bytes = GO_FILESYSTEM_PINS[target]
    if (sdk["digest"], sdk["go_executable_digest"]) != (sdk_ref, executable_ref):
        raise PackageError("Go filesystem SDK qualification does not match the target")
    if details["library"] != {
        "preparation": GO_FILESYSTEM_RECIPE, "package_source_ref": package_ref,
        "export_set_ref": export_ref, "generated_asset_ref": generated_ref,
        "export_count": exports, "export_bytes": export_bytes,
    }:
        raise PackageError("Go filesystem library qualification does not match the target")
    sources = details["sources"]
    if not isinstance(sources, list) or len(sources) != len(GO_FILESYSTEM_SOURCES):
        raise PackageError("invalid Go filesystem source inventory")
    for source, name in zip(sources, GO_FILESYSTEM_SOURCES, strict=True):
        if (not isinstance(source, dict) or set(source) != {"path", "sha256"}
                or source["path"] != GO_WORKER_SOURCE_ROOT + name or not HEX.fullmatch(source["sha256"])):
            raise PackageError("invalid Go filesystem source identity")
    path = native_go_filesystem_path(target)
    if (names != [path] or details["worker"] != files[path]
            or not 64 <= files[path]["bytes"] <= GO_WORKER_BYTES_LIMIT):
        raise PackageError("Go filesystem worker differs from package membership")
    expected_notices = native_go_filesystem_notices(sdk["layout"])
    if (notices != expected_notices or details["notices"] != [files[name] for name in expected_notices]
            or any(not 1 <= files[name]["bytes"] <= GO_NOTICE_BYTES_LIMIT for name in expected_notices)):
        raise PackageError("Go filesystem notices differ from package membership")
    return names


def optional_executables(manifest, files):
    return native_go_members(manifest, files) + native_go_filesystem_members(manifest, files)

def parse_manifest(raw):
    def pairs(entries):
        result = dict(entries)
        if len(result) != len(entries):
            raise PackageError("duplicate manifest property")
        return result

    if len(raw) > MANIFEST_LIMIT:
        raise PackageError("manifest too large")
    try:
        m = json.loads(raw, object_pairs_hook=pairs)
        if canonical(m) != raw or not isinstance(m, dict) or set(m) != FIELDS:
            raise PackageError("unsupported manifest structure or encoding")
        if (m["$schema"] != SCHEMA or m["schema_version"] != 1
                or m["authenticity"] != "UNVERIFIED" or m["release_authorization"] != "NOT_ESTABLISHED"
                or m["target"] not in ("windows-x64", "linux-x64", "macos-arm64")
                or not VERSION.fullmatch(m["product_version"])
                or not re.fullmatch(r"[0-9a-f]{40}", m["source_commit"])
                or not all(HEX.fullmatch(m[key]) for key in ("archive_sha256", "source_fingerprint"))
                or type(m["archive_bytes"]) is not int or not 22 <= m["archive_bytes"] <= LIMIT
                or not all(isinstance(m[key], dict) and m[key] for key in ("build", "runtime", "compatibility"))):
            raise PackageError("unsupported manifest binding")
        records = m["files"]
        if not isinstance(records, list) or not 1 <= len(records) <= MAX_MEMBERS:
            raise PackageError("invalid manifest inventory population")
        names = []
        for item in records:
            if (set(item) != {"path", "bytes", "sha256"} or not safe_member(item["path"])
                    or item["path"].casefold() == "manifest.json"
                    or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= LIMIT
                    or not HEX.fullmatch(item["sha256"])):
                raise PackageError("invalid manifest member")
            names.append(item["path"])
        folded = {name.casefold() for name in names}
        for name in names:
            if any(parent.as_posix().casefold() in folded for parent in Path(name).parents):
                raise PackageError("inventory contains overlapping paths")
        aliases = {}
        for name in names:
            for parent in Path(name).parents:
                alias = parent.as_posix()
                previous = aliases.setdefault(alias.casefold(), alias)
                if previous != alias:
                    raise PackageError("case-colliding inventory directories")
        if (len(folded) != len(names) or names != sorted(names)
                or sum(row["bytes"] for row in records) > LIMIT
                or "bin/" + executable_name(m["target"]) not in names):
            raise PackageError("noncanonical or incomplete inventory")
        optional_executables(m, {row["path"]: row for row in records})
        return m
    except (UnicodeError, TypeError, KeyError, RecursionError, AttributeError, json.JSONDecodeError) as e:
        raise PackageError("invalid package manifest") from e


def ordinary(path, directory=False):
    info = path.lstat()
    if (getattr(info, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode)
            or (not directory and info.st_nlink != 1)):
        raise PackageError("linked or unexpected filesystem object: " + str(path))
    return info


def directories(path, create=False):
    if not path.is_absolute() or ".." in path.parts:
        raise PackageError("destination must be an absolute path without parent traversal")
    for parent in [*reversed(path.parents), path]:
        try:
            ordinary(parent, directory=True)
        except FileNotFoundError:
            if not create:
                raise
            try:
                parent.mkdir(mode=0o700)
            except FileExistsError:
                pass
            ordinary(parent, directory=True)


@contextmanager
def open_file(path):
    original = ordinary(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        if not os.path.samestat(original, os.fstat(stream.fileno())):
            raise PackageError("file changed while being opened")
        yield stream


def hash_stream(stream, bound):
    total = 0
    state = hashlib.sha256()
    while block := stream.read(1024 * 1024):
        total += len(block)
        if total > bound:
            raise PackageError("input exceeds bound")
        state.update(block)
    return total, state.hexdigest()


def hash_file(path, bound=LIMIT):
    with open_file(path) as stream:
        return hash_stream(stream, bound)


def read_manifest(path):
    with open_file(path) as stream:
        return stream.read(MANIFEST_LIMIT + 1)


@contextmanager
def verified_zip(path, manifest):
    with open_file(path) as stream:
        size, sha = hash_stream(stream, manifest["archive_bytes"])
        if (size, sha) != (manifest["archive_bytes"], manifest["archive_sha256"]):
            raise PackageError("archive identity mismatch")
        stream.seek(-22, os.SEEK_END)
        sig, disk, catalog, count, total, index_size, offset, comment = struct.unpack("<4s4H2IH", stream.read(22))
        if (sig != b"PK\x05\x06" or disk or catalog or comment or count != total
                or not 1 <= count <= MAX_MEMBERS or index_size > MANIFEST_LIMIT
                or offset + index_size != size - 22):
            raise PackageError("unsupported or unbounded ZIP directory")
        try:
            with zipfile.ZipFile(stream) as archive:
                listed = archive.infolist()
                expected = {row["path"]: row for row in manifest["files"]}
                if (len(listed) != count or set(expected) != {x.filename for x in listed}
                        or len(expected) != len(listed)):
                    raise PackageError("archive does not have the exact member inventory")
                for entry in listed:
                    if (entry.orig_filename != entry.filename or entry.flag_bits & ~0x800
                            or entry.compress_type != zipfile.ZIP_STORED
                            or entry.file_size != entry.compress_size
                            or (entry.external_attr >> 16) & 0o170000 not in (0, stat.S_IFREG)
                            or entry.file_size != expected[entry.filename]["bytes"]):
                        raise PackageError("unsupported or altered ZIP member")
                machines = ["bin/" + executable_name(manifest["target"]), *optional_executables(manifest, expected)]
                for name in machines:
                    with archive.open(name) as executable:
                        verify_machine(executable, manifest["target"])
                yield archive
        except (zipfile.BadZipFile, NotImplementedError) as e:
            raise PackageError("invalid ZIP") from e


def verify_machine(executable, target):
    header = executable.read(64)
    if target == "linux-x64":
        valid = (len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01"
                 and header[18:20] == b"\x3e\x00")
    elif target == "windows-x64":
        valid = False
        if len(header) == 64 and header[:2] == b"MZ":
            offset = int.from_bytes(header[60:64], "little")
            if 64 <= offset <= 1024 * 1024:
                executable.seek(offset)
                valid = executable.read(6) == b"PE\x00\x00\x64\x86"
    else:
        raise PackageError("no qualified executable format reader for this target")
    if not valid:
        raise PackageError("archive executable format or architecture does not match target")


def verify_members(archive, manifest, destination=None):
    files = {row["path"]: row for row in manifest["files"]}
    executables = {"bin/" + executable_name(manifest["target"]), *optional_executables(manifest, files)}
    for member in manifest["files"]:
        with archive.open(member["path"]) as source:
            if destination is None:
                actual = hash_stream(source, member["bytes"])
            else:
                path = destination / member["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                state = hashlib.sha256()
                size = 0
                with path.open("xb") as output:
                    while block := source.read(1024 * 1024):
                        size += len(block)
                        if size > member["bytes"]:
                            raise PackageError("expanded member exceeds bound")
                        state.update(block)
                        output.write(block)
                    output.flush()
                    os.fsync(output.fileno())
                actual = (size, state.hexdigest())
                if member["path"] in executables:
                    path.chmod(0o755)
            if actual != (member["bytes"], member["sha256"]):
                raise PackageError("member integrity mismatch: " + member["path"])


def verify(path, raw):
    manifest = parse_manifest(raw)
    with verified_zip(path, manifest) as archive:
        verify_members(archive, manifest)
    return manifest


@contextmanager
def lease(root):
    marker = root / ".fortress-install.lock"
    try:
        with marker.open("xb") as f:
            f.write(b"\0")
    except FileExistsError:
        pass
    original = ordinary(marker)
    fd = os.open(marker, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "r+b") as stream:
        if not os.path.samestat(original, os.fstat(stream.fileno())):
            raise PackageError("installation lease identity changed")
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def slot_name(raw, manifest):
    return "fortress-" + manifest["product_version"] + "-" + digest(raw)


def inventory(slot, manifest, partial=False):
    directories(slot)
    expected = {member["path"]: member for member in manifest["files"]}
    directory_names = {parent.as_posix() for name in expected for parent in Path(name).parents} - {"."}
    seen = set()
    pending = [slot]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            rel = path.relative_to(slot).as_posix()
            if rel in directory_names:
                ordinary(path, directory=True)
                pending.append(path)
            elif rel == "manifest.json":
                ordinary(path)
            elif rel in expected:
                member = expected[rel]
                if hash_file(path, member["bytes"]) != (member["bytes"], member["sha256"]):
                    raise PackageError("modified installed member: " + rel)
                seen.add(rel)
            else:
                raise PackageError("unexpected installed object: " + rel)
    if not partial and seen != set(expected):
        raise PackageError("installed package has missing files")
    return seen, directory_names


def installed(slot, approved, partial=False):
    directories(slot)
    raw = read_manifest(slot / "manifest.json")
    if digest(raw) != approved:
        raise PackageError("installed manifest does not match the approved identity")
    m = parse_manifest(raw)
    if slot.name.removeprefix(".removing-") != slot_name(raw, m):
        raise PackageError("installed slot identity mismatch")
    return m, inventory(slot, m, partial)


def check_slot(name, approved):
    if not re.fullmatch(r"fortress-[0-9.]+-[0-9a-f]{64}", name) or not HEX.fullmatch(approved):
        raise PackageError("invalid installation identity")


def installation_root(root):
    if any(os.path.lexists(directory / marker) for directory in (root, *root.parents)
           for marker in (".git", "__fortress", "Cargo.toml", "contract.json")):
        raise PackageError("installation storage belongs outside project repositories")


def install(path, raw, root, previous=None):
    manifest = parse_manifest(raw)
    if manifest["target"] != target_platform():
        raise PackageError("package target does not match the installation platform")
    installation_root(root)
    name = slot_name(raw, manifest)
    with verified_zip(path, manifest) as archive:
        directories(root, create=True)
        with lease(root):
            if previous is not None:
                check_slot(*previous)
                prior, _ = installed(root / previous[0], previous[1])
                if (prior["product_version"], prior["target"]) != (manifest["product_version"], manifest["target"]):
                    raise PackageError("no supported replacement relationship")
            final = root / name
            if os.path.lexists(final):
                verify_members(archive, manifest)
                installed(final, digest(raw))
                return final
            with tempfile.TemporaryDirectory(prefix=".incoming-", dir=root) as staging:
                stage = Path(staging) / "slot"
                stage.mkdir()
                verify_members(archive, manifest, stage)
                with (stage / "manifest.json").open("xb") as stamp:
                    stamp.write(raw)
                    stamp.flush()
                    os.fsync(stamp.fileno())
                inventory(stage, manifest)
                if os.path.lexists(final):
                    raise PackageError("conflicting installation destination")
                stage.rename(final)
                return final


def remove(root, name, approved):
    check_slot(name, approved)
    installation_root(root)
    directories(root)
    with lease(root):
        slot = root / name
        pending = root / (".removing-" + name)
        if os.path.lexists(pending):
            if os.path.lexists(slot):
                raise PackageError("ambiguous removal state")
            _, (files, folders) = installed(pending, approved, partial=True)
        else:
            _, (files, folders) = installed(slot, approved)
            slot.rename(pending)
        for name in sorted(files):
            path = pending / name
            ordinary(path)
            path.unlink()
        for name in sorted(folders, key=lambda name: (name.count("/"), name), reverse=True):
            path = pending / name
            if path.exists():
                path.rmdir()
        (pending / "manifest.json").unlink()
        pending.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "install"):
        command = sub.add_parser(name)
        command.add_argument("archive", type=Path)
        command.add_argument("manifest", type=Path)
        command.add_argument("--manifest-sha256", required=True)
        if name == "install":
            command.add_argument("root", type=Path)
            command.add_argument("--replace", nargs=2, metavar=("SLOT", "MANIFEST_SHA256"))
    command = sub.add_parser("remove")
    command.add_argument("root", type=Path)
    command.add_argument("slot")
    command.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "remove":
            remove(args.root, args.slot, args.manifest_sha256)
            print(json.dumps({"status":"REMOVED"}))
            return
        raw = read_manifest(args.manifest)
        if digest(raw) != args.manifest_sha256:
            raise PackageError("supplied manifest identity did not match")
        if args.command == "install":
            slot = install(args.archive, raw, args.root, args.replace)
            print(json.dumps({"status":"INSTALLED", "slot":str(slot), "authenticity":"UNVERIFIED"}))
        else:
            verify(args.archive, raw)
            print(json.dumps({"status":"VERIFIED", "authenticity":"UNVERIFIED"}))
    except (OSError, PackageError) as error:
        parser.exit(2, json.dumps({"status":"REFUSED", "message":str(error)}) + "\n")


if __name__ == "__main__":
    main()
