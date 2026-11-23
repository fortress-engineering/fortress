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
                with archive.open("bin/" + executable_name(manifest["target"])) as executable:
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
                if member["path"] == "bin/" + executable_name(manifest["target"]):
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
