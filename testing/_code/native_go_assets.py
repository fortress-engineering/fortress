"""Build optional Fortress Go workers from a pinned external native SDK."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil

from bounded_io import strict_json

from package_install import (
    GO_FILESYSTEM_EDITION, GO_FILESYSTEM_FORMAT, GO_FILESYSTEM_PINS, GO_FILESYSTEM_RECIPE, GO_FILESYSTEM_SOURCES,
    GO_NOTICE_BYTES_LIMIT, GO_SDK_BYTES_LIMIT, GO_SDK_FILES_LIMIT, GO_WORKER_BUILD_FLAGS, GO_WORKER_BYTES_LIMIT,
    GO_WORKER_FORMAT, GO_WORKER_SOURCE_ROOT, GO_WORKER_VERSIONS, GO_WORKERS, HEX,
    PackageError, canonical, digest, directories, hash_file, native_go_environment, native_go_path,
    native_go_filesystem_notices, native_go_filesystem_path, native_go_notice_paths, open_file, ordinary, verify_machine,
)

WORKER_EDITIONS = (*GO_WORKERS, GO_FILESYSTEM_EDITION)
_MAX_PATH_BYTES = 512
_GO_EXPORT_ROWS = 160
_GO_EXPORT_BYTES = 128 << 20
_GO_ARCHIVE_BYTES = 16 << 20
_GO_PACKAGE_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")
_SOURCE_LIMIT = 64 << 10
_TIMEOUT = 180
_DEBIAN_ROOT = Path("/usr/lib/go-1.22")
_DEBIAN_LINKS = {
    "src": "../../share/go-1.22/src",
    "pkg/include": "../../../share/go-1.22/pkg/include",
}


def sdk_directory(root, target, logical, location):
    if location.is_symlink():
        expected = _DEBIAN_LINKS.get(logical)
        if target != "linux-x64" or root != _DEBIAN_ROOT or os.readlink(location) != expected:
            raise PackageError("unrecognized linked Go SDK directory")
        location = location.resolve(strict=True)
        directories(location)
        return location, True
    ordinary(location, directory=True)
    return location, False


def inspect_sdk(root, target, project):
    """Hash the explicit SDK command, build data, tool programs and standard sources."""
    if target not in GO_WORKER_VERSIONS or not root.is_absolute() or root.is_relative_to(project):
        raise PackageError("Go worker staging requires an external supported native SDK")
    directories(root)
    executable = "bin/go.exe" if target == "windows-x64" else "bin/go"
    entries = []
    pending = [(logical, root / logical) for logical in ("src", "pkg")]
    split = set()
    population = 0
    total = 0
    go_digest = None

    def record(logical, source):
        nonlocal total, go_digest
        if not logical.isascii() or len(logical) > _MAX_PATH_BYTES:
            raise PackageError("unsupported Go SDK inventory path")
        size, sha = hash_file(source, GO_SDK_BYTES_LIMIT - total)
        total += size
        entries.append({"path": logical, "bytes": size, "sha256": sha})
        if logical == executable:
            go_digest = sha

    directories(root / "bin")
    for name in (executable, "VERSION", "go.env"):
        record(name, root / name)

    while pending:
        logical, physical = pending.pop()
        physical, linked = sdk_directory(root, target, logical, physical)
        if physical.is_relative_to(project):
            raise PackageError("Go SDK inventory overlaps the project")
        if linked:
            split.add(logical)
        for child in physical.iterdir():
            population += 1
            if population > GO_SDK_FILES_LIMIT:
                raise PackageError("Go SDK inventory exceeds bounded population")
            name = logical + "/" + child.name
            if child.is_dir():
                pending.append((name, child))
            else:
                record(name, child)
    if split and split != set(_DEBIAN_LINKS):
        raise PackageError("incomplete reviewed split Go SDK layout")

    return {
        "version": GO_WORKER_VERSIONS[target],
        "digest": digest(canonical({
            "format": "fortress-go-sdk-inventory-v1",
            "split_links": [[path, _DEBIAN_LINKS[path]] for path in sorted(split)],
            "files": sorted(entries, key=lambda entry: entry["path"]),
        })),
        "go_executable_digest": go_digest,
        "layout": "debian-go-1.22-split" if split else "ordinary",
        "files": len(entries),
        "bytes": total,
    }


def validate_selection(sdk, expected, editions):
    if not editions:
        if sdk is not None or expected is not None:
            raise PackageError("Go SDK selection needs one or more explicit worker editions")
        return
    if (sdk is None or not isinstance(expected, str) or not HEX.fullmatch(expected)
            or len(set(editions)) != len(editions) or any(edition not in WORKER_EDITIONS for edition in editions)):
        raise PackageError("select exact Go SDK, inventory digest and unique supported worker editions")


def stage_sources(project, work, ingredients):
    inputs = []
    for name in ingredients:
        logical = GO_WORKER_SOURCE_ROOT + name
        original = project / logical
        _, sha = hash_file(original, _SOURCE_LIMIT)
        copied = work / name
        shutil.copyfile(original, copied)
        if hash_file(copied, _SOURCE_LIMIT)[1] != sha:
            raise PackageError("Go worker source changed during bounded capture")
        inputs.append({"path": logical, "sha256": sha})
    return inputs


def stage_filesystem_library(work, sdk, target, executable, env, cache, owner, run_command):
    """Embed only the reviewed target's Go gc archives for the standard os importer."""
    raw = run_command(work, [str(executable), "list", "-p=1", "-trimpath", "-deps", "-export", "-json", "os"],
                      env, capture=True, workspace=owner, timeout_seconds=_TIMEOUT)
    if not 0 < len(raw) <= 1 << 20:
        raise PackageError("Go filesystem export listing outside its byte envelope")
    decoder = json.JSONDecoder()
    remaining = raw.decode("utf8").lstrip()
    rows = []
    while remaining:
        if len(rows) == _GO_EXPORT_ROWS:
            raise PackageError("Go filesystem export population exceeds its bound")
        _, boundary = decoder.raw_decode(remaining)
        rows.append(strict_json(remaining[:boundary].encode()))
        remaining = remaining[boundary:].lstrip()
    if any(row.get("Standard") is not True or row.get("Incomplete") is True
           or row.get("Error") or row.get("DepsErrors") for row in rows):
        raise PackageError("Go filesystem export listing contains incomplete or nonstandard packages")
    selected = [row for row in rows if row["ImportPath"] == "os"]
    standard, _ = sdk_directory(sdk, target, "src", sdk / "src")
    package = standard / "os"
    directories(package)
    if len(selected) != 1 or Path(selected[0]["Dir"]).resolve(strict=True) != package:
        raise PackageError("Go filesystem export listing has no exact selected os package")
    go_files = selected[0]["GoFiles"]
    if (not isinstance(go_files, list) or not 1 <= len(go_files) <= 128
            or any(not isinstance(name, str) or not name.endswith(".go")
                   or not _GO_PACKAGE_NAME.fullmatch(name[:-3]) for name in go_files)
            or len(go_files) != len(set(go_files))):
        raise PackageError("Go filesystem package source inventory is invalid")
    package_ref = "sha256:" + digest(canonical([
        [name, "sha256:" + hash_file(package / name, 1 << 20)[1]] for name in sorted(go_files)
    ]))
    archive_bytes, archives = 0, {}
    for row in rows:
        if not row.get("Export"):
            continue
        name, source = row["ImportPath"], Path(row["Export"])
        if (not isinstance(name, str) or len(name) > 180 or name in archives
                or any(not _GO_PACKAGE_NAME.fullmatch(part) for part in name.split("/"))
                or not source.is_absolute() or ".." in source.parts or not source.is_relative_to(cache)):
            raise PackageError("invalid or unowned Go filesystem archive member")
        directories(source.parent)
        size, reference = hash_file(source, _GO_ARCHIVE_BYTES)
        archive_bytes += size
        if not size or archive_bytes > _GO_EXPORT_BYTES:
            raise PackageError("Go filesystem archives exceed their byte envelope")
        destination = work / "exports" / (name + ".a")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with open_file(source) as original, destination.open("xb") as output:
            shutil.copyfileobj(original, output, 1 << 20)
        if hash_file(destination, _GO_ARCHIVE_BYTES) != (size, reference):
            raise PackageError("Go filesystem archive changed during ordinary capture")
        archives[name] = "sha256:" + reference
    export_ref = "sha256:" + digest(canonical([
        {"path": name, "sha256": reference} for name, reference in sorted(archives.items())
    ]))
    _, _, expected_package, expected_exports, expected_generated, expected_count, expected_bytes = GO_FILESYSTEM_PINS[target]
    if ("os" not in archives or (package_ref, export_ref, len(archives), archive_bytes)
            != (expected_package, expected_exports, expected_count, expected_bytes)):
        raise PackageError("Go filesystem selected package or archives differ from reviewed qualification")
    entries = ",\n".join(f"{json.dumps(name)}:{json.dumps(ref)}" for name, ref in sorted(archives.items()))
    program = (
        'package main\nimport "embed"\n//go:embed exports\nvar nativeExportFiles embed.FS\n'
        'var selectedNativeExports = includeSelectedNativeExports()\n'
        'func includeSelectedNativeExports() bool {\n'
        '    goFilesystemAssets = &goFilesystemLibrary{\n'
        f'        files: nativeExportFiles, sourceRef: {json.dumps(package_ref)}, '
        f'toolchain: {json.dumps(GO_WORKER_VERSIONS[target])},\n'
        f'        targetOS: {json.dumps(target.removesuffix("-x64"))}, targetArch: "amd64", '
        f'exports: map[string]string{{{entries},\n'
        '        },\n    }\n    return true\n}\n'
    ).encode("ascii")
    generated_ref = "sha256:" + digest(program)
    if generated_ref != expected_generated:
        raise PackageError("Go filesystem generated worker source differs from reviewed recipe")
    with (work / "go_fs_assets.go").open("xb") as staged:
        staged.write(program)
    owner.check_budget()
    return {"preparation": GO_FILESYSTEM_RECIPE, "package_source_ref": package_ref,
            "export_set_ref": export_ref, "generated_asset_ref": generated_ref,
            "export_count": len(archives), "export_bytes": archive_bytes}

def build_workers(project, sdk, expected, editions, target, source, owner, run_command):
    """Build the original optional Go attachment for existing preparation callers."""
    if GO_FILESYSTEM_EDITION in editions:
        raise PackageError("use the complete native artifact builder for filesystem workers")
    members, attachments = build_artifacts(project, sdk, expected, editions, target, source, owner, run_command)
    return members, attachments.get("native_go")


def build_artifacts(project, sdk, expected, editions, target, source, owner, run_command):
    """Stage exact binaries and provenance within the distribution's existing owner."""
    validate_selection(sdk, expected, editions)
    if not editions:
        return {}, {}

    tool = inspect_sdk(sdk, target, project)
    filesystem = GO_FILESYSTEM_EDITION in editions
    if filesystem and (tool["digest"], tool["go_executable_digest"]) != GO_FILESYSTEM_PINS[target][:2]:
        raise PackageError("Go filesystem worker requires the independently qualified SDK inventory")
    if tool["digest"] != expected:
        raise PackageError("Go SDK changed from the independently selected inventory")
    executable = sdk / ("bin/go.exe" if target == "windows-x64" else "bin/go")
    stage = owner.staging / "native-go"
    stage.mkdir()
    compiler = owner.target / "native-go"
    compiler.mkdir()
    for key in ("cache", "temp", "module-cache"):
        (compiler / key).mkdir()
    for key in ("home", "isolated-path"):
        (stage / key).mkdir()
    env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR") if key in os.environ}
    selected_environment = native_go_environment(target)
    env.update(selected_environment)
    env.update(GOROOT=str(sdk), GOCACHE=str(compiler / "cache"), GOTMPDIR=str(compiler / "temp"),
               GOMODCACHE=str(compiler / "module-cache"), GOPATH=str(stage / "home"),
               HOME=str(stage / "home"), USERPROFILE=str(stage / "home"),
               PATH=str(stage / "isolated-path"), TEMP=str(compiler / "temp"), TMP=str(compiler / "temp"),
               TMPDIR=str(compiler / "temp"))
    observed = run_command(stage, [str(executable), "version"], env, capture=True, workspace=owner,
                           timeout_seconds=15).decode("ascii").strip()
    if observed != f"go version {tool['version']} {selected_environment['GOOS']}/amd64":
        raise PackageError("the trusted Go tool does not match the requested native host")

    members, workers = {}, []
    for edition in sorted(edition for edition in editions if edition != GO_FILESYSTEM_EDITION):
        ingredients, protocols = GO_WORKERS[edition]
        work = stage / edition
        work.mkdir()
        inputs = stage_sources(project, work, ingredients)
        path = native_go_path(edition, target)
        binary = work / Path(path).name
        run_command(work, [str(executable), "build", *GO_WORKER_BUILD_FLAGS, "-o", binary.name, *ingredients],
                    env, workspace=owner, timeout_seconds=_TIMEOUT)
        size, sha = hash_file(binary, GO_WORKER_BYTES_LIMIT)
        with binary.open("rb") as stream:
            verify_machine(stream, target)
        members[path] = binary
        workers.append({"edition": edition, "path": path, "bytes": size, "sha256": sha,
                        "protocols": protocols, "sources": inputs})
        owner.check_budget()

    filesystem_worker = filesystem_library = filesystem_sources = None
    if filesystem:
        work = stage / GO_FILESYSTEM_EDITION
        work.mkdir()
        filesystem_sources = stage_sources(project, work, GO_FILESYSTEM_SOURCES)
        filesystem_library = stage_filesystem_library(
            work, sdk, target, executable, env, compiler / "cache", owner, run_command,
        )
        path = native_go_filesystem_path(target)
        binary = work / Path(path).name
        run_command(work, [str(executable), "build", *GO_WORKER_BUILD_FLAGS, "-o", binary.name,
                           *GO_FILESYSTEM_SOURCES, "go_fs_assets.go"],
                    env, workspace=owner, timeout_seconds=_TIMEOUT)
        size, sha = hash_file(binary, GO_WORKER_BYTES_LIMIT)
        with binary.open("rb") as stream:
            verify_machine(stream, target)
        filesystem_worker = {"path": path, "bytes": size, "sha256": sha}
        members[path] = binary
        owner.check_budget()

    notice_sources = ((Path("/usr/share/doc/golang-1.22-src/copyright"),)
                      if tool["layout"] == "debian-go-1.22-split"
                      else (sdk / "LICENSE", sdk / "PATENTS"))
    notices, filesystem_notices = [], []
    for source_path, member_path in zip(notice_sources, native_go_notice_paths(tool["layout"]), strict=True):
        directories(source_path.parent)
        size, sha = hash_file(source_path, GO_NOTICE_BYTES_LIMIT)
        destination = stage / Path(member_path).name
        shutil.copyfile(source_path, destination)
        if hash_file(destination, GO_NOTICE_BYTES_LIMIT) != (size, sha) or size == 0:
            raise PackageError("Go SDK notice changed during staging")
        if workers:
            members[member_path] = destination
            notices.append({"path": member_path, "bytes": size, "sha256": sha})
        if filesystem:
            member = next(path for path in native_go_filesystem_notices(tool["layout"])
                          if Path(path).name == destination.name)
            members[member] = destination
            filesystem_notices.append({"path": member, "bytes": size, "sha256": sha})

    recorded_sources = [item for worker in workers for item in worker["sources"]] + (filesystem_sources or [])
    if (inspect_sdk(sdk, target, project) != tool
            or any(hash_file(project / item["path"], _SOURCE_LIMIT)[1] != item["sha256"]
                   for item in recorded_sources)):
        raise PackageError("Go SDK or exact worker source changed before package publication")
    common = {
        "target": target, "source_commit": source[0], "source_fingerprint": source[1],
        "build_flags": GO_WORKER_BUILD_FLAGS, "environment": selected_environment, "sdk": tool,
    }
    attachments = {}
    if workers:
        attachments["native_go"] = common | {"format": GO_WORKER_FORMAT, "workers": workers, "notices": notices}
    if filesystem:
        attachments["native_go_filesystem"] = common | {
            "format": GO_FILESYSTEM_FORMAT, "worker": filesystem_worker, "sources": filesystem_sources,
            "notices": filesystem_notices, "library": filesystem_library,
        }
    return members, attachments
