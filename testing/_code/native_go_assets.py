"""Build optional Fortress Go workers from a pinned external native SDK."""

from __future__ import annotations

import os
from pathlib import Path
import shutil

from package_install import (
    GO_NOTICE_BYTES_LIMIT, GO_SDK_BYTES_LIMIT, GO_SDK_FILES_LIMIT, GO_WORKER_BUILD_FLAGS, GO_WORKER_BYTES_LIMIT,
    GO_WORKER_FORMAT, GO_WORKER_SOURCE_ROOT, GO_WORKER_VERSIONS, GO_WORKERS, HEX,
    PackageError, canonical, digest, directories, hash_file, native_go_environment, native_go_path,
    native_go_notice_paths, ordinary, verify_machine,
)

_MAX_PATH_BYTES = 512
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
            or len(set(editions)) != len(editions) or any(edition not in GO_WORKERS for edition in editions)):
        raise PackageError("select exact Go SDK, inventory digest and unique supported worker editions")


def build_workers(project, sdk, expected, editions, target, source, owner, run_command):
    """Stage exact binaries and provenance within the distribution's existing owner."""
    validate_selection(sdk, expected, editions)
    if not editions:
        return {}, None

    tool = inspect_sdk(sdk, target, project)
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
    for edition in sorted(editions):
        ingredients, protocols = GO_WORKERS[edition]
        work = stage / edition
        work.mkdir()
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

    notice_sources = ((Path("/usr/share/doc/golang-1.22-src/copyright"),)
                      if tool["layout"] == "debian-go-1.22-split"
                      else (sdk / "LICENSE", sdk / "PATENTS"))
    notices = []
    for source_path, member_path in zip(notice_sources, native_go_notice_paths(tool["layout"]), strict=True):
        directories(source_path.parent)
        size, sha = hash_file(source_path, GO_NOTICE_BYTES_LIMIT)
        destination = stage / Path(member_path).name
        shutil.copyfile(source_path, destination)
        if hash_file(destination, GO_NOTICE_BYTES_LIMIT) != (size, sha) or size == 0:
            raise PackageError("Go SDK notice changed during staging")
        members[member_path] = destination
        notices.append({"path": member_path, "bytes": size, "sha256": sha})

    if (inspect_sdk(sdk, target, project) != tool
            or any(hash_file(project / item["path"], _SOURCE_LIMIT)[1] != item["sha256"]
                   for worker in workers for item in worker["sources"])):
        raise PackageError("Go SDK or exact worker source changed before package publication")
    return members, {
        "format": GO_WORKER_FORMAT, "target": target,
        "source_commit": source[0], "source_fingerprint": source[1],
        "build_flags": GO_WORKER_BUILD_FLAGS, "environment": selected_environment,
        "sdk": tool, "workers": workers, "notices": notices,
    }
