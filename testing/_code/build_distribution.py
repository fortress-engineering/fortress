"""Build an exact-source local Fortress archive through the existing storage owner."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "cli/_code"))
sys.path.insert(0, str(ROOT / "engine/snapshot_governance/_code"))
from execution_storage import RunWorkspace, StoragePolicy
from quality_certificate import repository_fingerprint, run_command, validate_control_artifact_registry
from package_install import SCHEMA, canonical, digest, executable_name, hash_file, target_platform, verify

SCHEMA_REGISTRY = "engine/standard_registry/_data/schema_manifest.json"
STANDARD = "engine/standard_registry/_data/standard_manifest.json"
VERIFIER = "testing/_code/verify_bundle.py"
INSTALLER = "cli/_code/package_install.py"
CARGO_LOCK = "_info/Cargo.lock"
NPM_LOCK = "editor/_data/npm_lock.json"
NODE = "v22.22.3"


def output(*command):
    return subprocess.check_output(command, cwd=ROOT, text=True, encoding="utf-8", timeout=45).strip()


def locked_environment(target):
    environment = os.environ.copy()
    for key in list(environment):
        if key.startswith(("CARGO_PROFILE_", "CARGO_TARGET_")) or key in {
            "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
        }:
            environment.pop(key)
    flags = [f"--remap-path-prefix={ROOT}=/fortress-source",
             f"--remap-path-prefix={target}=/fortress-target",
             f"--remap-path-prefix={Path(environment.get('CARGO_HOME', Path.home() / '.cargo')).resolve()}=/cargo"]
    if os.name == "nt":
        flags += ["-C", "link-arg=/Brepro"]
    environment.update(
        CARGO_TARGET_DIR=str(target), CARGO_RESOLVER_LOCKFILE_PATH=str(ROOT / CARGO_LOCK),
        CARGO_ENCODED_RUSTFLAGS="\x1f".join(flags), CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0",
        CARGO_PROFILE_RELEASE_STRIP="symbols", CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS="true",
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS="true", PYTHONDONTWRITEBYTECODE="1",
        # The editor invokes package entry points directly. npm bin links would
        # violate the execution workspace's ordinary-file inventory.
        npm_config_bin_links="false",
    )
    return environment


def source_assets():
    registry = json.loads((ROOT / SCHEMA_REGISTRY).read_bytes())
    standard = json.loads((ROOT / STANDARD).read_bytes())
    names = {*registry["schemas"], *standard["rules"], SCHEMA_REGISTRY, STANDARD,
             "engine/standard_registry/_data/compatibility_catalog_v1.json",
             "engine/standard_registry/_data/governance_profiles_v1.json",
             "engine/standard_registry/_data/application_assessment_policy_v1.json",
             "engine/standard_registry/_data/operation_summaries_v1.json",
             "engine/standard_registry/_data/cert_full_snapshot_v1.json",
             "engine/project_model/_data/filing_system_profiles.json"}
    names.update(f"engine/project_model/_data/control_layout_v{edition}.json" for edition in range(1, 9))
    return {f"share/fortress/{name}": ROOT / name for name in sorted(names)}


def package(path, members):
    records = []
    with zipfile.ZipFile(path, "x", allowZip64=False) as bundle:
        for name, source in sorted(members.items()):
            size, sha = hash_file(source)
            entry = zipfile.ZipInfo(name)
            entry.create_system = 3
            entry.external_attr = (0o100755 if name.startswith("bin/") else 0o100644) << 16
            entry.file_size = size
            with source.open("rb") as content, bundle.open(entry, "w") as member:
                shutil.copyfileobj(content, member, 1024 * 1024)
            records.append({"path":name, "bytes":size, "sha256":sha})
    return records


def workspace_inventory():
    data = tomllib.loads((ROOT/CARGO_LOCK).read_text(encoding="utf-8"))
    return canonical({"kind":"CARGO_WORKSPACE_LOCK_INVENTORY", "packages":[
        {key:row[key] for key in ("name","version","source","checksum") if key in row}
        for row in data["package"]
    ]})


def version_field(path, key):
    return json.loads((ROOT / path).read_bytes())[key]


def runtime_binding(executable):
    binding = {"build_os":platform.system(), "build_kernel_or_version":platform.version(),
               "verifier_python":"host-selected Python 3.11+ for offline bundle verification",
               "installation_python":"Python 3.11+ for the installer script",
               "workspace_certification":"registered native test execution requires a separate toolchain"}
    if os.name == "nt":
        return binding | {"system":"Windows x64 system libraries"}
    dynamic = output("readelf", "--dynamic", str(executable))
    versions = output("readelf", "--version-info", str(executable))
    return binding | {"system":"GNU C runtime and native system libraries",
                      "needed_libraries":sorted(set(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic))),
                      "glibc_symbols":sorted(set(re.findall(r"\bGLIBC_[0-9.]+\b", versions)))}


def build(destination, storage, checkout):
    if destination.is_relative_to(ROOT) or storage.is_relative_to(ROOT):
        raise ValueError("distribution destinations must be outside project source")
    if output("git", "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("a clean exact-source checkout is required")
    commit = output("git", "rev-parse", "HEAD")
    if checkout != commit:
        raise ValueError("requested source commit does not match this checkout")
    validate_control_artifact_registry(ROOT)
    source_fingerprint, _ = repository_fingerprint(ROOT)
    target = target_platform()
    toolchain = tomllib.loads((ROOT/"_data/rust_toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
    version = tomllib.loads((ROOT/"_data/Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    editor_version = version_field("editor/_data/editor_manifest.json", "version")
    if editor_version != version or output("node", "--version") != NODE:
        raise ValueError("workspace, extension or pinned Node version mismatch")
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if npm is None:
        raise ValueError("npm required for the locked extension build")
    rust = output("rustc", "+" + toolchain, "-vV")
    host = next(line.removeprefix("host: ") for line in rust.splitlines() if line.startswith("host: "))
    if host != {"windows-x64":"x86_64-pc-windows-msvc", "linux-x64":"x86_64-unknown-linux-gnu"}[target]:
        raise ValueError("the selected compiler does not match the native package target")
    destination.mkdir()
    policy = StoragePolicy.from_environment()
    if policy.retention != "cleanup-owned-compiler":
        raise ValueError("use cleanup-owned-compiler retention for independent builds")
    with RunWorkspace(ROOT, storage, policy) as owner:
        if any(path.name != "_owner.json" for path in owner.target.iterdir()):
            raise ValueError("independent build requires an empty compiler target")
        owner.record_preexisting(ROOT/"_data/Cargo.lock")
        env = locked_environment(owner.target)
        run_command(ROOT, ["cargo", "+"+toolchain, "--config", "_data/cargo_config.toml", "build",
                           "--manifest-path", "_data/Cargo.toml", "--locked", "--release",
                           "--all-features", "-p", "fortress-cli"], env, workspace=owner, timeout_seconds=7200)
        stage = owner.staging / "editor"
        run_command(ROOT, [sys.executable,"-B","editor/_code/build.py", str(stage),"--install-tools","--vsix"],
                    env, workspace=owner, timeout_seconds=600)
        # Cargo may hard-link the public executable to its dependency output.
        # Packages consume a separate ordinary file, leaving Cargo's layout intact.
        exe = owner.staging / executable_name(target)
        shutil.copyfile(owner.target / "release" / exe.name, exe)
        exe.chmod(0o755)
        version_line = subprocess.check_output([str(exe),"--version"], cwd=owner.staging, text=True, timeout=30).strip()
        if version_line != "fortress " + version:
            raise ValueError("built executable version differs from workspace version: " + version_line)
        inventory = owner.staging / "locked-dependencies.json"
        inventory.write_bytes(workspace_inventory())
        if (ROOT/VERIFIER).read_bytes() != (ROOT/"cli/_data/offline_verifier_v1.txt").read_bytes():
            raise ValueError("standalone and embedded verifier resources differ")
        vsix = destination / "fortress-development.vsix"
        shutil.copyfile(stage / vsix.name, vsix)
        archive = destination / f"fortress-{version}-{target}.zip"
        members = source_assets() | {
            "bin/" + exe.name:exe, "editor/" + vsix.name:vsix, "share/locked-dependencies.json":inventory,
            "share/verify_bundle.py":ROOT/VERIFIER, "share/install-guide.md":ROOT/"_docs/distribution.md",
        }
        files = package(archive, members)
        size, sha = hash_file(archive)
        manifest = {
            "$schema":SCHEMA, "schema_version":1, "product_version":version, "target":target,
            "source_commit":commit, "source_fingerprint":source_fingerprint.removeprefix("sha256:"),
            "archive_bytes":size,"archive_sha256":sha,"files":files,
            "build":{"toolchains":{"rust":rust.splitlines()[0],"cargo":output("cargo","+"+toolchain,"--version"),
                                    "node":NODE,"npm":output(npm,"--version"),"python":platform.python_version()},
                     "locks":{"cargo":hash_file(ROOT/CARGO_LOCK)[1],"npm":hash_file(ROOT/NPM_LOCK)[1]},
                     "target_triple":host,"profile":"release all-features assertions overflow checks stripped",
                     "path_mapping":"source, target and Cargo root remapped",
                     "completion":"BUILT_AND_INTEGRITY_CHECKED",
                     "qualification":"SEPARATELY_BOUND_INSTALLATION_RECEIPT",
                     "installer_sha256":hash_file(ROOT/INSTALLER)[1]},
            "runtime":runtime_binding(exe),
            "compatibility":{"standard_edition":version_field(STANDARD,"edition"),"query_protocols":[1,2,3,4,5],
                              "mcp_editions":["2025-06-18","2025-11-25"], "editor_version":editor_version,
                              "tested_editor_target":"VS Code Desktop 1.147.0",
                              "native_sdk":"registered public wire and verification schemas",
                              "semantic_scope":"bounded installed Rust analysis with explicit unsupported results"},
            "authenticity":"UNVERIFIED","release_authorization":"NOT_ESTABLISHED",
        }
        raw = canonical(manifest)
        verify(archive, raw)
        if repository_fingerprint(ROOT)[0] != source_fingerprint or output("git","rev-parse","HEAD") != commit:
            raise ValueError("source changed during packaging")
        shutil.copyfile(ROOT/INSTALLER,destination/"install.py")
        # Test driver is outside all installation payloads.
        shutil.copyfile(stage/"out/testing/_code/host.js",destination/"desktop_control.js")
        (destination/"manifest.json").write_bytes(raw)
        (destination/"manifest.sha256").write_text(digest(raw)+"\n",encoding="ascii",newline="\n")
        owner.publish("verified-local-distribution-build")
    print(digest(raw), destination, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination",type=Path)
    parser.add_argument("--storage",required=True,type=Path)
    parser.add_argument("--commit",required=True)
    args = parser.parse_args()
    build(args.destination.resolve(),args.storage.resolve(),args.commit)
