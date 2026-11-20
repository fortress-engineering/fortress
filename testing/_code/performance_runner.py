"""Bounded diagnostic workloads over an explicitly identified prebuilt observer.

No build, provider execution, repository initialization or onboarding is implicit.
Synthetic scaling is PSM-only; governed end-to-end workloads use an explicit root.
Numerical results never replace canonical qualification or independent corpora.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
from dataclasses import replace
import os
from pathlib import Path
import platform
import re
import stat
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine/snapshot_governance/_code"))
sys.path.insert(0, str(Path(__file__).parent))
import quality_certificate as quality
from bounded_io import hash_ordinary, inventory, read_ordinary, strict_json
from execution_storage import RunWorkspace, StoragePolicy
from heavy_admission import DirectoryIdentity
from performance_qualification import workload_manifest

MAX_WORKLOAD_SOURCE_BYTES = 64 * 1024**2
NATIVE_WORKLOAD_DOMAIN = "NATIVE_WORKLOAD_INVENTORY_V1"

def native_workload_identity(root):
    """Bind ordinary source without assuming project configuration authority."""
    paths = inventory(root, {".git"})
    if not paths:
        raise ValueError("EMPTY_WORKLOAD_INVENTORY")
    identity = hashlib.sha256(NATIVE_WORKLOAD_DOMAIN.encode("ascii") + b"\n")
    remaining = MAX_WORKLOAD_SOURCE_BYTES
    for relative in paths:
        length, content = hash_ordinary(root / relative, remaining)
        remaining -= length
        row = json.dumps([relative, length, content], ensure_ascii=False, separators=(",", ":"))
        identity.update(row.encode("utf-8") + b"\n")
    return ("sha256:" + identity.hexdigest(), len(paths))

def generate_fixture(root, workload):
    """Create only new disposable source; never governance or project permissions."""
    if type(workload.get("functions")) is not int or not 1 <= workload["functions"] <= 50000 or workload.get("lines_per_function") != 20 or workload.get("functions_per_file") != 25:
        raise ValueError("INVALID_WORKLOAD_BOUND")
    root.mkdir()
    source = root / "src"
    source.mkdir()
    manifest = "[package]\nname='performance_fixture'\nversion='0.1.0'\nedition='2024'\n"
    (root / "Cargo.toml").write_text(manifest, encoding="utf-8", newline="\n")
    lines, total = manifest.count("\n"), len(manifest.encode())
    modules = []
    for offset in range(0, workload["functions"], 25):
        name = f"unit_{offset // 25:06}"
        modules.append(f"pub mod {name};\n")
        rows = []
        for index in range(offset, min(offset + 25, workload["functions"])):
            rows.append(f"pub fn item_{index:06}(value: u64) -> u64 {{\n")
            rows.extend("    let value = value + 1;\n" for _ in range(17))
            rows.extend(["    value\n", "}\n"])
        text = "".join(rows)
        total += len(text.encode())
        lines += text.count("\n")
        if total > MAX_WORKLOAD_SOURCE_BYTES:
            raise ValueError("RESOURCE_LIMIT: synthetic source bytes")
        (source / (name + ".rs")).write_text(text, encoding="utf-8", newline="\n")
    text = "".join(modules)
    (source / "lib.rs").write_text(text, encoding="utf-8", newline="\n")
    return {"source_bytes": total + len(text.encode()), "lines_including_cargo_and_module_declarations": lines + text.count("\n"), "functions": workload["functions"], "scope": "PSM_ONLY_UNGOVERNED_ANALYSIS", "initialization": "NOT_PERFORMED"}


def distribution(samples):
    """Nearest-rank diagnostic percentiles; never infer a p99 from ten samples."""
    if not samples or len(samples) > 10000 or any(type(x) is not int or not 0 <= x <= 9007199254740991 for x in samples):
        raise ValueError("INVALID_TIMING_SAMPLES")
    values = sorted(samples)
    result = {"samples": len(values), "minimum_ns": values[0], "maximum_ns": values[-1], "p50_ns": values[(len(values) + 1) // 2 - 1]}
    if len(values) >= 20:
        result["p95_ns"] = values[(len(values) * 95 + 99) // 100 - 1]
    if len(values) >= 100:
        result["p99_ns"] = values[(len(values) * 99 + 99) // 100 - 1]
    return result


def ordinary_external(path, root):
    if ".." in Path(path).parts:
        raise ValueError("UNSAFE_PATH: parent traversal")
    absolute = Path(path).absolute()
    for parent in (absolute.parent, *absolute.parent.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("UNSAFE_PATH: linked external ancestor")
    if absolute.resolve().is_relative_to(root.resolve()):
        raise ValueError("UNSAFE_PATH: output or executable must be external")
    return absolute


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--storage-root", required=True, type=Path)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--root", type=Path)
    choice.add_argument("--workload")
    parser.add_argument("--manifest", type=Path, default=ROOT / "testing/_data/performance_workloads.json")
    parser.add_argument("--timeout-seconds", type=int, default=14400)
    parser.add_argument("--accounted-bytes", type=int, default=16 * 1024**3)
    parser.add_argument("--warm-evaluations", type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 86400 or not 0 <= args.warm_evaluations <= 10 or not 1 <= args.accounted_bytes <= 64 * 1024**3:
        parser.error("bounded operational duration, samples and accounting are required")
    output = ordinary_external(args.output_dir, ROOT)
    if args.root:
        ordinary_external(output, args.root)
    if not args.executable.is_absolute():
        parser.error("the prebuilt executable must be an absolute host path")
    output.mkdir()
    source = args.root.resolve() if args.root else output / "subject"
    manifest = workload_manifest(read_ordinary(args.manifest, 64 * 1024))
    preparation = None
    if args.workload:
        matches = [w for w in manifest["workloads"] if w["id"] == args.workload]
        if len(matches) != 1:
            raise ValueError("UNKNOWN_WORKLOAD")
        started = time.monotonic_ns()
        preparation = generate_fixture(source, matches[0])
        preparation["generation_wall_time_ns"] = time.monotonic_ns() - started
    executable = ordinary_external(args.executable, source)
    if not executable.is_absolute() or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.expected_digest) or hash_ordinary(executable, 256 * 1024**2)[1] != args.expected_digest:
        raise ValueError("UNBOUND_EXECUTABLE")
    identify_source = native_workload_identity if args.workload else quality.repository_fingerprint
    before = identify_source(source)
    pin = DirectoryIdentity(source)
    supervisor = output / "supervisor"
    supervisor.mkdir()
    args.storage_root = ordinary_external(args.storage_root, source)
    ordinary_external(args.storage_root, ROOT)
    observations = []
    context = {
        "format": "source-bound-performance-run-v1",
        "numeric_certification": False,
        "host": {"os": platform.platform(), "python": platform.python_version(),
                 "architecture": platform.machine(), "cpu_count": os.cpu_count()},
        "tool_digest": args.expected_digest,
        "workload_source_before": before,
        "workload_source_domain": NATIVE_WORKLOAD_DOMAIN if args.workload else "QUALITY_CERTIFICATE_SOURCE_FINGERPRINT",
        "preparation": preparation,
        "scope": "PSM_ONLY" if args.workload else "GOVERNED_RESIDENT_AND_CANDIDATE",
        "timeout_seconds": args.timeout_seconds,
        "resident_accounted_limit": args.accounted_bytes,
        "accounting_is_not_process_rss": True,
    }
    try:
        policy = replace(StoragePolicy.from_environment(), retention="cleanup-owned-compiler")
        with RunWorkspace(supervisor, args.storage_root, policy) as work:
            runtime = ordinary_external(args.runtime_root or args.storage_root / "runtime", source)
            ordinary_external(runtime, ROOT)
            runtime.mkdir(exist_ok=True)
            for number in range(2 if args.workload else 1):
                report = output / f"observation-{number}.json"
                command = [str(executable), str(source), str(runtime), str(report), "psm" if args.workload else "resident", str(args.accounted_bytes), str(args.warm_evaluations)]
                quality.run_command(source, command, os.environ.copy(), workspace=work, timeout_seconds=args.timeout_seconds)
                result = strict_json(read_ordinary(report, 2 * 1024**2), maximum=2 * 1024**2)
                observations.append(result)
                if not pin.matches(source) or identify_source(source) != before or hash_ordinary(executable, 256 * 1024**2)[1] != args.expected_digest:
                    raise ValueError("SOURCE_OR_TOOL_DRIFT")
            if args.workload and observations[0]["psm_digest"] != observations[1]["psm_digest"]:
                raise ValueError("INDEPENDENT_COLD_MISMATCH")
        context["outcome"] = "OBSERVATIONS_COMPLETE_NO_NUMERICAL_CERTIFICATION"
    except BaseException as error:
        context.update(outcome="INCOMPLETE_NO_QUALIFICATION_CLAIM", error=str(error))
        raise
    finally:
        try:
            context["workload_source_after"] = identify_source(source)
            if not pin.matches(source) or context["workload_source_after"] != before:
                raise ValueError("SOURCE_DRIFT: final workload identity")
        except (OSError, ValueError, quality.CertificateError) as error:
            context.update(outcome="INCOMPLETE_NO_QUALIFICATION_CLAIM", final_identity_error=str(error))
            raise
        finally:
            pin.close()
            context["observations"] = observations
            (output / "run.json").write_text(json.dumps(context, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
