"""Qualify the VSIX runtime with a real VS Code Desktop extension host."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import zipfile


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def sample(root: Path) -> None:
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "lib.rs").write_bytes(
        b'// unchanged file encoding\r\npub fn value() { let _ = std::fs::read("input"); }\r\n'
    )
    (root / "Cargo.toml").write_bytes(b'[package]\nname = "editor_fixture"\nversion = "0.1.0"\nedition = "2024"\n')
    root_id = "PF-EDITOR-FIXTURE"
    scope = "AF-EDITOR-FIXTURE-SCOPE-0001"
    policy = "_data/logical_modules/semantic_scope/contract.json"
    common: dict[str, object] = dict(provides=[], requires=[], relationships=[], constraints=[],
                                    guarantees=[], features=[], behavior=[])
    write_json(root / "contract.json", {
        "$schema": "urn:fortress:schema:v2:module-contract", "schema_version": 2,
        "id": root_id, "display_name": "Editor Fixture",
        "ecosystem": {"repository_grammar": 1, "standard": {
            "id": "STD-FORTRESS-ENGINEERING", "edition": "1.0.0-draft.2",
        }}, **common,
    })
    write_json(root / policy, {
        "$schema": "urn:fortress:schema:v3:module-contract", "schema_version": 3,
        "id": scope, "display_name": "Observed operations", **common,
        "semantic_policy": {
            "default": "UNDECLARED",
            "capabilities": {"allow": [], "deny": []},
            "effects": {"allow": [], "deny": ["filesystem.read"]},
        },
    })
    write_json(root / "__fortress" / ".fsconfig", {
        "$schema": "urn:fortress:schema:v4:project-configuration", "schema_version": 4,
        "observation_exclusions": [".git"], "assurance_profiles": [],
        "logical_modules": [{"module": scope, "contract": policy, "parent": root_id,
                             "bindings": [{"kind": "directory", "path": "src"}]}],
        "governance": {"default_layout": "native-logical-v1", "module_overrides": [],
                       "selected_profiles": [{"id": "GOV-FORTRESS-NATIVE", "version": "1.0.0",
                            "digest": "sha256:ac541bb1e1dd0f7f6ef6c8f1c1babcbe62c9a13cc507e74ad0058454baa7c475"}]},
    })


def extract_runtime(artifact: Path, destination: Path) -> None:
    destination.mkdir()
    with zipfile.ZipFile(artifact) as bundle:
        entries = bundle.infolist()
        assert len(entries) <= 40 and sum(entry.file_size for entry in entries) <= 1024**2
        for entry in entries:
            if not entry.filename.startswith("extension/") or entry.is_dir():
                continue
            mapped = PurePosixPath(entry.filename).parts[1:]
            assert mapped and all(part not in (".", "..") and ":" not in part and "\\" not in part for part in mapped)
            assert mapped[0] in ("package.json", "README.md", "readme.md", "out")
            if mapped[0] == "out":
                assert len(mapped) == 3 and mapped[1] == "_code" and mapped[2].endswith(".js")
            path = destination.joinpath(*mapped)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as output:
                output.write(bundle.read(entry))
    assert (destination / "out/_code/extension.js").is_file()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--editor", type=Path, required=True)
    parser.add_argument("--fortress", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--xvfb", action="store_true")
    parser.add_argument("--mode", choices=("both", "trusted", "restricted"), default="both")
    args = parser.parse_args()
    stage = args.stage.resolve(strict=True)
    results = args.results.resolve()
    root = Path(__file__).resolve().parents[3]
    assert not results.is_relative_to(root)
    results.mkdir()
    runtime = results / "extension"
    extract_runtime(stage / "fortress-development.vsix", runtime)
    environment = dict(os.environ, FORTRESS_EDITOR_TEST_EXECUTABLE=str(args.fortress.resolve(strict=True)))
    modes = ("trusted", "restricted") if args.mode == "both" else (args.mode,)
    for mode in modes:
        workspace = results / mode
        sample(workspace)
        if mode == "trusted":
            second = results / "other-repository"
            sample(second)
            (second / "src/lib.rs").write_bytes(b"pub fn independent() {}\n")
            project = results / "inspection.code-workspace"
            write_json(project, {"folders": [{"path": workspace.name}, {"path": second.name}]})
            workspace = project
        user_data = results / (mode + "-profile")
        write_json(user_data / "User/settings.json", {
            "workbench.startupEditor": "none", "security.workspace.trust.startupPrompt": "never",
            "security.workspace.trust.banner": "never", "extensions.autoUpdate": False,
            "update.mode": "none", "telemetry.telemetryLevel": "off", "chat.disableAIFeatures": True,
            "git.enabled": False, "extensions.autoCheckUpdates": False,
        })
        report = results / (mode + ".json")
        environment["FORTRESS_EDITOR_TEST_REPORT"] = str(report)
        environment["FORTRESS_EDITOR_TEST_RESTRICTED"] = "1" if mode == "restricted" else "0"
        params = [
            str(args.editor.resolve(strict=True)), str(workspace),
            "--extensionDevelopmentPath=" + str(runtime),
            "--extensionTestsPath=" + str(stage / "out/testing/_code/host.js"),
            "--user-data-dir=" + str(user_data), "--extensions-dir=" + str(results / "extensions"),
            "--disable-extensions", "--disable-gpu", "--skip-welcome", "--skip-release-notes",
        ]
        if mode == "trusted":
            params.append("--disable-workspace-trust")
        if args.xvfb:
            xvfb = shutil.which("xvfb-run")
            assert xvfb
            params = [xvfb, "-a", *params]
        with (results / (mode + ".log")).open("xb") as log:
            subprocess.run(params, cwd=results, env=environment, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=480)
        assert json.loads(report.read_bytes())["status"] == "PASS"
    print(results)


if __name__ == "__main__":
    main()
