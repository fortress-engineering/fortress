"""Stage the locked local development extension outside the repository."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile


def local_vsix(destination: Path) -> None:
    package = destination / "fortress-development.vsix"
    intermediate = destination / "vsce-output.vsix"
    (destination / ".vscodeignore").write_text(
        "_code/**\ntesting/**\nout/testing/**\npackage-lock.json\ntsconfig.json\n", encoding="utf-8", newline="\n"
    )
    subprocess.run(
        ["node", "node_modules/@vscode/vsce/vsce", "package", "--no-dependencies",
         "--allow-missing-repository", "--skip-license", "--out", intermediate.name],
        cwd=destination, check=True, timeout=90,
    )
    # The vendor packager supplies the VSIX manifest and contents. Only normalize
    # the archive envelope, whose original timestamps depend on the build host.
    with zipfile.ZipFile(intermediate) as source:
        entries = sorted(source.infolist(), key=lambda item: item.filename)
        if (len(entries) > 32 or len(source.namelist()) != len(set(source.namelist())) or
                sum(entry.file_size for entry in entries) > 1024**2):
            raise ValueError("VSIX exceeds the local package inventory limits")
        with zipfile.ZipFile(package, "x") as output:
            for entry in entries:
                if entry.is_dir():
                    continue
                fixed = zipfile.ZipInfo(entry.filename)
                fixed.create_system = 3
                fixed.external_attr = 0o100644 << 16
                output.writestr(fixed, source.read(entry))
    intermediate.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="new directory outside the project")
    parser.add_argument("--install-tools", action="store_true", help="restore locked npm tooling with lifecycle scripts disabled")
    parser.add_argument("--tools", type=Path, help="previously restored matching external tooling directory")
    parser.add_argument("--vsix", action="store_true", help="build a local development installation file")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    root = source.parent
    destination = args.destination.resolve()
    if destination.is_relative_to(root):
        parser.error("staging must remain outside project source")
    if args.install_tools == bool(args.tools):
        parser.error("select --install-tools or an already restored --tools directory")
    destination.mkdir()
    for authored, staged in (
        ("editor_manifest.json", "package.json"),
        ("npm_lock.json", "package-lock.json"),
        ("tsconfig.json", "tsconfig.json"),
    ):
        shutil.copyfile(source / "_data" / authored, destination / staged)
    for folder in ("_code", "testing/_code"):
        target = destination / folder
        target.mkdir(parents=True)
        for file in sorted((source / folder).glob("*.ts")):
            shutil.copyfile(file, target / file.name)
    readme = (source / "README.md").read_text(encoding="utf-8")
    readme = re.sub(r"\[([^\]]+)\]\(\.{1,2}/[^)]+\)", r"\1", readme)
    (destination / "README.md").write_text(readme, encoding="utf-8", newline="\n")
    if args.install_tools:
        npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        if not npm:
            parser.error("npm is required for explicit tool restoration")
        subprocess.run(
            [npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=destination, check=True, timeout=300,
        )
    else:
        tools = args.tools.resolve(strict=True)
        if tools.is_relative_to(root):
            parser.error("tooling must remain outside project source")
        for file in ("package.json", "package-lock.json"):
            if (tools / file).read_bytes() != (destination / file).read_bytes():
                parser.error("restored tooling does not match the pinned manifests")
        shutil.copytree(tools / "node_modules", destination / "node_modules")
    subprocess.run(
        ["node", "node_modules/typescript/bin/tsc", "-p", "tsconfig.json"],
        cwd=destination, check=True, timeout=90,
    )
    if args.vsix:
        local_vsix(destination)
    print(destination)


if __name__ == "__main__":
    main()
