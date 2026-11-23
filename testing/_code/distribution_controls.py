"""Independent controls for the portable package and installed-file boundary."""
import hashlib
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "cli/_code"))
import package_install as installer


def fixture(path, replacements=(), target=None, guide=b"fixture documentation", version="0.1.0", machine=True):
    host = target or installer.target_platform()
    if host == "windows-x64":
        header = b"MZ" + bytes(58) + b"\x40\x00\x00\x00PE\x00\x00\x64\x86"
    else:
        header = b"\x7fELF\x02\x01\x01" + bytes(11) + b"\x3e\x00" + bytes(44)
    files = {"bin/" + installer.executable_name(host):header if machine else b"mismatched executable",
             "share/guide.txt": guide}
    with zipfile.ZipFile(path, "x") as bundle:
        for name, data in [*files.items(), *replacements]:
            bundle.writestr(name, data)
    records = [{"path": name, "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()} for name, data in sorted(files.items())]
    manifest = {"schema_version":1, "$schema":installer.SCHEMA, "product_version":version,
                "target":host,
                "archive_sha256":installer.hash_file(path)[1], "archive_bytes":path.stat().st_size,
                "source_commit":"a"*40, "source_fingerprint":"b"*64, "files":records,
                "build":{"toolchains":{"rust":"fixture"},"locks":{"cargo":"c"*64}},
                "compatibility":{"query_protocols":[1,2,3,4,5]},
                "runtime":{"python":"optional for bundle verification"},
                "authenticity":"UNVERIFIED", "release_authorization":"NOT_ESTABLISHED"}
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


class InstallationControls(unittest.TestCase):
    def setUp(self):
        self.storage = TemporaryDirectory()
        self.addCleanup(self.storage.cleanup)
        self.outer = Path(self.storage.name)
        self.root = self.outer / "User space — 合"
        self.package = self.outer / "package.zip"

    def test_idempotence_exact_uninstall_and_unrelated_bytes(self):
        stamp = fixture(self.package)
        owned = installer.install(self.package, stamp, self.root)
        self.assertEqual(owned, installer.install(self.package, stamp, self.root))
        other = self.root / "personal.txt"
        other.write_bytes(b"user")
        installer.remove(self.root, owned.name, installer.digest(stamp))
        self.assertEqual(other.read_bytes(), b"user")
        self.assertFalse(owned.exists())

    def test_refuses_unrelated_or_changed_installed_files(self):
        stamp = fixture(self.package)
        owned = installer.install(self.package, stamp, self.root)
        extra = owned / "unrelated.txt"
        extra.write_bytes(b"unrelated")
        with self.assertRaises(installer.PackageError):
            installer.remove(self.root, owned.name, installer.digest(stamp))
        self.assertEqual(extra.read_bytes(), b"unrelated")
        self.assertTrue((owned / "bin" / installer.executable_name()).exists())

    def test_never_extracts_unsafe_or_unlisted_names(self):
        stamp = fixture(self.package, [("../escape", b"bad"), ("Bin/alias", b"bad")])
        with self.assertRaises(installer.PackageError):
            installer.install(self.package, stamp, self.root)
        self.assertFalse(self.outer.joinpath("escape").exists())

    def test_mismatched_platform_and_tamper_are_rejected(self):
        stamp = fixture(self.package, target="macos-arm64")
        with self.assertRaises(installer.PackageError):
            installer.install(self.package, stamp, self.root)
        self.assertFalse(self.root.exists())
        self.package.unlink()
        stamp = fixture(self.package)
        with self.package.open("ab") as stream:
            stream.write(b"tampered")
        with self.assertRaises(installer.PackageError):
            installer.install(self.package, stamp, self.root)
        self.assertFalse(self.root.exists())

    def test_same_version_replacement_and_unknown_relation(self):
        first = fixture(self.package)
        old = installer.install(self.package, first, self.root)
        self.package.unlink()
        second = fixture(self.package, guide=b"new build")
        new = installer.install(self.package, second, self.root, (old.name, installer.digest(first)))
        self.assertNotEqual(old, new)
        self.assertTrue(old.exists())
        self.package.unlink()
        third = fixture(self.package, version="0.2.0")
        with self.assertRaises(installer.PackageError):
            installer.install(self.package, third, self.root, (new.name, installer.digest(second)))

    def test_resume_removal_and_preserve_independent_files(self):
        stamp = fixture(self.package)
        owned = installer.install(self.package, stamp, self.root)
        pending = owned.rename(owned.with_name(".removing-"+owned.name))
        (pending/"share/guide.txt").unlink()
        installer.remove(self.root, owned.name, installer.digest(stamp))
        self.assertFalse(pending.exists())

    def test_reject_wrong_machine_even_with_valid_manifest(self):
        stamp = fixture(self.package, machine=False)
        with self.assertRaises(installer.PackageError):
            installer.install(self.package, stamp, self.root)
        self.assertFalse(self.root.exists())

    def test_failed_staging_never_publishes_an_installation(self):
        stamp = fixture(self.package)
        with patch.object(installer, "verify_members", side_effect=OSError("fixture interruption")):
            with self.assertRaises(OSError):
                installer.install(self.package, stamp, self.root)
        self.assertFalse(any(path.name.startswith("fortress-") for path in self.root.iterdir()))
        self.assertTrue(installer.install(self.package, stamp, self.root).exists())

    def test_hardlinked_or_governed_destination_is_never_removed(self):
        stamp = fixture(self.package)
        owned = installer.install(self.package, stamp, self.root)
        target = self.outer / "different-owner.txt"
        target.write_bytes(b"fixture documentation")
        member = owned / "share/guide.txt"
        member.unlink()
        os.link(target, member)
        with self.assertRaises(installer.PackageError):
            installer.remove(self.root, owned.name, installer.digest(stamp))
        self.assertEqual(target.read_bytes(), b"fixture documentation")
        governed = self.outer / "project"
        (governed / "__fortress").mkdir(parents=True)
        with self.assertRaises(installer.PackageError):
            installer.install(self.package, stamp, governed/"installed")
        self.assertFalse((governed/"installed").exists())


if __name__ == "__main__":
    unittest.main()
