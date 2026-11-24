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




class NativeWorkerPackageControls(unittest.TestCase):
    """Freeze independent attachment and entry expectations with no toolchain installed."""

    def setUp(self):
        self.storage = TemporaryDirectory()
        self.addCleanup(self.storage.cleanup)
        self.outer = Path(self.storage.name)
        self.archive = self.outer / "worker-transport.zip"
        self.target = installer.target_platform()
        self.windows = self.target == "windows-x64"
        self.worker = "bin/fortress-go-collector-v1" + (".exe" if self.windows else "")
        self.primary = "bin/fortress" + (".exe" if self.windows else "")
        self.header = (b"MZ" + bytes(58) + b"\x40\x00\x00\x00PE\x00\x00\x64\x86" if self.windows
                       else b"\x7fELF\x02\x01\x01" + bytes(11) + b"\x3e\x00" + bytes(44))

    def manifest(self, *, wrong_worker=False, editions=("v1",)):
        recipes = {
            "v1": (["collector.go"], ["observe-go-v1"]),
            "body-v1": (["collector.go", "go_body.go"], ["observe-go-v1", "lower-first-order-go-v1"]),
            "tests-v1": (["collector.go", "collector_build_context.go", "go_test_observer.go"],
                         ["observe-go-v1", "select-build-go-v2", "observe-go-tests-v1"]),
        }
        suffix = ".exe" if self.windows else ""
        worker_paths = {edition: "bin/fortress-go-collector-" + edition + suffix for edition in editions}
        notices = {"share/fortress/native/go/LICENSE.txt": b"fixture license",
                   "share/fortress/native/go/PATENTS.txt": b"fixture patent notice"}
        worker_bytes = b"foreign architecture" * 8 if wrong_worker else self.header
        sources = {**notices, self.primary: self.header, **dict.fromkeys(worker_paths.values(), worker_bytes)}
        with zipfile.ZipFile(self.archive, "x", allowZip64=False) as archive:
            for path, content in sources.items():
                archive.writestr(path, content)
        inventory = [
            {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(sources.items())
        ]
        member_by_path = {item["path"]: item for item in inventory}
        go_version = "go1.22.12" if self.windows else "go1.22.2"
        go_os = "windows" if self.windows else "linux"
        attachment = {
            "format": "fortress-native-go-workers-v1",
            "source_commit": "a" * 40, "source_fingerprint": "b" * 64, "target": self.target,
            "build_flags": ["-trimpath", "-buildvcs=false", "-p=1", "-ldflags=-buildid="],
            "environment": {
                "CGO_ENABLED":"0","GO111MODULE":"off","GOAMD64":"v1","GOARCH":"amd64",
                "GODEBUG":"gotypesalias=0","GOENV":"off","GOEXPERIMENT":"","GOFLAGS":"",
                "GOMAXPROCS":"2","GOOS":go_os,"GOPROXY":"off","GOSUMDB":"off","GOTOOLCHAIN":"local",
                "GOVCS":"*:off","GOWORK":"off",
            },
            "sdk": {"version":go_version, "digest":"c"*64, "go_executable_digest":"d"*64,
                    "layout":"ordinary", "files":4, "bytes":1234},
            "notices": [entry for entry in inventory if entry["path"] in notices],
            "workers": [
                {
                    **member_by_path[worker_paths[edition]], "edition": edition, "protocols": recipes[edition][1],
                    "sources": [{"path": "engine/program_semantics/_code/" + filename, "sha256": "e"*64}
                                for filename in recipes[edition][0]],
                }
                for edition in sorted(worker_paths)
            ],
        }
        return {
            "$schema": "urn:fortress:schema:v1:package-manifest",
            "schema_version": 1, "target":self.target, "product_version":"0.1.0",
            "archive_sha256": installer.hash_file(self.archive)[1],
            "archive_bytes": self.archive.stat().st_size,
            "source_commit":"a"*40, "source_fingerprint":"b"*64, "files":inventory,
            "build":{"native_go":attachment, "fixture":"transport"},
            "compatibility":{"query_protocols":[1,2,3,4,5]},
            "runtime":{"python":"optional for bundle verification"},
            "authenticity":"UNVERIFIED", "release_authorization":"NOT_ESTABLISHED",
        }

    def test_optional_worker_installs_as_executable_and_removes_by_inventory(self):
        raw = installer.canonical(self.manifest())
        store = self.outer / "store"
        slot = installer.install(self.archive, raw, store)
        self.assertEqual((slot / self.worker).read_bytes(), self.header)
        self.assertTrue(os.access(slot / self.worker, os.X_OK))
        owner_file = store / "personal.txt"
        owner_file.write_bytes(b"unrelated")
        installer.remove(store, slot.name, installer.digest(raw))
        self.assertFalse(slot.exists())
        self.assertEqual(owner_file.read_bytes(), b"unrelated")

    def test_reserved_member_requires_an_exact_bounded_attachment(self):
        manifest = self.manifest()
        attachment = manifest["build"].pop("native_go")
        with self.assertRaisesRegex(installer.PackageError, "has no known build attachment"):
            installer.verify(self.archive, installer.canonical(manifest))
        manifest["build"]["native_go"] = attachment
        for change in (
            ("source_commit", "0"*40),
            ("target", "macos-arm64"),
            ("build_flags", ["-toolexec", "unselected"]),
        ):
            field, value = change
            original = attachment[field]
            attachment[field] = value
            with self.assertRaisesRegex(installer.PackageError, "unsupported native Go worker build attachment"):
                installer.verify(self.archive, installer.canonical(manifest))
            attachment[field] = original

    def test_untrusted_sdk_edition_and_member_digest_are_refused(self):
        manifest = self.manifest()
        attachment = manifest["build"]["native_go"]
        edition = attachment["sdk"]["version"]
        attachment["sdk"]["version"] = "go1.99"
        with self.assertRaisesRegex(installer.PackageError, "unsupported native Go SDK binding"):
            installer.verify(self.archive, installer.canonical(manifest))
        attachment["sdk"]["version"] = edition
        attachment["workers"][0]["sha256"] = "0"*64
        with self.assertRaisesRegex(installer.PackageError, "differs from package membership"):
            installer.verify(self.archive, installer.canonical(manifest))

    def test_worker_machine_is_checked_even_when_catalog_hashes_agree(self):
        raw = installer.canonical(self.manifest(wrong_worker=True))
        with self.assertRaisesRegex(installer.PackageError, "architecture does not match target"):
            installer.verify(self.archive, raw)

    def test_body_and_test_workers_require_distinct_exact_recipes(self):
        manifest = self.manifest(editions=("tests-v1", "body-v1", "v1"))
        raw = installer.canonical(manifest)
        slot = installer.install(self.archive, raw, self.outer / "distinct")
        workers = manifest["build"]["native_go"]["workers"]
        self.assertEqual([worker["edition"] for worker in workers], ["body-v1", "tests-v1", "v1"])
        for worker in workers:
            self.assertTrue(os.access(slot / worker["path"], os.X_OK))
        self.assertEqual(sorted(path.relative_to(slot).as_posix() for path in slot.rglob("*") if path.is_file()),
                         sorted([item["path"] for item in manifest["files"]] + ["manifest.json"]))
        workers[0]["sources"][1]["path"] = "engine/program_semantics/_code/go_test_observer.go"
        with self.assertRaisesRegex(installer.PackageError, "invalid native Go source identity"):
            installer.verify(self.archive, installer.canonical(manifest))
        workers[0]["sources"][1]["path"] = "engine/program_semantics/_code/go_body.go"
        workers[1]["protocols"].append("lower-first-order-go-v1")
        with self.assertRaisesRegex(installer.PackageError, "unrecognized native Go worker recipe"):
            installer.verify(self.archive, installer.canonical(manifest))

    def test_worker_attachment_never_creates_host_registration(self):
        raw = installer.canonical(self.manifest())
        store = self.outer / "store"
        slot = installer.install(self.archive, raw, store)
        actual = sorted(
            str(path.relative_to(slot).as_posix())
            for path in slot.rglob("*") if path.is_file()
        )
        self.assertEqual(actual, sorted([self.primary, self.worker, "manifest.json",
                                          "share/fortress/native/go/LICENSE.txt",
                                          "share/fortress/native/go/PATENTS.txt"]))
        self.assertEqual(installer.parse_manifest(raw)["authenticity"], "UNVERIFIED")

if __name__ == "__main__":
    unittest.main()
