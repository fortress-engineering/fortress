"""Independent adversarial admission controls; no project code or network access."""
import importlib.util
import argparse
import json
from pathlib import Path
import struct
import subprocess
import os
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("boundary_consumer", Path(__file__).with_name("verify_bundle.py"))
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "engine/snapshot_governance/_code"))
import bounded_io
import security_qualification


class PublicBoundaryControls(unittest.TestCase):
    """Admission must precede potentially expanding library decoders."""

    def test_json_depth_is_admitted_before_tree_allocation(self):
        with mock.patch.object(consumer.json, "loads", side_effect=AssertionError("decoder reached")):
            with self.assertRaises(consumer.Invalid) as caught:
                consumer.parse(b"[" * 65 + b"0" + b"]" * 65)
        self.assertEqual(caught.exception.code, "RESOURCE_LIMIT")

    def test_json_node_budget_is_global_and_preallocation(self):
        with mock.patch.object(consumer, "MAX_JSON_NODES", 4):
            self.assertEqual(consumer.parse(b"[0,0,0]"), [0, 0, 0])
            with mock.patch.object(consumer.json, "loads", side_effect=AssertionError("decoder reached")):
                with self.assertRaises(consumer.Invalid) as caught:
                    consumer.parse(b"[0,0,0,0]")
            self.assertEqual(caught.exception.code, "RESOURCE_LIMIT")

    def test_quoted_delimiters_and_unicode_preserve_public_bytes(self):
        for data in [b'{"a":"[[[{}]]]","b":[true,null,1]}', '"\u00e9"'.encode(), b'{"a":"\\\"["}']:
            value = consumer.parse(data)
            self.assertEqual(consumer.parse(consumer.canonical(value)), value)

    def test_zip_inventory_admission_precedes_zipfile_allocation(self):
        with tempfile.TemporaryDirectory(prefix="fortress-boundary-") as root:
            path = Path(root) / "input.zip"
            path.write_bytes(struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 131, 131, 0, 0, 0))
            with mock.patch.object(consumer.zipfile, "ZipFile", side_effect=AssertionError("ZIP decoder reached")):
                with self.assertRaises(consumer.Invalid) as caught:
                    consumer.Reader(path)
            self.assertEqual(caught.exception.code, "RESOURCE_LIMIT")

    def test_unqualified_compression_is_rejected_without_expansion(self):
        with tempfile.TemporaryDirectory(prefix="fortress-boundary-") as root:
            path = Path(root) / "input.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_BZIP2) as archive:
                archive.writestr("manifest.json", b"{}")
            reader = None
            try:
                with self.assertRaises(consumer.Invalid) as caught:
                    reader = consumer.Reader(path)
                self.assertEqual(caught.exception.code, "UNSUPPORTED_ARCHIVE")
            finally:
                if reader:
                    reader.close()

    def test_zip_inventory_and_members_use_one_retained_container(self):
        with tempfile.TemporaryDirectory(prefix="fortress-boundary-") as root:
            path = Path(root) / "input.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("manifest.json", b"{}")
            with mock.patch.object(consumer.zipfile, "ZipFile", wraps=zipfile.ZipFile) as opened:
                reader = consumer.Reader(path)
                try:
                    self.assertEqual(reader.read("manifest.json"), b"{}")
                    self.assertEqual(opened.call_count, 1)
                finally:
                    reader.close()

    def test_archive_mutation_corpus_is_rejected_without_extraction(self):
        with tempfile.TemporaryDirectory(prefix="fortress-boundary-") as root:
            path = Path(root) / "input.zip"
            for payload in [b"", b"PK", b"prefix" + struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0),
                            struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 65535, 65535, 0, 0, 0),
                            struct.pack("<4s4H2LH", b"PK\x05\x06", 1, 1, 0, 0, 0, 0, 0)]:
                path.write_bytes(payload)
                with self.assertRaises(consumer.Invalid):
                    consumer.Reader(path)
            self.assertEqual(sorted(p.name for p in Path(root).iterdir()), ["input.zip"])

    def test_quote_and_escape_mutations_use_the_strict_decoder(self):
        seed = b'{"a":[true,false,null,1],"b":"\\\"["}'
        for index in range(len(seed)):
            for byte in [0, 34, 91, 125, 92, 255]:
                payload = seed[:index] + bytes([byte]) + seed[index + 1:]
                try:
                    parsed = consumer.parse(payload)
                except consumer.Invalid:
                    continue
                self.assertEqual(consumer.parse(consumer.canonical(parsed)), parsed)

    def test_member_path_and_case_ambiguity_are_rejected(self):
        for members in [["../manifest.json"], ["/manifest.json"], ["manifest.json", "MANIFEST.JSON"], ["artifacts/../manifest.json"]]:
            with tempfile.TemporaryDirectory(prefix="fortress-boundary-") as root:
                path = Path(root) / "input.zip"
                with zipfile.ZipFile(path, "w") as archive:
                    for member in members:
                        archive.writestr(member, b"{}")
                with self.assertRaises(consumer.Invalid):
                    consumer.Reader(path)

    def test_archive_resize_after_admission_invalidates_read(self):
        with tempfile.TemporaryDirectory(prefix="fortress-boundary-") as root:
            path = Path(root) / "input.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("manifest.json", b"{}")
            reader = consumer.Reader(path)
            try:
                with path.open("ab") as stream:
                    stream.write(b"drift")
                with self.assertRaises(consumer.Invalid) as caught:
                    reader.read("manifest.json")
                self.assertEqual(caught.exception.code, "INTEGRITY_ERROR")
            finally:
                reader.close()

    def test_operational_json_admission_precedes_decoder_and_rejects_duplicates(self):
        with mock.patch.object(bounded_io.json, "loads", side_effect=AssertionError("decoder reached")):
            for data in [b"[" * 97 + b"0" + b"]" * 97, b"[0,0,0,0,0]"]:
                with self.assertRaises(json.JSONDecodeError):
                    bounded_io.strict_json(data, nodes=5)
        for data in [b'{"id":1,"id":2}', b'{"x":1e999}', b'NaN', b'\xff']:
            with self.assertRaises((json.JSONDecodeError, UnicodeDecodeError)):
                bounded_io.strict_json(data)

    def test_operational_file_admission_rejects_before_oversized_read(self):
        with tempfile.TemporaryDirectory(prefix="fortress-boundary-") as root:
            path = Path(root) / "record.json"
            path.write_bytes(b"abc")
            with mock.patch.object(bounded_io.os, "open", side_effect=AssertionError("opened oversized input")):
                with self.assertRaises(OSError):
                    bounded_io.read_ordinary(path, 2)
            self.assertEqual(bounded_io.read_ordinary(path, 3), b"abc")

    def test_qualification_integrity_requires_exact_source_and_gate_manifest(self):
        source = "sha256:" + "a" * 64
        gates = ["FULL_PROFILE_CERTIFICATION", "SECURITY_BOUNDARIES", "WORKSPACE_TESTS"]
        controls = json.dumps(dict(schema_version=1, status="PASS", tests_run=15, failures=0, errors=0, skipped=0)).encode()
        record = security_qualification.compose(source, gates, controls, b"threat model")
        self.assertEqual(security_qualification.check(record, source, gates), record)
        with self.assertRaises(ValueError):
            security_qualification.check(record, "sha256:" + "b" * 64, gates)
        with self.assertRaises(ValueError):
            security_qualification.check(record, source, gates + ["OTHER"])
        record["authenticity"] = "VERIFIED"
        with self.assertRaises(ValueError):
            security_qualification.check(record, source, gates)

    def test_operational_inventory_bounds_collection_without_partial_success(self):
        with tempfile.TemporaryDirectory(prefix="fortress-boundary-") as root:
            for name in ["a", "b", "c", "d"]:
                (Path(root) / name).write_bytes(b"x")
            with self.assertRaises(OSError):
                bounded_io.inventory(root, set(), max_entries=3)
            with self.assertRaises(OSError):
                bounded_io.inventory(root, set(), max_files=3)
            self.assertEqual(bounded_io.inventory(root, set()), ["a", "b", "c", "d"])

    def test_operational_inventory_rejects_junctions_and_link_roots(self):
        with tempfile.TemporaryDirectory(prefix="fortress-boundary-") as base:
            root = Path(base) / "root"
            outside = Path(base) / "outside"
            root.mkdir()
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"preserve")
            link = root / "linked"
            if os.name == "nt":
                command = Path(os.environ["SystemRoot"]) / "System32/cmd.exe"
                subprocess.run([str(command), "/d", "/c", "mklink", "/J", str(link), str(outside)],
                               check=True, stdout=subprocess.DEVNULL, timeout=10)
            else:
                os.symlink(outside, link, target_is_directory=True)
            try:
                for path in [root, link]:
                    with self.assertRaises(OSError):
                        bounded_io.inventory(path, set())
                self.assertEqual(sentinel.read_bytes(), b"preserve")
            finally:
                if os.name == "nt":
                    os.rmdir(link)
                else:
                    link.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PublicBoundaryControls))
    if args.report:
        args.report.write_text(json.dumps({"schema_version": 1, "status": "PASS" if result.wasSuccessful() else "FAIL",
            "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped)},
            sort_keys=True) + "\n", encoding="utf-8")
    sys.exit(0 if result.wasSuccessful() else 1)
