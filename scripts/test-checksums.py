#!/usr/bin/env python3
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.
"""Hermetic checksum generator and public-release gate regression tests."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
VERSION = "1.10.15"
PLATFORMS = ("linux/amd64/cohctl", "linux/arm64/cohctl", "linux/386/cohctl",
             "windows/amd64/cohctl.exe", "windows/arm64/cohctl.exe")
NAMES = [f"cohctl-{VERSION}-{p.rsplit('/', 1)[0].replace('/', '-')}{'.exe' if p.endswith('.exe') else ''}"
         for p in PLATFORMS] + ["docs.zip"]


class Checksums(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.inputs = [self.bin / p for p in PLATFORMS] + [self.root / "docs.zip"]
        self.public = self.root / "public"
        self.public.mkdir()
        self.expected = ""
        for index, (path, name) in enumerate(zip(self.inputs, NAMES)):
            path.parent.mkdir(parents=True, exist_ok=True)
            data = f"distinct known fixture {index}\n".encode()
            path.write_bytes(data)
            (self.public / name).write_bytes(data)
            self.expected += f"{hashlib.sha256(data).hexdigest()}  {name}\n"
        self.output = self.root / "manifest.txt"
        self.temp = self.root / "temporary"
        self.temp.mkdir()
        self.env = dict(os.environ, TMPDIR=str(self.temp))

    def generate(self):
        return subprocess.run(["bash", str(SCRIPTS / "generate-checksums.sh"), VERSION,
                               str(self.bin), str(self.inputs[-1]), str(self.output)],
                              env=self.env, capture_output=True, text=True)

    def verify(self, manifest=None, public_manifest=None, fail_download=False):
        manifest = self.expected if manifest is None else manifest
        self.output.write_text(manifest)
        (self.public / f"cohctl-{VERSION}-checksums.txt").write_text(
            manifest if public_manifest is None else public_manifest)
        mock = self.root / "mock"
        mock.mkdir(exist_ok=True)
        (mock / "curl").write_text('''#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv[1:]
assert all(flag in args for flag in ['--retry', '--retry-all-errors', '--retry-max-time', '--connect-timeout', '--max-time'])
if os.environ['FAIL_DOWNLOAD'] == 'true': sys.exit(22)
shutil.copyfile(pathlib.Path(os.environ['PUBLIC']) / args[-1].rsplit('/', 1)[1], args[args.index('-o') + 1])
''')
        (mock / "curl").chmod(0o700)
        env = dict(self.env, PATH=f"{mock}:{os.environ['PATH']}", PUBLIC=str(self.public),
                   FAIL_DOWNLOAD=str(fail_download).lower())
        result = subprocess.run(["bash", str(SCRIPTS / "verify-release.sh"), VERSION, str(self.output)],
                                env=env, capture_output=True, text=True)
        self.assertEqual(list(self.temp.iterdir()), [], result.stderr)
        return result

    def test_known_values_exact_names_and_format(self):
        result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), self.expected)
        self.assertEqual(len(set(NAMES)), 6)
        self.assertEqual(list(self.root.glob("manifest.txt.tmp.*")), [])

    def test_each_missing_input_never_publishes_partial_manifest(self):
        for missing in self.inputs:
            data = missing.read_bytes()
            missing.unlink()
            for existing in (False, True):
                with self.subTest(missing=missing, existing=existing):
                    if existing:
                        self.output.write_text("preserve existing manifest\n")
                    result = self.generate()
                    self.assertNotEqual(result.returncode, 0)
                    if existing:
                        self.assertEqual(self.output.read_text(), "preserve existing manifest\n")
                        self.output.unlink()
                    else:
                        self.assertFalse(self.output.exists())
                    self.assertEqual(list(self.root.glob("manifest.txt.tmp.*")), [])
            missing.write_bytes(data)

    def test_hashing_failure_does_not_publish(self):
        mock = self.root / "mock"
        mock.mkdir()
        (mock / "sha256sum").write_text("#!/bin/bash\nexit 1\n")
        (mock / "sha256sum").chmod(0o700)
        self.env["PATH"] = f"{mock}:{os.environ['PATH']}"
        self.assertNotEqual(self.generate().returncode, 0)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob("manifest.txt.tmp.*")), [])

    def test_public_gate_checks_all_six_assets(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count(": OK"), 6)
        for name in NAMES:
            with self.subTest(corrupt=name):
                path = self.public / name
                data = path.read_bytes()
                path.write_bytes(b"corrupted download\n")
                self.assertNotEqual(self.verify().returncode, 0)
                path.write_bytes(data)

    def test_public_gate_rejects_metadata_and_download_failures(self):
        lines = self.expected.splitlines(keepends=True)
        invalid = ["", "".join(lines[1:]), lines[0] + self.expected,
                   self.expected.upper(), self.expected.replace("  ", " ", 1),
                   self.expected + "0" * 64 + "  ../outside\n"]
        for manifest in invalid:
            with self.subTest(manifest=manifest):
                self.assertNotEqual(self.verify(manifest=manifest).returncode, 0)
        self.assertNotEqual(self.verify(public_manifest=self.expected + "\n").returncode, 0)
        self.assertNotEqual(self.verify(fail_download=True).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
