#!/usr/bin/env python3
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.
"""Stage the seven release assets locally; publish a path only after verification."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile


class StagingError(Exception):
    """Release inputs or staged bytes could not be verified."""


def require(condition, message):
    if not condition:
        raise StagingError(message)


def required_env(name):
    value = os.environ.get(name, "")
    require(bool(value) and "\n" not in value and "\r" not in value,
            f"{name} must be set to a single-line value.")
    return value


def regular_file(path):
    require(stat.S_ISREG(path.lstat().st_mode), f"Expected a regular non-symlink file: {path}")


def parse_manifest(data, names):
    # Validate every line and the complete allowlist before using any name as a
    # path. Accept precisely the six-entry format from generate-checksums.sh.
    lines = data.split(b"\n")
    require(len(lines) == 7 and lines[-1] == b"", "Expected six newline-terminated checksum entries.")
    checksums = {}
    for line in lines[:-1]:
        match = re.fullmatch(rb"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        require(match is not None, "Malformed checksum entry.")
        digest, name = (part.decode("ascii") for part in match.groups())
        require(name in names and name not in checksums, "Unexpected or duplicate checksum name.")
        checksums[name] = digest
    require(checksums.keys() == names, "Missing release checksum entries.")
    return checksums


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as payload:
        for block in iter(lambda: payload.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stage_assets(version, root, runner, output):
    # Match the existing generator/verifier filename convention, without shell
    # evaluation, normalization, or accepting path separators/display labels.
    require(re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", version) is not None, "Invalid release version.")
    require(runner.is_absolute() and runner.is_dir(), "RUNNER_TEMP must be an absolute existing directory.")
    require(output.is_absolute(), "GITHUB_OUTPUT must be an absolute regular file.")
    regular_file(output)
    assets = {
        f"cohctl-{version}-linux-amd64": root / "bin/linux/amd64/cohctl",
        f"cohctl-{version}-linux-arm64": root / "bin/linux/arm64/cohctl",
        f"cohctl-{version}-linux-386": root / "bin/linux/386/cohctl",
        f"cohctl-{version}-windows-amd64.exe": root / "bin/windows/amd64/cohctl.exe",
        f"cohctl-{version}-windows-arm64.exe": root / "bin/windows/arm64/cohctl.exe",
        "docs.zip": root / "build/_output/docs.zip",
    }
    manifest_name = f"cohctl-{version}-checksums.txt"
    manifest = root / manifest_name
    regular_file(manifest)
    manifest_bytes = manifest.read_bytes()
    checksums = parse_manifest(manifest_bytes, assets.keys())
    inputs = {**assets, manifest_name: manifest}
    for source in inputs.values():
        regular_file(source)
        require(not output.samefile(source), "GITHUB_OUTPUT must not alias a release input.")

    staged = Path(tempfile.mkdtemp(prefix="release-assets-", dir=runner))
    try:
        require("\n" not in str(staged) and "\r" not in str(staged), "Invalid staging output path.")
        for name, source in inputs.items():
            shutil.copyfile(source, staged / name)
        require((staged / manifest_name).read_bytes() == manifest_bytes, "Staged manifest bytes changed.")
        for name, digest in checksums.items():
            require(sha256(staged / name) == digest, f"Staged SHA-256 mismatch: {name}")
        # The manifest is the seventh asset, never an entry in its own list.
        with output.open("a", encoding="utf-8") as stream:
            stream.write(f"path={staged}\n")
    except BaseException:
        # Only this invocation's unique directory is owned by the helper.
        shutil.rmtree(staged)
        raise
    return staged


def main():
    stage_assets(required_env("RELEASE_VERSION"), Path.cwd(),
                 Path(required_env("RUNNER_TEMP")), Path(required_env("GITHUB_OUTPUT")))
    print("Release assets staged and verified.")


if __name__ == "__main__":
    try:
        main()
    except (StagingError, OSError) as error:
        print(f"Release asset staging failed: {error}", file=sys.stderr)
        sys.exit(1)
