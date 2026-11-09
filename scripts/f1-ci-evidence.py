#!/usr/bin/env python3
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.

"""Record exact hosted/local candidate and failure-artifact contents; no upload."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--finalize", action="store_true")
    parser.add_argument("--job-status", default="local-preparation")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    args.output_dir.mkdir(parents=True, exist_ok=True)
    sources = {}
    inventory = subprocess.check_output(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=root, timeout=20)
    scopes = ("cohctl/", "pkg/", "scripts/", "test/", ".github/workflows/", "java/", "templates/")
    for raw in sorted(set(inventory.split(b"\0")) - {b""}):
        name = raw.decode()
        path = root / name
        if path.is_file() and name.startswith(scopes):
            sources[name] = digest(path)
    for name in ("go.mod", "go.sum", "Makefile", ".golangci.yaml"):
        sources[name] = digest(root / name)
    sources = dict(sorted(sources.items()))

    def git(*words):
        return subprocess.check_output(["git", *words], cwd=root, timeout=20).decode(errors="replace")

    evidence = {"recorded_at": datetime.now(timezone.utc).isoformat(), "job_status": args.job_status,
                "source_files": sources, "source_map_sha256": hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                "head": git("rev-parse", "HEAD").strip(), "status": git("status", "--porcelain=v1"),
                "tracked_diff_sha256": hashlib.sha256(git("diff", "--binary", "HEAD").encode()).hexdigest(),
                "context": {key: os.environ[key] for key in ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_EVENT_NAME", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion", "F1_COHERENCE_VERSION", "F1_JAVA_VERSION") if key in os.environ},
                "scope": "source/binary/content capture only; local execution does not establish hosted upload"}
    if args.binary and args.binary.is_file():
        evidence["binary"] = {"path": str(args.binary), "length": args.binary.stat().st_size, "sha256": digest(args.binary)}
    name = "f1-final-candidate.json" if args.finalize else "f1-checkout.json"
    (args.output_dir / name).write_text(json.dumps(evidence, indent=2) + "\n")
    if args.finalize:
        # Exclude this manifest itself; all actual payload files are independently hashed.
        files = {path.relative_to(args.output_dir).as_posix(): {"length": path.stat().st_size, "sha256": digest(path)}
                 for path in sorted(args.output_dir.rglob("*")) if path.is_file() and path.name != "f1-artifact-manifest.json"}
        (args.output_dir / "f1-artifact-manifest.json").write_text(json.dumps({"files": files, "job_status": args.job_status,
                                                                          "overwrite": False, "retention_days": 14}, indent=2) + "\n")


if __name__ == "__main__":
    main()
