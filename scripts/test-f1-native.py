#!/usr/bin/env python3
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.

"""Execute native F1 package/race/console checks and retain raw command evidence.

No host provisioning, connection, privilege change, or remote mutation. Use an
assigned host and a task-owned scratch directory. A skipped capability is UNRUN.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import time

import f1_platform as native
import f1_process_guard as guard


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch-dir", type=Path, required=True)
    parser.add_argument("--require-no-handle", action="store_true", help="fail qualification when the actual Linux no-handle test skips")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    scratch = args.scratch_dir.resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    assert not any(scratch.iterdir()), "native output directory must be empty and task-owned"
    env = dict(os.environ, GOCACHE=str(scratch / "go-cache"), GOTMPDIR=str(scratch / "tmp"),
               TMPDIR=str(scratch / "tmp"), TMP=str(scratch / "tmp"), TEMP=str(scratch / "tmp"), GOTOOLCHAIN="local")
    (scratch / "tmp").mkdir()
    evidence = {"platform": native.identity(), "commands": [], "status": "RUNNING", "skips": []}

    def run(name, argv, timeout=240):
        started = time.monotonic()
        with (scratch / (name + ".stdout")).open("wb") as out, (scratch / (name + ".stderr")).open("wb") as err:
            record = guard.run_owned(argv, root, env, out, err, timeout, scratch / (name + ".guard.json"))
        record.update(name=name, elapsed=time.monotonic() - started)
        evidence["commands"].append(record)
        assert record["exit"] == 0 and record["guardian_exit"] == 0 and not record["rescue"] and not record["remaining_owned"] and not record["errors"], record
        return (scratch / (name + ".stdout")).read_text(errors="replace")

    try:
        evidence["containment_backend"] = guard.backend()
        run("containment-controls", [os.sys.executable, str(root / "scripts" / "test-f1-process-guard.py"), "--require-native"], 120)
        evidence["go_version"] = run("go-version", ["go", "version"])
        evidence["go_env"] = json.loads(run("go-env", ["go", "env", "-json", "GOOS", "GOARCH", "GOVERSION", "CGO_ENABLED"]))
        assert evidence["go_env"]["GOOS"] == {"Linux": "linux", "Windows": "windows", "Darwin": "darwin"}[platform.system()], "cross build is not native execution"
        architecture = {"aarch64": "arm64", "arm64": "arm64", "AMD64": "amd64", "x86_64": "amd64"}.get(platform.machine())
        assert architecture and evidence["go_env"]["GOARCH"] == architecture, "native architecture mismatch"
        for name, extra in (("package", []), ("race", ["-race"])):
            output = run(name, ["go", "test", *extra, "./pkg/...", "-count=1", "-timeout=180s", "-json"], 600)
            events = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
            evidence["skips"] += [{"suite": name, **event} for event in events if event.get("Action") == "skip" and event.get("Test")]
            passed = {event.get("Test") for event in events if event.get("Action") == "pass"}
            required = {"TestManagementObserverNativeNonChild", "TestManagementObserverNativeExitedRace",
                        "TestManagementRestartBarrier", "TestManagementCleanup", "TestManagementStop", "TestManagementCancellation"}
            # Prefix groups contain several tests. Require actual selected events.
            for prefix in required:
                assert any(test and test.startswith(prefix) for test in passed), (name, "required group not executed", prefix)
            if platform.system() == "Linux":
                assert "TestManagementSignalExecutable" in passed and "TestManagementObserverLinuxZombie" in passed
                if args.require_no_handle:
                    assert "TestManagementObserverLinuxNoHandle" in passed, "UNRUN actual no-handle branch"
            if os.name == "nt":
                assert "TestManagementStopWindowsExitClassification" in passed
                assert "TestManagementWindowsNativePermissionFailure" in passed
        suffix = ".exe" if os.name == "nt" else ""
        binary = scratch / ("cohctl" + suffix)
        run("build", ["go", "build", "-trimpath", "-buildvcs=false", "-o", str(binary), "./cohctl"], 300)
        evidence["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        if os.name == "nt":
            fixture = scratch / "f1-windows.exe"
            run("build-console-fixture", ["go", "build", "-trimpath", "-o", str(fixture), "./scripts/fixtures/f1-windows"], 300)
            run("console", [os.sys.executable, str(root / "scripts" / "test-windows-console.py"), "--cli", str(binary),
                            "--fixture", str(fixture), "--scratch-dir", str(scratch / "tmp"), "--output", str(scratch / "console.json")], 600)
        evidence["status"] = "PASS with explicit capability gaps" if evidence["skips"] else "PASS"
    except BaseException as error:
        evidence["status"], evidence["failure"] = "FAIL", repr(error)
        raise
    finally:
        (scratch / "native-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
