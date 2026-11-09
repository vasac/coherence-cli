#!/usr/bin/env python3
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.

"""One bounded JSON request on an explicitly assigned F1 peer. No shell/server."""

import argparse
import hashlib
import ipaddress
import json
import os
import platform
from pathlib import Path
import signal
import socket
import subprocess
import sys
import urllib.request

from f1_platform import identity


def exchange(query, allowed_host, classes, java):
    assert query["protocol"] == 1 and isinstance(query["nonce"], str) and len(query["nonce"]) == 32
    result = {"protocol": 1, "nonce": query["nonce"], "identity": identity(), "hostname": platform.node()}
    for label, path in (("agent", Path(__file__)), ("adapter", Path(__file__).with_name("f1_platform.py")),
                        ("probe_source", Path(__file__).with_name("ManagementProbe.java"))):
        result[label + "_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    if classes:
        result["probe_class_sha256"] = hashlib.sha256((classes / "ManagementProbe.class").read_bytes()).hexdigest()
    if query["operation"] == "identity":
        return result
    assert query["operation"] == "probe" and query["host"] == allowed_host
    host = str(ipaddress.IPv4Address(query["host"]))
    ports = query["ports"]
    assert len(ports) <= 64 and all(type(p) is int and 0 < p < 65536 for p in ports)
    rest_ports = query.get("rest_ports", [])
    assert len(rest_ports) == len(set(rest_ports)) and set(rest_ports).issubset(ports)
    assert isinstance(query["control_token"], str) and len(query["control_token"]) == 32
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    control_port = query["control_port"]
    assert type(control_port) is int and 0 < control_port < 65536

    def control():
        with opener.open(f"http://{host}:{control_port}/", timeout=3) as response:
            value = response.read(256).decode()
        assert value == query["control_token"], "peer positive control identity mismatch"
        return value

    result["control_before"] = control()
    result["tcp"] = {}
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=1):
                result["tcp"][str(port)] = True
        except OSError as error:
            result["tcp"][str(port)] = {"connected": False, "error": repr(error)}
    result["rest"] = {}
    for port in rest_ports:
        assert port in ports
        responses = {}
        for suffix in ("", "/members"):
            with opener.open(f"http://{host}:{port}/management/coherence/cluster{suffix}", timeout=5) as response:
                responses[suffix or "cluster"] = json.load(response)
        result["rest"][str(port)] = responses
    if query.get("jmx_port"):
        assert query["jmx_port"] in ports and classes is not None
        command = [java, "-cp", str(classes), "ManagementProbe", host, str(query["jmx_port"]), str(query["expected_pid"])]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=20)
        result["jmx"] = {"argv": command, "exit": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
        assert completed.returncode == 0, result["jmx"]
    result["control_after"] = control()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-host", required=True, type=ipaddress.IPv4Address)
    parser.add_argument("--classes", type=Path, help="peer-local directory with the exact compiled ManagementProbe")
    parser.add_argument("--java", default="java")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(65537)
    assert len(raw) <= 65536, "peer request exceeds 64 KiB"
    query = json.loads(raw)
    if os.name != "posix":
        raise RuntimeError("MISSING COVERAGE: this supervised peer agent requires an assigned Linux/macOS peer")
    if not args.worker:
        argv = [sys.executable, str(Path(__file__).resolve()), "--allow-host", str(args.allow_host), "--java", args.java, "--worker"]
        if args.classes:
            argv += ["--classes", str(args.classes)]
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True, env=dict(os.environ, F1_PEER_WORKER="1", PYTHONDONTWRITEBYTECODE="1"))
        rescue = False
        try:
            stdout, stderr = child.communicate(raw, timeout=90)
        except subprocess.TimeoutExpired:
            rescue = True
            # The worker's handler unwinds subprocess.run, killing/reaping its
            # Java child. A separate group kill bounds a failed unwind as well.
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = child.communicate(timeout=5)
        if child.returncode == 0 and not rescue:
            result = json.loads(stdout)
        else:
            result = {"protocol": 1, "nonce": query.get("nonce"), "failure": "supervised peer worker failed or timed out",
                      "worker_stdout": stdout.decode(errors="replace"), "worker_stderr": stderr.decode(errors="replace")}
        result["supervision"] = {"worker_pid": child.pid, "exit": child.returncode, "rescue": rescue,
                                 "deadline_seconds": 90, "wait_owner": "supervisor only"}
        print(json.dumps(result))
        raise SystemExit(1 if rescue or child.returncode else 0)
    assert os.environ.get("F1_PEER_WORKER") == "1", "private supervisor required"

    def terminate_worker(signum, frame):
        raise TimeoutError("peer aggregate deadline")

    signal.signal(signal.SIGTERM, terminate_worker)
    try:
        result = exchange(query, str(args.allow_host), args.classes, args.java)
    except Exception as error:
        print(json.dumps({"protocol": 1, "nonce": query.get("nonce"), "failure": repr(error)}))
        raise SystemExit(1)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
