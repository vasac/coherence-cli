# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.

"""Assigned-peer checks. The caller supplies the transport and isolated resources."""

import hashlib
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import uuid

import f1_platform as native


class Peer:
    def __init__(self, path, host, evidence):
        self.config = json.loads(Path(path).read_text())
        assert self.config["scope"] in ("network-namespace", "two-host", "virtual-machine")
        assert self.config["resources"] and self.config["network_context"], "assigned resources/routes/firewall context required"
        assert isinstance(self.config["argv"], list) and all(isinstance(s, str) for s in self.config["argv"])
        self.host, self.evidence = host, evidence
        self.token = uuid.uuid4().hex
        token = self.token.encode()

        class Control(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(token)))
                self.end_headers()
                self.wfile.write(token)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer((host, 0), Control)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        try:
            peer = self.call({"operation": "identity"})
            local = native.identity()
            if self.config["scope"] == "network-namespace":
                assert local.get("/proc/self/ns/net") and peer["identity"].get("/proc/self/ns/net"), "both Linux network namespace identities required"
                assert peer["identity"]["/proc/self/ns/net"] != local["/proc/self/ns/net"], "peer shares local network namespace"
            elif self.config["scope"] == "two-host":
                assert self.config.get("physical_host_assignment"), "two physical host assignment evidence required"
            else:
                assert self.config.get("virtual_machine_assignment"), "assigned virtual-machine topology evidence required"
            for label, name in (("agent", "f1-peer.py"), ("adapter", "f1_platform.py"), ("probe_source", "ManagementProbe.java")):
                assert peer[label + "_sha256"] == hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest(), "peer source drift"
            assert peer["probe_class_sha256"] == self.config["probe_class_sha256"], "peer compiled probe identity mismatch"
            evidence["peer"] = {"configuration": self.config, "identity": peer, "calls": []}
            evidence["topology"] = self.config["scope"]
        except BaseException:
            self.close()
            raise

    def call(self, query):
        query = dict(query, protocol=1, nonce=uuid.uuid4().hex)
        completed = subprocess.run(self.config["argv"], input=json.dumps(query), capture_output=True, text=True, timeout=120)
        record = {"request": query, "exit": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
        if "peer" in self.evidence:
            self.evidence["peer"]["calls"].append(record)
        assert completed.returncode == 0, record
        response = json.loads(completed.stdout)
        assert response["nonce"] == query["nonce"] and response["protocol"] == 1
        assert response["supervision"]["exit"] == 0 and not response["supervision"]["rescue"]
        assert response["supervision"]["deadline_seconds"] == 90
        if "peer" in self.evidence:
            previous = self.evidence["peer"]["identity"]
            for key in ("identity", "hostname", "agent_sha256", "adapter_sha256", "probe_source_sha256", "probe_class_sha256"):
                assert response[key] == previous[key], "peer identity changed during qualification"
        return response

    def check(self, record, jmx):
        remote = record["nonloopback_probes"].endswith("reachable")
        ports = sorted(set([*record["rest"].values(), jmx]))
        query = {"operation": "probe", "host": self.host, "ports": ports,
                 "control_port": self.server.server_port, "control_token": self.token}
        if remote:
            query["rest_ports"] = list(record["rest"].values())
            if not record["jmx_port_closed"]:
                query.update(jmx_port=jmx, expected_pid=record["members"]["storage-0"])
        result = self.call(query)
        assert result["control_before"] == self.token and result["control_after"] == self.token
        assert set(result["tcp"]) == {str(port) for port in ports}, "peer omitted a selected socket"
        assert set(result.get("rest", {})) == {str(port) for port in query.get("rest_ports", [])}
        if query.get("jmx_port"):
            assert result["jmx"]["exit"] == 0 and f"runtime={query['expected_pid']}@" in result["jmx"]["stdout"]
        for port, connected in result["tcp"].items():
            expected = remote and (int(port) != jmx or not record["jmx_port_closed"])
            assert (connected is True) == expected, (port, connected, expected)
        for responses in result.get("rest", {}).values():
            assert responses["cluster"]["clusterName"] == self.evidence["cluster_name"]
            observed = {row["memberName"]: int(row["processName"]) for row in responses["/members"]["items"]}
            assert observed == record["members"], "peer REST cluster/PID identity mismatch"
        record["peer"] = result

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive(), "positive-control server did not finish"


def qualify(command, inspect, config, marker, interface, http, cluster, jmx, create, set_host, evidence):
    """Concrete-interface and wildcard cases, with no-ack, failure and cancellation."""
    def state():
        path = config / "cohctl.yaml"
        return path.read_bytes() if path.exists() else b"", native.processes(marker)

    def reject(*words):
        before = state()
        output = command(*words, success=False)
        assert "--allow-insecure-remote-management" in output, output
        assert state() == before, "remote rejection changed configuration or owned PIDs"
        evidence.setdefault("remote_rejections", []).append({"argv": list(words), "config_sha256": hashlib.sha256(before[0]).hexdigest(), "pids": before[1]})

    command("stop", "cluster", marker, "-y")
    for bind in (interface, "0.0.0.0"):
        command("remove", "cluster", marker, "-y")
        words = [*create, "-N", "-J", jmx, "--management-address", bind, "--jmx-address", bind, "--jmx-host", interface]
        reject(*words)
        output = command(*words, "--allow-insecure-remote-management")
        assert "WARNING" in output and "without authentication or encryption" in output.lower(), output
        set_host(interface if bind != "0.0.0.0" else "127.0.0.1")
        inspect("remote create " + bind, 2, True, bind)
        reject("scale", "cluster", marker, "-r", 4, "-N")
        command("stop", "cluster", marker, "-y")
        reject("start", "cluster", marker, "-r", 3, "-N")
        command("start", "cluster", marker, "-r", 3, "-N", "--allow-insecure-remote-management")
        inspect("remote saved start " + bind, 3, True, bind)
        command("scale", "cluster", marker, "-r", 4, "-N", "--allow-insecure-remote-management")
        inspect("remote scale " + bind, 3, True, bind)
        reject("restart", "cluster", marker, "-y", "-r", 2)
        command("restart", "cluster", marker, "-y", "-r", 2, "--allow-insecure-remote-management")
        inspect("remote restart " + bind, 1, True, bind)
        saved = state()[0]
        assert b"allowinsecureremote" not in saved.lower() and b"allow-insecure-remote" not in saved.lower()
        command("stop", "cluster", marker, "-y")
        before = state()
        command("start", "cluster", marker, "-r", 2, "-S", "f1.QualificationMissingClass", "--allow-insecure-remote-management", success=False)
        assert state() == before, "failed remote startup changed saved state or leaked children"
        if os.name == "nt":
            raise RuntimeError("MISSING COVERAGE: remote cancellation needs the assigned Windows console controller")
        last = evidence["commands"][-1]["argv"]
        argv = last[:3] + ["start", "cluster", marker, "-r", "2", "-D", "30s", "--allow-insecure-remote-management"]
        output_path = config.parent / ("cancel-" + bind + ".log")
        with output_path.open("w") as stream:
            child = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while not native.processes(marker):
                    assert child.poll() is None and time.monotonic() < deadline, "remote delay phase not reached"
                    time.sleep(.05)
                owned = native.processes(marker)
                child.send_signal(signal.SIGINT)
                exit_code = child.wait(timeout=15)
                assert exit_code != 0 and "context canceled" in output_path.read_text()
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                    raise AssertionError("remote CLI required forced rescue")
        assert state() == before, "remote cancellation changed configuration or leaked children"
        evidence.setdefault("remote_transactions", []).append({"bind": bind, "failure_preserved": True, "cancellation_preserved": True,
                                                               "cancel_owned": owned, "cancel_exit": exit_code, "cancel_output": output_path.read_text(),
                                                               "config_sha256": hashlib.sha256(saved).hexdigest(), "permission_not_saved": True})
