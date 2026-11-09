#!/usr/bin/env python3
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.

"""Local F1 runtime gate. Requires java/javac, cached Maven dependencies and lsof.

Uses task-owned config/JVMs, local REST/JMX success, PID-owned listener inspection,
and negative probes through a real host interface with a positive TCP control.
This is same-host evidence; second-host and insecure-remote qualification are separate.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
import uuid
import shlex

import f1_platform as native


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--cli", default="bin/cohctl")
    parser.add_argument("--download-deps", action="store_true", help="allow Maven to populate missing dependency cache entries")
    parser.add_argument("--commercial", action="store_true")
    parser.add_argument("--monitor", action="store_true", help="also exercise the existing terminal monitor fixture (requires expect)")
    parser.add_argument("--output", help="optional JSON evidence destination")
    parser.add_argument("--scratch-dir", type=Path, help="existing task-owned temporary parent")
    parser.add_argument("--interface", help="assigned local IPv4 interface; automatic route selection otherwise")
    parser.add_argument("--rest-port", type=int, help="assigned fixed Management REST test port")
    parser.add_argument("--cluster-port", type=int, help="assigned fixed NameService/cluster test port")
    parser.add_argument("--jmx-port", type=int, help="assigned fixed registry/RMI test port")
    parser.add_argument("--initialize-config", action="store_true", help="run version first as an explicit initialized-configuration control")
    parser.add_argument("--peer-config", type=Path, help="assigned isolated peer JSON: argv, scope, resource description")
    args = parser.parse_args()
    assigned_ports = [port for port in (args.rest_port, args.cluster_port, args.jmx_port) if port is not None]
    if any(not 0 < port < 65536 for port in assigned_ports) or len(assigned_ports) != len(set(assigned_ports)):
        parser.error("assigned test ports must be distinct integers in 1..65535")
    native.prerequisites()
    if not all(shutil.which(tool) for tool in ("java", "javac")):
        raise RuntimeError("MISSING COVERAGE: java and javac are required")
    root = Path(__file__).resolve().parent.parent
    cli = str(Path(args.cli).resolve())
    base = args.scratch_dir or Path("/private/tmp/codex-work" if Path("/private/tmp").exists() else tempfile.gettempdir())
    base.mkdir(parents=True, exist_ok=True)
    evidence = {"version": args.version, "platform": native.identity(),
                "started_at": datetime.now(timezone.utc).isoformat(), "status": "RUNNING",
                "java": subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT, text=True).strip(),
                "cli_sha256": hashlib.sha256(Path(cli).read_bytes()).hexdigest(),
                "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "probe_sha256": hashlib.sha256((root / "scripts" / "ManagementProbe.java").read_bytes()).hexdigest(),
                "topology": "same host, real non-loopback interface; no second-host test", "checks": [], "commands": [],
                "adapter_sha256": hashlib.sha256((root / "scripts" / "f1_platform.py").read_bytes()).hexdigest()}
    evidence["requested_fixed_ports"] = {"rest": args.rest_port, "cluster": args.cluster_port, "jmx": args.jmx_port}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    marker = "f1-" + uuid.uuid4().hex[:12]
    evidence["cluster_name"] = marker

    local_host = "127.0.0.1"

    def request(port):
        with opener.open(f"http://{local_host}:{port}/management/coherence/cluster", timeout=2) as response:
            return json.load(response)

    def free_port():
        # Keep fixed Coherence discovery/management ports below the host's usual
        # ephemeral range. A socket assigned with bind(..., 0) can be reused by
        # an outgoing connection before the cluster's NameService binds it.
        for _ in range(100):
            candidate = 18000 + secrets.randbelow(10000)
            try:
                with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    tcp.bind(("127.0.0.1", candidate))
                    udp.bind(("127.0.0.1", candidate))
                    return candidate
            except OSError:
                pass
        raise RuntimeError("no free fixed test port in 18000..27999")

    def connect(host, port):
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            return False

    # UDP connect chooses an interface without sending a packet.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(("192.0.2.1", 9))
        interface = args.interface or route.getsockname()[0]
    if interface.startswith("127.") or interface == "0.0.0.0":
        raise RuntimeError("MISSING COVERAGE: no real non-loopback interface")
    with socket.socket() as control:
        control.bind((interface, 0)); control.listen(1)
        assert connect(interface, control.getsockname()[1]), "positive interface control failed"
        evidence["positive_tcp_control_address"] = f"{interface}:{control.getsockname()[1]}"
    evidence["interface"] = interface
    evidence["positive_tcp_control"] = True

    with tempfile.TemporaryDirectory(prefix="f1-management-", dir=base) as temp:
        config = Path(temp) / "config"
        config.mkdir()
        reserved = set(assigned_ports)

        def select_port(assigned):
            if assigned is not None:
                return assigned
            while True:
                port = free_port()
                if port not in reserved:
                    reserved.add(port)
                    return port

        http, cluster, jmx = select_port(args.rest_port), select_port(args.cluster_port), select_port(args.jmx_port)
        evidence["selected_fixed_ports"] = {"rest": http, "cluster": cluster, "jmx": jmx}
        linux_identities, observer_errors = {}, []
        observer_stop, observer_lock = threading.Event(), threading.Lock()

        def remember_linux_pids():
            try:
                for pid in native.processes(marker):
                    state = native.linux_process_state(pid)
                    if state:
                        with observer_lock:
                            linux_identities.setdefault(f"{pid}:{state['start_ticks']}", state)
            except Exception as error:
                observer_errors.append(repr(error))

        def observe_linux():
            while not observer_stop.wait(.1):
                remember_linux_pids()

        observer = None
        if evidence["platform"]["system"] == "Linux":
            observer = threading.Thread(target=observe_linux, daemon=True)
            observer.start()

        def command(*words, success=True, env=None):
            started = time.monotonic()
            result = subprocess.run([cli, "--config-dir", str(config), *map(str, words)], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, env=env)
            evidence["commands"].append({"argv": [cli, "--config-dir", str(config), *map(str, words)],
                                         "exit_code": result.returncode, "expected_success": success,
                                         "elapsed_seconds": time.monotonic() - started,
                                         "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(), "stdout": result.stdout})
            print("cohctl", *words, flush=True)
            if (result.returncode == 0) != success:
                raise AssertionError(result.stdout)
            return result.stdout

        def members(port=http):
            with opener.open(f"http://{local_host}:{port}/management/coherence/cluster/members", timeout=3) as response:
                items = json.load(response)["items"]
            result = {item["memberName"]: int(item["processName"]) for item in items}
            assert len(result) == len(items) and len(set(result.values())) == len(items), "ambiguous member/PID identities"
            return result

        def marked_processes():
            return set(native.processes(marker))

        peer = None

        def set_host(host):
            nonlocal local_host
            local_host = host

        def inspect(label, expected_http, with_jmx, bind_address="127.0.0.1"):
            remote = bind_address != "127.0.0.1"
            current = members()
            assert set(current.values()) == marked_processes(), "REST snapshot differs from current test-owned processes"
            snapshots, rest, rest_identity = [], {}, {}
            for member, pid in current.items():
                snapshot = native.snapshot(pid)
                process_args = snapshot["command"]
                assert f"-Dcoherence.cluster={marker}" in process_args.split(), "cluster PID identity mismatch"
                assert f"-Dcoherence.member={member}" in process_args.split(), "member PID identity mismatch"
                addresses = snapshot["listeners"]
                snapshot["member"] = member
                snapshots.append(snapshot)
                state = snapshot.get("linux_process_identity")
                if state:
                    with observer_lock:
                        linux_identities.setdefault(f"{pid}:{state['start_ticks']}", state)
                tokens = [word.strip('"') for word in shlex.split(process_args, posix=os.name != "nt")]
                classpath = tokens[tokens.index("-cp") + 1]
                snapshot["classpath"] = [{"path": item, "sha256": hashlib.sha256(Path(item).read_bytes()).hexdigest()}
                                         for item in classpath.split(os.pathsep)]
                # The Coherence log names each selected management HTTP acceptor.
                log = (config / "logs" / marker / (member + ".log")).read_text()
                ports = set(map(int, re.findall(r"HttpAcceptor now listening for connections on [^\n]*?:(\d+)", log)))
                for port in ports:
                    # Logs can retain entries from an earlier incarnation. Only a
                    # socket owned by this current member can supply evidence.
                    if not any(address.rsplit(":", 1)[-1] == str(port) for address in addresses):
                        continue
                    # Health endpoints may share HttpAcceptor logs; only count Management REST.
                    try:
                        data = request(port)
                    except (OSError, ValueError):
                        continue
                    if data.get("clusterName") != marker:
                        continue
                    native.assert_listener_bind(addresses, port, bind_address)
                    observed = members(port)
                    assert observed == current, ("REST endpoint member/PID identity mismatch", member, port, observed, current)
                    assert connect(interface, port) == remote, ("unexpected interface REST reachability", port)
                    assert member not in rest, ("multiple Management REST listeners on one member", member)
                    rest[member] = port
                    rest_identity[member] = {"owner_pid": pid, "cluster_name": data["clusterName"], "members": observed}
            assert len(rest) == expected_http, (label, "REST listener count", rest, snapshots)
            if with_jmx:
                owner = current["storage-0"]
                sockets = [s for s in snapshots if any(a.rsplit(":", 1)[-1] == str(jmx) for a in s["listeners"])]
                assert len(sockets) == 1 and sockets[0]["pid"] == owner, sockets
                native.assert_listener_bind(sockets[0]["listeners"], jmx, bind_address)
                output = subprocess.check_output(["java", "-cp", temp, "ManagementProbe", local_host, str(jmx), str(owner)], text=True, timeout=15)
                assert connect(interface, jmx) == remote, "unexpected interface JMX registry/RMI reachability"
                assert "endpoint:[" in output and f":{jmx}]" in output, "actual RMI endpoint not identified"
            else:
                output = "JMX disabled"
                for snapshot in snapshots:
                    assert "com.sun.management.jmxremote" not in snapshot["command"]
                    assert not any(address.rsplit(":", 1)[-1] == str(jmx) for address in snapshot["listeners"]), snapshot
                assert not connect("127.0.0.1", jmx), "disabled JMX port still accepts loopback connections"
                assert not connect(interface, jmx), "disabled JMX port still accepts interface connections"
            assert members() == current and marked_processes() == set(current.values()), "members changed during socket inspection"
            record = {"case": label, "result": "PASS", "members": current, "rest": rest, "rest_identity": rest_identity,
                      "sockets": snapshots, "jmx": output.strip(), "jmx_port_closed": not with_jmx,
                      "nonloopback_probes": "all selected REST and JMX reachable" if remote else "all selected REST and JMX failed"}
            with socket.socket() as control:
                control.bind((interface, 0)); control.listen(1)
                assert connect(interface, control.getsockname()[1]), "same-case positive interface control failed"
                record["positive_control"] = f"{interface}:{control.getsockname()[1]}"
            if peer:
                peer.check(record, jmx)
            evidence["checks"].append(record)
            print(label, "PASS", rest, output.strip(), flush=True)
            return record

        try:
            subprocess.run(["javac", "-d", temp, str(root / "scripts" / "ManagementProbe.java")], check=True)
            if args.peer_config:
                from f1_remote import Peer
                peer = Peer(args.peer_config, interface, evidence)
            create = ["create", "cluster", marker, "-y", "-I", "-v", args.version, "-r", 2, "-H", http, "-p", cluster]
            if args.download_deps:
                create.remove("-I")
            if args.commercial:
                create.append("-C")
            if args.initialize_config:
                command("version")
                evidence["configuration_preinitialized"] = True
            command(*create)
            inspect("default create", 1, False)
            assert marker in command("nslookup", f"127.0.0.1:{cluster}", "-q", "Cluster/name")
            assert "127.0.0.1" in command("nslookup", f"127.0.0.1:{cluster}", "-q", "NameService/string/management/HTTPManagementURL")
            command("get", "members", "-c", f"127.0.0.1:{cluster}")
            evidence["name_service_discovery"] = "PASS"
            if args.monitor:
                fixture = Path(temp) / "monitor.expect"
                fixture.write_text((root / "scripts" / "monitor.expect").read_text().replace("monitor cluster local", "monitor cluster $env(F1_CLUSTER)"))
                environment = dict(os.environ, DIR=str(root), CONFIG_DIR=str(config), F1_CLUSTER=marker)
                result = subprocess.run(["expect", "-f", str(fixture)], env=environment, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                assert result.returncode == 0 and "Coherence CLI" in result.stdout, result.stdout
                evidence["terminal_monitor"] = "PASS"

            # Stop needs neither Java nor valid inherited management options.
            no_java = dict(os.environ, PATH="/nonexistent", JAVA_TOOL_OPTIONS="@invalid")
            command("stop", "cluster", marker, "-y", env=no_java)
            command("remove", "cluster", marker, "-y")
            command(*create, "-N")
            inspect("dynamic create", 2, False)
            command("stop", "cluster", marker, "-y")
            command("start", "cluster", marker, "-r", 3, "-J", jmx, "-N")
            inspect("dynamic start with local JMX", 3, True)
            for count, expected in ((4, 3), (6, 4), (9, 6)):
                command("scale", "cluster", marker, "-r", count, "-N")
                inspect(f"dynamic scale to {count}", expected, True)
            before = (config / "cohctl.yaml").read_bytes()
            old_members = members()
            command("restart", "cluster", marker, "-y", "--management-address=0.0.0.0", success=False)
            assert (config / "cohctl.yaml").read_bytes() == before
            assert members() == old_members and marked_processes() == set(old_members.values()), "invalid restart changed running members"
            evidence["invalid_restart"] = {"result": "PASS", "members_before": old_members, "members_after": members(),
                                           "config_sha256_before_and_after": hashlib.sha256(before).hexdigest(), "no_replacement": True}
            command("restart", "cluster", marker, "-y", "-r", 2, "--management-address=localhost", "--jmx-port=0")
            # Restart without -N retains the ordinary single REST selection.
            record = inspect("restart override persistence / explicit JMX disable", 1, False)
            assert len(record["members"]) == 2 and not set(record["members"].values()).intersection(old_members.values()), "restart retained old members"
            record["old_members"] = old_members
            record["all_members_replaced"] = True
            # Successful endpoint override must round-trip through config for get/stop.
            output = command("get", "members")
            assert marker in command("get", "clusters") and output
            saved = (config / "cohctl.yaml").read_text()
            assert "http://127.0.0.1:" in saved and "jmxport: 0" in saved
            record["saved_config_sha256"] = hashlib.sha256((config / "cohctl.yaml").read_bytes()).hexdigest()
            record["saved_loopback_url_and_jmx_zero"] = True
            if peer:
                from f1_remote import qualify
                qualify(command, inspect, config, marker, interface, http, cluster, jmx, create, set_host, evidence)
            if marked_processes():
                command("stop", "cluster", marker, "-y", env=no_java)
            deadline = time.monotonic() + 10
            while marked_processes() and time.monotonic() < deadline:
                time.sleep(.1)
            assert not marked_processes(), "Java-free stop left owned JVMs"
            evidence["status"] = "PASS"
        except Exception as error:
            evidence["status"] = "FAIL"
            evidence["failure"] = repr(error)
            selected = config / "cohctl.yaml"
            if selected.exists():
                body = selected.read_bytes()
                evidence["failed_configuration"] = {"encoding": "base64", "original_length": len(body),
                                                    "sha256": hashlib.sha256(body).hexdigest(),
                                                    "data": base64.b64encode(body).decode()}
            evidence["logs"] = {log.name: log.read_text() for log in sorted((config / "logs" / marker).glob("*.log"))}
            for name, content in evidence["logs"].items():
                print(name, content[-4000:], flush=True)
            raise
        finally:
            observer_stop.set()
            if observer:
                observer.join(timeout=12)
                if observer.is_alive():
                    observer_errors.append("owned PID observer did not finish")
                remember_linux_pids()
            before_cleanup = native.processes(marker)
            stopped = native.stop_owned(marker)
            def kernel_survivors():
                result = {}
                with observer_lock:
                    identities = list(linux_identities.items())
                for key, original in identities:
                    try:
                        state = native.linux_process_state(original["pid"])
                    except OSError as error:
                        result[key] = {"observation_error": repr(error)}
                        continue
                    if state and state["start_ticks"] == original["start_ticks"]:
                        result[key] = state
                return result
            deadline = time.monotonic() + 10
            while (marked_processes() or kernel_survivors()) and time.monotonic() < deadline:
                time.sleep(.1)
            remaining = sorted(marked_processes())
            kernel_remaining = kernel_survivors()
            evidence["cleanup"] = {"before": before_cleanup, "forced_owned_pids": stopped,
                                   "remaining_marked_pids": remaining, "linux_observed_identities": linux_identities,
                                   "remaining_owned_kernel_processes": kernel_remaining, "observer_errors": observer_errors,
                                   "result": "FAIL" if remaining or kernel_remaining or observer_errors else "PASS"}
            if peer:
                peer.close()
            evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
            if remaining or kernel_remaining or observer_errors:
                evidence["status"] = "FAIL"
            if args.output:
                Path(args.output).write_text(json.dumps(evidence, indent=2) + "\n")
            assert not remaining and not kernel_remaining and not observer_errors, "test-owned JVM cleanup incomplete"
    if args.output:
        Path(args.output).write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
