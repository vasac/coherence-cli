#!/usr/bin/env python3
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.

"""Real local protocol controls. These are not distinct-network qualification."""

import importlib.util
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from f1_remote import Peer
import f1_platform as native

spec = importlib.util.spec_from_file_location("f1_peer", Path(__file__).with_name("f1-peer.py"))
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)

spec = importlib.util.spec_from_file_location("f1_management", Path(__file__).with_name("test-local-management.py"))
management = importlib.util.module_from_spec(spec)
spec.loader.exec_module(management)


class MembershipReadinessTests(unittest.TestCase):
    def test_inspection_waits_for_partial_secondary_view(self):
        self.inspect_views({58081})

    def test_inspection_waits_for_partial_primary_view(self):
        self.inspect_views({58080})

    def test_inspection_still_rejects_identity_change_after_readiness(self):
        self.inspect_views(set(), regress=True)

    def inspect_views(self, partial_ports, regress=False):
        source = Path(__file__).with_name("test-local-management.py")
        tree = ast.parse(source.read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        inspect = next(node for node in ast.walk(main) if isinstance(node, ast.FunctionDef) and node.name == "inspect")
        marker = "f1-membership-control"
        expected = {"storage-0": 11050, "storage-1": 11051}
        ports = {"storage-0": 58080, "storage-1": 58081}
        calls = []
        synchronized = False

        def members(port=58080, timeout=3):
            calls.append(port)
            if regress and synchronized:
                return {"storage-0": 99999, "storage-1": 11051}
            if port in partial_ports and calls.count(port) == 1:
                member = next(name for name, selected in ports.items() if selected == port)
                return {member: expected[member]}
            return dict(expected)

        def wait(*args):
            nonlocal synchronized
            result = management.wait_for_rest_membership(*args)
            synchronized = True
            return result

        class Control:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def bind(self, address):
                pass
            def listen(self, count):
                pass
            def getsockname(self):
                return ("192.0.2.10", 59999)

        with tempfile.TemporaryDirectory(prefix="f1-membership-control-") as temp:
            directory = Path(temp)
            logs = directory / "logs" / marker
            logs.mkdir(parents=True)
            jar = directory / "classpath.jar"
            jar.write_bytes(b"controlled identity; no JVM")
            snapshots = {}
            for member, pid in expected.items():
                (logs / (member + ".log")).write_text(f"HttpAcceptor now listening for connections on 127.0.0.1:{ports[member]}\n")
                snapshots[pid] = {"pid": pid, "command": f"java -cp {jar} -Dcoherence.cluster={marker} -Dcoherence.member={member}",
                                  "listeners": [f"127.0.0.1:{ports[member]}"]}
            record = {"checks": []}
            environment = {"members": members, "marked_processes": lambda: set(expected.values()),
                "native": types.SimpleNamespace(processes=lambda selected: {pid: row["command"] for pid, row in snapshots.items()},
                                                snapshot=lambda pid: dict(snapshots[pid]), assert_listener_bind=native.assert_listener_bind),
                "marker": marker, "config": directory, "Path": Path, "hashlib": hashlib, "shlex": shlex, "os": os, "re": re,
                "request": lambda selected: {"clusterName": marker}, "connect": lambda host, port: port == 59999,
                "interface": "192.0.2.10", "jmx": 58082, "peer": None, "socket": types.SimpleNamespace(socket=Control),
                "observer_lock": threading.Lock(), "linux_identities": {}, "evidence": record,
                "wait_for_rest_membership": wait}
            exec(compile(ast.fix_missing_locations(ast.Module(body=[inspect], type_ignores=[])), str(source), "exec"), environment)
            with patch.object(management.time, "sleep"):
                if regress:
                    with self.assertRaisesRegex(AssertionError, "REST endpoint member/PID identity mismatch"):
                        environment["inspect"]("dynamic create", 2, False)
                    self.assertEqual(record["checks"], [])
                    return
                result = environment["inspect"]("dynamic create", 2, False)
            self.assertEqual(result["members"], expected)
            self.assertEqual(result["rest"], ports)
            for port in partial_ports:
                self.assertGreaterEqual(calls.count(port), 2)
            self.assertEqual(len(record["checks"]), 1)

    def clock(self):
        clock = types.SimpleNamespace(now=0)
        def sleep(seconds):
            self.assertGreater(seconds, 0)
            clock.now += seconds
        for name, effect in (("monotonic", lambda: clock.now), ("sleep", sleep)):
            control = patch.object(management.time, name, side_effect=effect)
            control.start()
            self.addCleanup(control.stop)
        return clock

    def test_transient_request_errors_are_retried(self):
        self.clock()
        expected = {"storage-0": 11050}
        outcomes = [OSError("listener not ready"), ValueError("incomplete JSON"), expected]
        def read(port, timeout):
            item = outcomes.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        result = management.wait_for_rest_membership(expected, {"storage-0": 58080}, read, timeout=1)
        self.assertEqual(result, {"storage-0": {"port": 58080, "members": expected}})
        self.assertEqual(outcomes, [])

    def test_timeout_retains_each_endpoint_map_and_exact_expected_identities(self):
        clock = self.clock()
        expected = {"storage-0": 11050, "storage-1": 11051}
        primary = dict(expected)
        for observed in ({"storage-1": 11051}, {"storage-0": 99999, "storage-1": 11051},
                         dict(expected, unexpected=11052)):
            with self.subTest(observed=observed):
                clock.now = 0
                def read(port, timeout):
                    return primary if port == 58080 else observed
                with self.assertRaises(TimeoutError) as raised:
                    management.wait_for_rest_membership(expected, {"storage-0": 58080, "storage-1": 58081}, read, timeout=.25)
                diagnostic = json.loads(str(raised.exception).split(": ", 1)[1])
                self.assertEqual(diagnostic["expected"], expected)
                self.assertEqual(diagnostic["endpoints"]["storage-0"]["members"], primary)
                self.assertEqual(diagnostic["endpoints"]["storage-1"]["members"], observed)
                self.assertAlmostEqual(clock.now, .25)

    def test_timeout_preserves_last_map_and_request_error(self):
        self.clock()
        reads = []
        def read(port, timeout):
            reads.append(port)
            if len(reads) == 1:
                return {"storage-1": 11051}
            raise OSError("endpoint unavailable")
        with self.assertRaises(TimeoutError) as raised:
            management.wait_for_rest_membership({"storage-0": 11050, "storage-1": 11051}, {"storage-1": 58081}, read, timeout=.25)
        diagnostic = json.loads(str(raised.exception).split(": ", 1)[1])
        self.assertEqual(diagnostic["endpoints"]["storage-1"]["members"], {"storage-1": 11051})
        self.assertIn("endpoint unavailable", diagnostic["endpoints"]["storage-1"]["error"])

    def test_requests_share_one_deadline(self):
        clock = self.clock()
        calls = []
        def read(port, timeout):
            calls.append((port, timeout))
            clock.now += timeout
            raise TimeoutError("read timed out")
        with self.assertRaises(TimeoutError) as raised:
            management.wait_for_rest_membership({"storage-0": 11050}, {"primary": 58080, "secondary": 58081}, read, timeout=.25)
        self.assertEqual(calls, [(58080, .25)])
        self.assertAlmostEqual(clock.now, .25)
        diagnostic = json.loads(str(raised.exception).split(": ", 1)[1])
        self.assertIsNone(diagnostic["endpoints"]["secondary"]["members"])

    def test_ambiguous_identity_is_not_retried(self):
        self.clock()
        def read(port, timeout):
            raise AssertionError("ambiguous member/PID identities")
        with self.assertRaisesRegex(AssertionError, "ambiguous member/PID identities"):
            management.wait_for_rest_membership({"storage-0": 11050}, {"storage-0": 58080}, read)


class ListenerBindTests(unittest.TestCase):
    def test_complete_selected_socket_set(self):
        for bind in ("127.0.0.1", "192.0.2.10", "0.0.0.0"):
            with self.subTest(bind=bind):
                native.assert_listener_bind([f"{bind}:58080", "127.0.0.1:59999"], 58080, bind)
                if bind == "0.0.0.0":
                    native.assert_listener_bind(["*:58080"], 58080, bind)
                wrong = "192.0.2.11:58080" if bind != "192.0.2.11" else "127.0.0.1:58080"
                invalid = [[], ["[::]:58080"], [wrong], [f"{bind}:58080", "*:58080"]]
                if bind != "0.0.0.0":
                    invalid.extend([["*:58080"], ["0.0.0.0:58080"]])
                for addresses in invalid:
                    with self.assertRaisesRegex(AssertionError, "incorrect listener bind"):
                        native.assert_listener_bind(addresses, 58080, bind)

    def test_actual_rest_and_jmx_inspection_rejects_wrong_wildcard(self):
        source = Path(__file__).with_name("test-local-management.py")
        tree = ast.parse(source.read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        inspect = next(node for node in ast.walk(main) if isinstance(node, ast.FunctionDef) and node.name == "inspect")
        marker, member, pid, port, jmx = "f1-bind-control", "storage-0", 12345, 58080, 58081

        class Control:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def bind(self, address):
                pass
            def listen(self, count):
                pass
            def getsockname(self):
                return ("192.0.2.10", 59999)

        with tempfile.TemporaryDirectory(prefix="f1-bind-control-") as temp:
            directory = Path(temp)
            logs = directory / "logs" / marker
            logs.mkdir(parents=True)
            (logs / (member + ".log")).write_text(f"HttpAcceptor now listening for connections on 127.0.0.1:{port}\n")
            jar = directory / "classpath-fixture.jar"
            jar.write_bytes(b"controlled classpath identity; no JVM")
            command = f"java -cp {jar} -Dcoherence.cluster={marker} -Dcoherence.member={member}"
            # JMX-only negatives retain a valid REST socket so the JMX assertion
            # itself must reject the wildcard; network observations still match.
            for bind in ("127.0.0.1", "192.0.2.10", "0.0.0.0"):
                for wrong in ("rest", "jmx"):
                    with self.subTest(bind=bind, wrong=wrong):
                        addresses = [f"{'*' if wrong == 'rest' else bind}:{port}",
                                     f"{'*' if wrong == 'jmx' else bind}:{jmx}"]
                        record = {"checks": []}
                        environment = {"members": lambda selected=port, timeout=3: {member: pid}, "marked_processes": lambda: {pid},
                            "native": types.SimpleNamespace(processes=lambda selected: {pid: command},
                                                            snapshot=lambda selected: {"pid": pid, "command": command, "listeners": addresses},
                                                            assert_listener_bind=native.assert_listener_bind),
                            "marker": marker, "config": directory, "Path": Path, "hashlib": hashlib, "shlex": shlex, "os": os, "re": re,
                            "request": lambda selected: {"clusterName": marker},
                            "connect": lambda host, selected: selected == 59999 or (selected in (port, jmx) and bind != "127.0.0.1"),
                            "interface": "192.0.2.10", "jmx": jmx, "peer": None, "socket": types.SimpleNamespace(socket=Control),
                            "subprocess": types.SimpleNamespace(check_output=lambda *a, **kw: f"endpoint:[192.0.2.10:{jmx}] runtime={pid}@control"),
                            "temp": temp, "local_host": bind, "evidence": record,
                            "wait_for_rest_membership": management.wait_for_rest_membership}
                        exec(compile(ast.fix_missing_locations(ast.Module(body=[inspect], type_ignores=[])), str(source), "exec"), environment)
                        if bind == "0.0.0.0":
                            environment["inspect"]("valid wildcard", 1, True, bind)
                            self.assertEqual(len(record["checks"]), 1)
                        else:
                            with self.assertRaisesRegex(AssertionError, "incorrect listener bind"):
                                environment["inspect"]("incorrect wildcard", 1, True, bind)
                            self.assertEqual(record["checks"], [])


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.token = uuid.uuid4().hex
        token = self.token

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                value = token if self.path == "/" else json.dumps({"clusterName": "owned", "items": [{"memberName": "storage-0", "processName": "123"}]})
                self.send_response(200)
                self.end_headers()
                self.wfile.write(value.encode())

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())

    def query(self):
        return {"protocol": 1, "nonce": uuid.uuid4().hex, "operation": "probe", "host": "127.0.0.1",
                "ports": [self.server.server_port], "control_port": self.server.server_port, "control_token": self.token,
                "rest_ports": [self.server.server_port]}

    def test_positive_identity_and_negative_tcp_with_controls(self):
        query = self.query()
        # Keep a bound, non-listening socket so this negative port cannot be reused.
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))
            port = closed.getsockname()[1]
            query["ports"].append(port)
            result = peer.exchange(query, "127.0.0.1", None, "java")
        self.assertEqual(result["nonce"], query["nonce"])
        self.assertEqual(result["control_before"], self.token)
        self.assertEqual(result["control_after"], self.token)
        self.assertTrue(result["tcp"][str(self.server.server_port)])
        self.assertFalse(result["tcp"][str(port)]["connected"])
        self.assertEqual(result["rest"][str(self.server.server_port)]["cluster"]["clusterName"], "owned")

    def test_wrong_control_cannot_produce_negative_pass(self):
        query = self.query()
        query["control_token"] = "0" * 32
        with self.assertRaisesRegex(AssertionError, "identity mismatch"):
            peer.exchange(query, "127.0.0.1", None, "java")

    def test_unassigned_host_is_rejected(self):
        with self.assertRaises(AssertionError):
            peer.exchange(self.query(), "192.0.2.1", None, "java")

    def test_identity_needs_no_connection(self):
        query = dict(self.query(), operation="identity")
        result = peer.exchange(query, "127.0.0.1", None, "java")
        self.assertIn("system", result["identity"])
        self.assertNotIn("tcp", result)

    def test_stdio_protocol_preserves_nonce_and_source_identity(self):
        query = dict(self.query(), operation="identity")
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("f1-peer.py")), "--allow-host", "127.0.0.1"],
                                input=json.dumps(query), capture_output=True, text=True, timeout=10, check=True)
        response = json.loads(result.stdout)
        self.assertEqual(response["nonce"], query["nonce"])
        self.assertEqual(len(response["agent_sha256"]), 64)

    def test_vm_topology_is_named_and_requires_assignment(self):
        identity = peer.exchange(dict(self.query(), operation="identity"), "127.0.0.1", None, "java")
        identity["probe_class_sha256"] = "a" * 64
        config = {"scope": "virtual-machine", "resources": "assigned test guest",
                  "network_context": "approved test LAN", "argv": ["unused"],
                  "probe_class_sha256": identity["probe_class_sha256"]}
        with tempfile.TemporaryDirectory(prefix="f1-vm-metadata-") as directory:
            path = Path(directory) / "peer.json"
            path.write_text(json.dumps(config))
            with patch.object(Peer, "call", return_value=identity):
                with self.assertRaisesRegex(AssertionError, "virtual-machine topology"):
                    Peer(path, "127.0.0.1", {})
                config["virtual_machine_assignment"] = "owner-assigned guest on approved LAN"
                path.write_text(json.dumps(config))
                evidence = {}
                selected = Peer(path, "127.0.0.1", evidence)
                try:
                    self.assertEqual(evidence["topology"], "virtual-machine")
                finally:
                    selected.close()

    def test_vm_assignment_does_not_clear_physical_host_requirement(self):
        identity = peer.exchange(dict(self.query(), operation="identity"), "127.0.0.1", None, "java")
        config = {"scope": "two-host", "resources": "assigned test guest",
                  "network_context": "approved test LAN", "argv": ["unused"],
                  "virtual_machine_assignment": "guest only"}
        with tempfile.TemporaryDirectory(prefix="f1-vm-metadata-") as directory:
            path = Path(directory) / "peer.json"
            path.write_text(json.dumps(config))
            with patch.object(Peer, "call", return_value=identity):
                with self.assertRaisesRegex(AssertionError, "two physical host"):
                    Peer(path, "127.0.0.1", {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
