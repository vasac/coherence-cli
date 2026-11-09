#!/usr/bin/env python3
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.

"""Native containment controls; modeled Windows API order is labeled separately."""

import ast
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import f1_process_guard as guard

REQUIRE_NATIVE = "--require-native" in sys.argv
if REQUIRE_NATIVE:
    sys.argv.remove("--require-native")


class BackendTests(unittest.TestCase):
    def test_unsupported_platform_fails_before_spawn(self):
        with patch.object(guard.platform, "system", return_value="Unsupported"), patch.object(guard.subprocess, "Popen") as start:
            with self.assertRaisesRegex(RuntimeError, "MISSING COVERAGE"):
                guard.run_owned(["must-not-start"], ".", {}, None, None, 1, "unused.json")
            start.assert_not_called()

    def test_linux_signal_does_not_follow_reused_pid_or_signal_zombie(self):
        original = {"pid": 12345, "start_ticks": 7}
        for current in (None, {"start_ticks": 8, "state": "S"}, {"start_ticks": 7, "state": "Z"}):
            with self.subTest(current=current), patch.object(guard, "linux_state", return_value=current), patch.object(guard.os, "kill") as kill:
                guard.linux_signal(original, 9)
                kill.assert_not_called()

    def test_windows_timeout_and_leftover_descendant_terminate_job(self):
        for timeout in (False, True):
            with self.subTest(timeout=timeout):
                calls, state = [], {"active": 2, "killed": False}

                class Gate:
                    def write(self, value):
                        calls.append("dispatch")
                    def flush(self):
                        pass
                    def close(self):
                        pass

                class Child:
                    pid, stdin = 12345, Gate()
                    @property
                    def returncode(self):
                        return 1 if state["killed"] else None if timeout else 0
                    def poll(self):
                        return self.returncode
                    def wait(self, timeout):
                        calls.append("wait")
                        return self.returncode
                    def kill(self):
                        raise AssertionError("job containment must replace direct-child-only rescue")

                class Job:
                    def assign(self, child):
                        calls.append("assign")
                    def active(self):
                        return state["active"]
                    def terminate(self):
                        calls.append("terminate-all-job-members")
                        state.update(active=0, killed=True)
                    def close(self):
                        calls.append("close-job")

                record = {"errors": [], "rescue": False}
                with patch.object(guard.subprocess, "Popen", return_value=Child()):
                    guard.windows_guard({"argv": ["modeled"], "env": {}, "timeout": .03}, record, [False], Job)
                self.assertTrue(record["rescue"])
                self.assertEqual(record["remaining_owned"], {})
                self.assertLess(calls.index("assign"), calls.index("dispatch"))
                self.assertLess(calls.index("terminate-all-job-members"), calls.index("wait"))
                self.assertEqual(calls[-1], "close-job")

    def test_darwin_missing_accounting_fails_before_workloads(self):
        if platform.system() != "Darwin":
            self.skipTest("Darwin accounting control is host-specific")
        import f1_darwin_guard
        with patch.object(f1_darwin_guard, "DarwinProcesses", side_effect=RuntimeError("MISSING COVERAGE")), patch.object(guard.subprocess, "Popen") as start:
            with self.assertRaisesRegex(RuntimeError, "MISSING COVERAGE"):
                guard.run_owned(["must-not-start"], ".", {}, None, None, 1, "unused.json")
            start.assert_not_called()

    def test_darwin_failed_registration_removes_gated_job(self):
        if platform.system() != "Darwin":
            self.skipTest("Darwin registration control is host-specific")
        import f1_darwin_guard as darwin
        with tempfile.TemporaryDirectory(prefix="f1-guard-registration-") as temp:
            directory = Path(temp)
            marker = directory / "must-not-start"
            record = {"errors": [], "rescue": False, "remaining_owned": {"unconfirmed": True}}
            request = {"receipt": str(directory / "guard.json"), "nonce": __import__("uuid").uuid4().hex,
                       "env": dict(os.environ), "cwd": temp, "timeout": 2,
                       "argv": [sys.executable, "-c", "from pathlib import Path; Path(" + repr(str(marker)) + ").touch()"]}
            original = darwin.launchctl

            def uncertain_registration(*args, **kwargs):
                original(*args, **kwargs)
                if args[0] == "bootstrap":
                    raise OSError("injected error after actual launchd registration")

            with patch.object(darwin, "launchctl", side_effect=uncertain_registration):
                darwin.guard(request, record, [False], guard.CLEANUP_SECONDS)
            self.assertTrue(record["rescue"])
            self.assertTrue(record["errors"])
            self.assertEqual(record["remaining_owned"], {})
            self.assertFalse(marker.exists(), "workload started after uncertain registration")
            label = "org.oracle.cohctl.f1." + request["nonce"]
            result = subprocess.run(["/bin/launchctl", "list", label], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0, "gated launchd job remained registered")

    def test_windows_assignment_precedes_dispatch_and_failure_never_dispatches(self):
        for fail in (False, True):
            with self.subTest(assignment_failure=fail):
                calls = []

                class Gate:
                    def write(self, value):
                        calls.append("dispatch")
                    def flush(self):
                        pass
                    def close(self):
                        pass

                class Child:
                    pid, returncode, stdin = 12345, 0, Gate()
                    def poll(self):
                        return 0
                    def wait(self, timeout):
                        calls.append("wait")
                        return 0
                    def kill(self):
                        calls.append("kill-gated-bootstrap")

                class Job:
                    def assign(self, child):
                        calls.append("assign")
                        if fail:
                            raise OSError("modeled assignment denied")
                    def active(self):
                        return 0
                    def terminate(self):
                        calls.append("terminate-job")
                    def close(self):
                        calls.append("close-job")

                record = {"errors": [], "rescue": False}
                with patch.object(guard.subprocess, "Popen", return_value=Child()):
                    guard.windows_guard({"argv": ["modeled"], "env": {}, "timeout": 1}, record, [False], Job)
                if fail:
                    self.assertNotIn("dispatch", calls)
                    self.assertTrue(record["rescue"])
                    self.assertIn("kill-gated-bootstrap", calls)
                else:
                    self.assertLess(calls.index("assign"), calls.index("dispatch"))
                    self.assertFalse(record["rescue"])
                self.assertEqual(record["remaining_owned"], {})


class NativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() not in ("Linux", "Windows", "Darwin"):
            if REQUIRE_NATIVE:
                raise RuntimeError("MISSING COVERAGE: native Linux/Windows/macOS containment required")
            raise unittest.SkipTest("UNRUN native containment; unsupported host fails before dispatch")

    def run_command(self, directory, argv, timeout):
        path = directory / "guard.json"
        try:
            with (directory / "stdout").open("wb") as out, (directory / "stderr").open("wb") as err:
                record = guard.run_owned(argv, Path(__file__).resolve().parent.parent, dict(os.environ), out, err, timeout, path)
        finally:
            if os.environ.get("F1_GUARD_TEST_EVIDENCE"):
                destination = Path(os.environ["F1_GUARD_TEST_EVIDENCE"]) / directory.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(directory, destination)
        self.assertEqual(record["remaining_owned"], {}, record)
        self.assertFalse(record["errors"], record)
        self.assertFalse(path.with_suffix(".request.json").exists())
        return record

    def test_success_without_rescue(self):
        with tempfile.TemporaryDirectory(prefix="f1-guard-success-") as temp:
            record = self.run_command(Path(temp), [sys.executable, "-c", "print('owned success')"], 5)
            self.assertEqual(record["exit"], 0)
            self.assertEqual(record["guardian_exit"], 0)
            self.assertFalse(record["rescue"])

    def test_darwin_nested_guard_retains_custody_with_clean_command_environment(self):
        if platform.system() != "Darwin":
            self.skipTest("Darwin nested coalition control is host-specific")
        import f1_darwin_guard as darwin
        with tempfile.TemporaryDirectory(prefix="f1-guard-nested-") as temp:
            directory = Path(temp)
            scripts = Path(__file__).resolve().parent
            code = ("import sys,pathlib;sys.path.insert(0,sys.argv[1]);import f1_process_guard as g;"
                    "p=pathlib.Path(sys.argv[2]);"
                    "g.run_owned([sys.executable,'-c','import time;time.sleep(6)'],p,"
                    "{'PYTHONDONTWRITEBYTECODE':'1'},(p/'inner.stdout').open('wb'),"
                    "(p/'inner.stderr').open('wb'),8,p/'inner.guard.json')")
            record = self.run_command(directory, [sys.executable, "-c", code, str(scripts), temp], 2)
            self.assertTrue(record["rescue"])
            self.assertNotEqual(record["guardian_exit"], 0)
            identities = record["observed_identities"].values()
            self.assertGreaterEqual(len({state["coalition"] for state in identities}), 2,
                                    "enclosing guardian did not account for the nested launchd coalition")
            api = darwin.DarwinProcesses()
            self.assertTrue(all(api.same(state) is None for state in identities), record)
            print(json.dumps({"native_control": "nested-clean-environment", "record": record}), flush=True)

    def test_actual_runner_records_and_rejects_rescue(self):
        source = Path(__file__).with_name("test-f1-native.py")
        tree = ast.parse(source.read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        run = next(node for node in main.body if isinstance(node, ast.FunctionDef) and node.name == "run")
        with tempfile.TemporaryDirectory(prefix="f1-guard-runner-") as temp:
            evidence = {"commands": []}
            environment = {"scratch": Path(temp), "root": source.resolve().parent.parent,
                           "env": dict(os.environ), "guard": guard, "time": time, "evidence": evidence}
            exec(compile(ast.fix_missing_locations(ast.Module(body=[run], type_ignores=[])), str(source), "exec"), environment)
            output = environment["run"]("success", [sys.executable, "-c", "print('owned output')"], 5)
            self.assertIn("owned output", output)
            with self.assertRaises(AssertionError):
                environment["run"]("timeout", [sys.executable, "-c", "import time; time.sleep(20)"], .2)
            self.assertFalse(evidence["commands"][0]["rescue"])
            self.assertTrue(evidence["commands"][1]["rescue"])
            self.assertEqual(evidence["commands"][1]["remaining_owned"], {})
            print(json.dumps({"native_control": "actual-runner", "record": evidence}), flush=True)

    def test_timeout_and_successful_parent_leak_cleanup_new_session_descendant(self):
        fixture = Path(__file__).with_name("fixtures") / "f1-guard-child.py"
        for mode in ("timeout", "leak"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="f1-guard-" + mode + "-") as temp:
                directory = Path(temp)
                started = time.monotonic()
                record = self.run_command(directory, [sys.executable, str(fixture), mode, str(directory)], 2)
                self.assertLess(time.monotonic() - started, 12)
                self.assertTrue(record["rescue"], record)
                self.assertNotEqual(record["guardian_exit"], 0)
                children = [json.loads(p.read_text()) for p in directory.glob("[0-9]*.json")]
                self.assertEqual(len(children), 1, record)
                if platform.system() == "Linux":
                    self.assertIsNone(guard.linux_state(children[0]["pid"]), record)
                    self.assertIn(children[0]["pid"], [x["pid"] for x in record["adopted_reaped"]])
                elif platform.system() == "Darwin":
                    import f1_darwin_guard
                    self.assertIsNone(f1_darwin_guard.DarwinProcesses().state(children[0]["pid"]), record)
                    self.assertIn(children[0]["pid"], [x["pid"] for x in record["observed_identities"].values()])
                print(json.dumps({"native_control": mode, "record": record}), flush=True)

    def test_cleanup_preserves_unrelated_child(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
        try:
            with tempfile.TemporaryDirectory(prefix="f1-guard-unrelated-") as temp:
                record = self.run_command(Path(temp), [sys.executable, "-c", "import time; time.sleep(20)"], .2)
                self.assertTrue(record["rescue"])
                self.assertIsNone(unrelated.poll(), "guard cleanup touched a sibling outside its owned tree")
        finally:
            unrelated.kill()
            unrelated.wait(timeout=5)  # This test is the unrelated child's sole Wait owner.

    def test_guardian_deadline_survives_caller_exit(self):
        with tempfile.TemporaryDirectory(prefix="f1-guard-caller-") as temp:
            directory = Path(temp)
            fixture = Path(__file__).with_name("fixtures") / "f1-guard-child.py"
            code = ("import pathlib,os,sys; sys.path.insert(0,sys.argv[1]); import f1_process_guard as g; "
                    "p=pathlib.Path(sys.argv[2]); "
                    "g.run_owned([sys.executable,sys.argv[3],'timeout',str(p)],sys.argv[1],dict(os.environ),"
                    "(p/'stdout').open('wb'),(p/'stderr').open('wb'),2,p/'guard.json')")
            caller = subprocess.Popen([sys.executable, "-c", code, str(Path(__file__).resolve().parent), temp, str(fixture.resolve())])
            try:
                deadline = time.monotonic() + 6
                while not list(directory.glob("[0-9]*.json")) and time.monotonic() < deadline:
                    self.assertIsNone(caller.poll(), "caller exited before its child was ready")
                    time.sleep(.01)
                self.assertTrue(list(directory.glob("[0-9]*.json")), "new-session leaf did not start")
                caller.kill()
                caller.wait(timeout=5)  # Sole Wait owner of this deliberately lost caller.
                receipt = directory / "guard.json"
                deadline = time.monotonic() + 10
                while not receipt.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                record = json.loads(receipt.read_text())
                self.assertTrue(record["rescue"])
                self.assertEqual(record["reason"], "timeout")
                self.assertEqual(record["remaining_owned"], {})
                self.assertFalse(record["errors"])
                self.assertFalse(receipt.with_suffix(".request.json").exists())
                if platform.system() == "Linux":
                    for state in record["observed_identities"].values():
                        current = guard.linux_state(state["pid"])
                        self.assertFalse(current and current["start_ticks"] == state["start_ticks"], record)
                    original = record["guardian_identity"]
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        current = guard.linux_state(original["pid"])
                        if not current or current["start_ticks"] != original["start_ticks"]:
                            break
                        time.sleep(.02)
                    self.assertFalse(current and current["start_ticks"] == original["start_ticks"], "orphan guardian was not reaped by init/subreaper")
                print(json.dumps({"native_control": "caller-exit", "record": record}), flush=True)
            finally:
                if caller.poll() is None:
                    caller.kill()
                    caller.wait(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
