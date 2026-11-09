# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.

"""Bound native test commands, including descendants in different process groups.

Linux uses a private subreaper, Windows a non-breakaway Job Object, and macOS a
private launchd resource coalition. No workload starts without verified custody.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import uuid

CLEANUP_SECONDS = 15


def backend():
    system = platform.system()
    if system == "Linux":
        return "linux-subreaper"
    if system == "Windows":
        return "windows-job"
    if system == "Darwin":
        import f1_darwin_guard
        f1_darwin_guard.DarwinProcesses()  # Verify the local accounting ABI before dispatch.
        return "darwin-coalition"
    raise RuntimeError("MISSING COVERAGE: complete native-runner containment requires Linux, Windows or macOS; "
                       + system + " has no implemented backend (process groups alone are insufficient)")


def linux_state(pid):
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return None
    fields = raw[raw.rindex(") ") + 2:].split()
    return {"pid": pid, "ppid": int(fields[1]), "state": fields[0], "start_ticks": int(fields[19])}


def linux_children(pid):
    """Include children forked by any thread, not just the process leader."""
    result = set()
    try:
        tasks = list((Path("/proc") / str(pid) / "task").iterdir())
    except (FileNotFoundError, ProcessLookupError):
        return result
    for task in tasks:
        try:
            result.update(map(int, (task / "children").read_text().split()))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return result


def linux_tree():
    result, pending = {}, [os.getpid()]
    while pending:
        parent = pending.pop()
        for pid in linux_children(parent):
            if pid in result:
                continue
            state = linux_state(pid)
            if state and state["ppid"] == parent:
                result[pid] = state
                pending.append(pid)
    return result


def linux_signal(original, signum):
    current = linux_state(original["pid"])
    if current and current["start_ticks"] == original["start_ticks"] and current["state"] != "Z":
        try:
            os.kill(original["pid"], signum)
        except ProcessLookupError:
            pass


def linux_guard(request, record, interrupted):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    # Only this separate guardian becomes a subreaper; never change the caller.
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
    enabled = ctypes.c_int()
    if libc.prctl(37, ctypes.addressof(enabled), 0, 0, 0) != 0 or enabled.value != 1:
        raise RuntimeError("subreaper verification failed")
    own = os.getpid()
    record["guardian_identity"] = linux_state(own)
    if record["guardian_identity"] is None:
        raise RuntimeError("MISSING COVERAGE: guardian /proc birth identity unavailable")
    # An absent children interface is not an empty process tree. Verify this
    # kernel capability before dispatch, then tolerate only actual exit races.
    (Path("/proc") / str(own) / "task" / str(own) / "children").read_text()
    child = subprocess.Popen(request["argv"], cwd=request["cwd"], env=request["env"], stdin=subprocess.DEVNULL)
    record["pid"] = child.pid
    record["pid_role"] = "command"
    observed = {}

    def observe():
        tree = linux_tree()
        for state in tree.values():
            observed[f"{state['pid']}:{state['start_ticks']}"] = state
        return tree

    def reap_adopted(tree):
        # Popen alone owns the command's Wait. This guardian alone owns Wait for
        # orphaned descendants, and only after the kernel reparents them here.
        for pid, state in tree.items():
            if pid != child.pid and state["ppid"] == os.getpid():
                try:
                    reaped, status = os.waitpid(pid, os.WNOHANG)
                    if reaped:
                        record.setdefault("adopted_reaped", []).append({"pid": reaped, "status": status})
                except ChildProcessError:
                    pass

    try:
        deadline = time.monotonic() + request["timeout"]
        while child.poll() is None and not interrupted[0] and time.monotonic() < deadline:
            reap_adopted(observe())
            time.sleep(.02)
        record["exit"] = child.poll()
        pending = observe()
        reap_adopted(pending)
        pending = observe()
        if record["exit"] is None or pending:
            record["rescue"] = True
            record["reason"] = "interrupted" if interrupted[0] else "timeout" if record["exit"] is None else "descendants survived command exit"
    except BaseException as error:
        record["errors"].append(repr(error))
        record["rescue"] = True
    finally:
        deadline = time.monotonic() + CLEANUP_SECONDS
        observation_failed = False
        while True:
            try:
                tree = observe()
                reap_adopted(tree)
                tree = observe()
            except (OSError, ValueError) as error:
                text = "owned process observation: " + repr(error)
                if text not in record["errors"]:
                    record["errors"].append(text)
                observation_failed = True
                tree = {state["pid"]: state for state in observed.values()}
            child.poll()
            if not tree and not observation_failed:
                break
            record["rescue"] = True
            # Freeze before killing and rescan on the next pass. Adoption retains
            # custody if an intermediate parent exits between scans; groups and
            # sessions do not change that kernel ancestry/adoption boundary.
            for signum in (signal.SIGSTOP, signal.SIGKILL):
                for state in tree.values():
                    try:
                        linux_signal(state, signum)
                    except OSError as error:
                        text = f"signal owned PID {state['pid']}: {error!r}"
                        if text not in record["errors"]:
                            record["errors"].append(text)
            # This retained direct child cannot be reused before this sole
            # Popen owner reaps it, even if /proc inspection itself failed.
            if child.poll() is None:
                try:
                    child.kill()
                except ProcessLookupError:
                    pass
                except OSError as error:
                    record["errors"].append("kill owned command: " + repr(error))
            if time.monotonic() >= deadline:
                break
            observation_failed = False
            time.sleep(.02)
        try:
            record["remaining_owned"] = observe()
        except (OSError, ValueError) as error:
            record["remaining_owned"] = {"observation_unresolved": repr(error)}
        if child.poll() is not None:
            record["exit"] = child.wait()  # Same Popen owner, no competing waitpid.
        record["observed_identities"] = observed
        record["wait_owner"] = "guardian Popen for command; guardian waitpid for adopted children only"


class WindowsJob:
    def __init__(self):
        from ctypes import wintypes as w

        class Limits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class Extended(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", Limits), ("IoInfo", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        class Accounting(ctypes.Structure):
            _fields_ = [(name, ctypes.c_int64) for name in ("TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime", "ThisPeriodTotalKernelTime")] + [
                (name, w.DWORD) for name in ("TotalPageFaultCount", "TotalProcesses", "ActiveProcesses", "TotalTerminatedProcesses")]

        self.accounting_type = Accounting
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            method = getattr(self.kernel, name)
            method.argtypes, method.restype = arguments, result
        self.handle = self.kernel.CreateJobObjectW(None, None)  # Private, non-inheritable, unnamed handle.
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            limits = Extended()
            limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE, with neither breakaway flag.
            self.check(self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
        except BaseException:
            self.close()
            raise

    @staticmethod
    def check(success):
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, child):
        # The CPython-created process handle is retained while bootstrap waits
        # for its gate. No numeric-PID reopening or assignment-after-dispatch.
        self.check(self.kernel.AssignProcessToJobObject(self.handle, int(child._handle)))

    def active(self):
        value = self.accounting_type()
        self.check(self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(value), ctypes.sizeof(value), None))
        return value.ActiveProcesses

    def terminate(self):
        self.check(self.kernel.TerminateJobObject(self.handle, 1))

    def close(self):
        if self.handle:
            self.check(self.kernel.CloseHandle(self.handle))
            self.handle = None


def windows_guard(request, record, interrupted, job_factory=WindowsJob):
    job, child = job_factory(), None
    try:
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--gated"],
                                 stdin=subprocess.PIPE, env=request["env"])
        record["pid"] = child.pid
        record["pid_role"] = "gated bootstrap; command is its child"
        try:
            job.assign(child)
        except BaseException:
            child.kill()  # Only the gated bootstrap exists; no workload was dispatched.
            child.wait(timeout=CLEANUP_SECONDS)
            raise
        child.stdin.write(json.dumps(request).encode() + b"\n")
        child.stdin.flush()
        child.stdin.close()
        record["workload_dispatched_after_job_assignment"] = True
        deadline = time.monotonic() + request["timeout"]
        while child.poll() is None and not interrupted[0] and time.monotonic() < deadline:
            time.sleep(.02)
        record["exit"] = child.poll()
        if record["exit"] is None or job.active():
            record["rescue"] = True
            record["reason"] = "interrupted" if interrupted[0] else "timeout" if record["exit"] is None else "descendants survived command exit"
    except BaseException as error:
        record["errors"].append(repr(error))
        record["rescue"] = True
    finally:
        try:
            deadline = time.monotonic() + CLEANUP_SECONDS
            if child is not None:
                if job.active():
                    record["rescue"] = True
                    job.terminate()
                child.wait(timeout=max(.01, deadline - time.monotonic()))  # Guardian alone owns bootstrap's Wait.
                while job.active() and time.monotonic() < deadline:
                    time.sleep(.02)
                record["exit"] = child.returncode
            active = job.active()
            record["remaining_owned"] = {"job_active_processes": active} if active else {}
            record["wait_owner"] = "guardian Popen for bootstrap; bootstrap Popen for command; Job Object for descendants"
        except BaseException as error:
            record["errors"].append("job cleanup: " + repr(error))
            record["rescue"] = True
            record["remaining_owned"] = {"job_cleanup_unresolved": True}
        finally:
            job.close()  # Kernel cleanup backstop even if accounting/wait fails.


def run_owned(argv, cwd, env, stdout, stderr, timeout, receipt_path):
    selected = backend()  # Fail before any command is spawned on unsupported systems.
    path = Path(receipt_path)
    request = {"argv": list(argv), "cwd": str(cwd), "env": dict(env), "timeout": timeout,
               "receipt": str(path), "nonce": uuid.uuid4().hex}
    if selected == "darwin-coalition":
        request.update(stdout_path=str(Path(stdout.name).resolve()) if stdout is not None else None,
                       stderr_path=str(Path(stderr.name).resolve()) if stderr is not None else None)
    request_path = path.with_suffix(".request.json")
    descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(request, stream)
    started = time.monotonic()
    try:
        guardian = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--guard", str(request_path)],
                                    stdout=stdout, stderr=stderr, start_new_session=os.name == "posix")
        try:
            code = guardian.wait(timeout=timeout + 2 * CLEANUP_SECONDS + 10)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                guardian.kill()  # Kernel closes its sole non-inherited job handle and terminates the job.
            else:
                guardian.send_signal(signal.SIGTERM)  # Preserve subreaper custody during independent cleanup.
            try:
                guardian.wait(timeout=2 * CLEANUP_SECONDS + 5)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError(f"guardian cleanup unresolved; retained owner PID {guardian.pid}, receipt {path}") from error
            raise RuntimeError(f"guardian exceeded independent deadline; receipt {path}")
        record = json.loads(path.read_text())
        assert record["nonce"] == request["nonce"] and record["backend"] == selected
        assert record["guard_sha256"] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "guardian source drift"
        if selected == "darwin-coalition":
            assert record["backend_sha256"] == hashlib.sha256(Path(__file__).with_name("f1_darwin_guard.py").read_bytes()).hexdigest(), "macOS backend source drift"
        record.update(guardian_pid=guardian.pid, guardian_exit=code, elapsed=time.monotonic() - started)
        return record
    finally:
        request_path.unlink(missing_ok=True)  # Contains inherited environment; receipt retains no environment values.


def main():
    if sys.argv[1:] == ["--gated"]:
        # Assignment failure/guardian death closes stdin: do not start a workload.
        raw = sys.stdin.buffer.readline()
        if not raw:
            raise SystemExit(125)
        request = json.loads(raw)
        child = subprocess.Popen(request["argv"], cwd=request["cwd"], env=request["env"], stdin=subprocess.DEVNULL)
        raise SystemExit(child.wait())
    if len(sys.argv) != 3 or sys.argv[1] != "--guard":
        raise SystemExit("private F1 native command guardian")
    request_path = Path(sys.argv[2])
    request = json.loads(request_path.read_text())
    request_path.unlink()  # Do not retain inherited environment if the caller is lost.
    record = {"nonce": request["nonce"], "backend": backend(), "argv": request["argv"], "timeout": request["timeout"],
              "guard_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "rescue": False,
              "exit": None, "errors": [], "remaining_owned": {"cleanup_not_confirmed": True}, "guardian_pid": os.getpid()}
    interrupted = [False]
    signal.signal(signal.SIGTERM, lambda *unused: interrupted.__setitem__(0, True))
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, lambda *unused: interrupted.__setitem__(0, True))
    try:
        if record["backend"] == "darwin-coalition":
            import f1_darwin_guard
            record["backend_sha256"] = hashlib.sha256(Path(f1_darwin_guard.__file__).read_bytes()).hexdigest()
            f1_darwin_guard.guard(request, record, interrupted, CLEANUP_SECONDS)
        else:
            (linux_guard if record["backend"] == "linux-subreaper" else windows_guard)(request, record, interrupted)
    except BaseException as error:
        record["errors"].append(repr(error))
        record["rescue"] = True
    receipt = Path(request["receipt"])
    temporary = receipt.with_suffix(".receipt-tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(json.dumps(record, indent=2) + "\n")
        os.replace(temporary, receipt)
    finally:
        temporary.unlink(missing_ok=True)
    raise SystemExit(0 if record["exit"] == 0 and not record["rescue"] and not record["errors"] and not record["remaining_owned"] else 1)


if __name__ == "__main__":
    main()
