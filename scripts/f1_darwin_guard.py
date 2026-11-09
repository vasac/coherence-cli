# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.

"""Private launchd resource-coalition backend for native macOS test commands.

Coalition membership is inherited by fork/spawn and survives setsid/reparenting.
No workload gate opens until its private coalition and ancestor custody agree.
The private libproc ABI is checked at runtime; unavailable accounting fails closed.
"""

import ctypes
import errno
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import sys
import time

CHAIN = "F1_DARWIN_GUARD_CHAIN"


def private_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class DarwinProcesses:
    class BSD(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint32) for name in (
            "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "reserved")]
        _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
        _fields_ += [(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "jobc", "tdev", "tpgid")]
        _fields_ += [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]

    def __init__(self):
        self.lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pidinfo.restype = ctypes.c_int
        self.lib.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_listpids.restype = ctypes.c_int
        if ctypes.sizeof(self.BSD) != 136 or not self.state(os.getpid()) or not self.coalition(os.getpid()):
            raise RuntimeError("MISSING COVERAGE: macOS libproc accounting ABI unavailable")

    def info(self, pid, flavor, value):
        ctypes.set_errno(0)
        size = self.lib.proc_pidinfo(pid, flavor, 0, ctypes.byref(value), ctypes.sizeof(value))
        if size == 0 and ctypes.get_errno() == errno.ESRCH:
            return None
        if size != ctypes.sizeof(value):
            raise OSError(ctypes.get_errno(), f"macOS proc_pidinfo({pid}, {flavor}): {size} bytes")
        return value

    def state(self, pid):
        value = self.info(pid, 3, self.BSD())  # PROC_PIDTBSDINFO
        if value is None:
            return None
        return {"pid": pid, "ppid": value.ppid, "uid": value.uid, "state": value.status,
                "pgid": value.pgid, "birth": [value.start_sec, value.start_usec]}

    def coalition(self, pid):
        value = self.info(pid, 20, (ctypes.c_uint64 * 5)())  # PROC_PIDCOALITIONINFO
        return None if value is None else int(value[0])  # Resource coalition, not process group.

    def pids(self):
        for size in (4096, 16384, 65536, 262144):
            values = (ctypes.c_int * size)()
            count = self.lib.proc_listpids(1, 0, values, ctypes.sizeof(values))  # PROC_ALL_PIDS
            if count <= 0 or count % ctypes.sizeof(ctypes.c_int):
                raise OSError(ctypes.get_errno(), "macOS process enumeration failed")
            if count < ctypes.sizeof(values):
                return {pid for pid in values[:count // ctypes.sizeof(ctypes.c_int)] if pid > 0}
        raise RuntimeError("macOS process enumeration truncated")

    def members(self, coalitions):
        result = {}
        for pid in self.pids():
            cid = self.coalition(pid)
            if cid in coalitions:
                state = self.state(pid)
                if state:
                    if state["uid"] != os.geteuid():
                        raise RuntimeError("owned macOS coalition changed user")
                    state["coalition"] = cid
                    result[pid] = state
        return result

    def same(self, original):
        state = self.state(original["pid"])
        return state if state and state["birth"] == original["birth"] else None

    def send(self, original, signum):
        state = self.same(original)
        if state and state["state"] != 5:  # SZOMB is exited, awaiting its sole parent/launchd reaper.
            if self.coalition(state["pid"]) != original["coalition"]:
                raise RuntimeError("macOS coalition identity changed")
            try:
                os.kill(state["pid"], signum)
            except ProcessLookupError:
                pass


def launchctl(*args, missing_ok=False, timeout=5):
    result = subprocess.run(["/bin/launchctl", *args], capture_output=True, text=True, timeout=timeout)
    if missing_ok and result.returncode == 3:  # Exact already-removed service, not an arbitrary error.
        return
    if result.returncode:
        raise RuntimeError(f"launchctl {args[0]} failed: {result.returncode}: {result.stderr.strip()}")


def guard(request, record, interrupted, cleanup_seconds):
    api = DarwinProcesses()
    directory = Path(request["receipt"]).with_suffix(".darwin")
    directory.mkdir(mode=0o700)
    ledger = directory / "descendants"
    ledger.mkdir(mode=0o700)
    label = "org.oracle.cohctl.f1." + request["nonce"]
    own = api.state(os.getpid())
    # Custody follows the guardian's actual inherited context. A command may
    # deliberately receive a clean environment without dropping its ancestry.
    ancestors = json.loads(os.environ.get(CHAIN, "[]"))
    registrations, job_started, observed = [], False, {}
    bootstrap, exit_record = None, None
    private_json(directory / "owner.json", {"nonce": request["nonce"], "guardian": own})

    def entries():
        result = []
        for path in ledger.glob("*.json"):
            value = json.loads(path.read_text())
            if value["label"] != "org.oracle.cohctl.f1." + value["nonce"]:
                raise RuntimeError("invalid descendant launchd label")
            result.append(value)
        return result

    def observe():
        values = entries()
        ids = {v["coalition"] for v in values if v.get("coalition")}
        if bootstrap:
            ids.add(bootstrap["coalition"])
        result = api.members(ids)
        for state in result.values():
            observed[f"{state['pid']}:{state['birth']}"] = state
        return result

    try:
        # Register pending jobs with all enclosing guardians BEFORE launch. This
        # also contains nested self-tests, whose jobs launch through launchd.
        for ancestor in ancestors:
            parent = Path(ancestor["directory"])
            metadata = json.loads((parent / "owner.json").read_text())
            if metadata["nonce"] != ancestor["nonce"] or parent.stat().st_uid != os.geteuid() or parent.stat().st_mode & 0o077:
                raise RuntimeError("invalid macOS guardian ancestry")
            if api.coalition(os.getpid()) != ancestor["coalition"] and not any(
                    api.coalition(os.getpid()) == item["coalition"] for item in ancestors):
                raise RuntimeError("macOS guardian ancestry is outside its recorded coalition")
            path = parent / "descendants" / (request["nonce"] + ".json")
            value = {"label": label, "nonce": request["nonce"], "coalition": None}
            private_json(path, value)
            registrations.append((path, value))
        env = dict(request["env"])
        private_json(directory / "request.json", {**request, "env": env, "guardian": own,
                                                  "bootstrap_deadline": time.monotonic() + request["timeout"] + 2 * cleanup_seconds + 15})
        plist = directory / "job.plist"
        definition = {"Label": label, "RunAtLoad": True, "ProgramArguments": [sys.executable, str(Path(__file__).resolve()), "--bootstrap", str(directory)]}
        for key, name in (("StandardOutPath", "stdout_path"), ("StandardErrorPath", "stderr_path")):
            if request.get(name):
                definition[key] = request[name]
        plist.write_bytes(plistlib.dumps(definition))
        os.chmod(plist, 0o600)
        job_started = True
        launchctl("bootstrap", "gui/" + str(os.geteuid()), str(plist))
        deadline = time.monotonic() + 10
        while not (directory / "ready.json").exists() and not interrupted[0] and time.monotonic() < deadline:
            time.sleep(.02)
        ready = json.loads((directory / "ready.json").read_text())
        bootstrap = ready["identity"]
        if ready["nonce"] != request["nonce"] or not api.same(bootstrap) or api.coalition(bootstrap["pid"]) != bootstrap["coalition"]:
            raise RuntimeError("macOS bootstrap identity mismatch")
        if bootstrap["ppid"] != 1 or bootstrap["coalition"] in (api.coalition(os.getpid()), api.coalition(1)):
            raise RuntimeError("MISSING COVERAGE: launchd did not create a private resource coalition")
        if set(observe()) != {bootstrap["pid"]}:
            raise RuntimeError("new macOS coalition already has other members")
        record.update(guardian_identity=own, pid=bootstrap["pid"], pid_role="launchd gated bootstrap",
                      resource_coalition=bootstrap["coalition"], launchd_label=label)
        for path, value in registrations:
            value["coalition"] = bootstrap["coalition"]
            private_json(path, value)
        chain = ancestors + [{"directory": str(directory), "nonce": request["nonce"], "coalition": bootstrap["coalition"]}]
        private_json(directory / "gate.json", {"nonce": request["nonce"], "chain": chain})
        deadline = time.monotonic() + request["timeout"]
        while not interrupted[0] and time.monotonic() < deadline:
            observe()
            if (directory / "exit.json").exists():
                exit_record = json.loads((directory / "exit.json").read_text())
                if exit_record["nonce"] != request["nonce"]:
                    raise RuntimeError("macOS command exit nonce mismatch")
                break
            if not api.same(bootstrap):
                raise RuntimeError("macOS bootstrap exited without command result")
            time.sleep(.02)
        record["exit"] = None if exit_record is None else exit_record["exit"]
        pending = observe()
        pending.pop(bootstrap["pid"], None)
        if exit_record is None or pending:
            record["rescue"] = True
            record["reason"] = "interrupted" if interrupted[0] else "timeout" if exit_record is None else "descendants survived command exit"
        else:
            private_json(directory / "release.json", {"nonce": request["nonce"]})
    except BaseException as error:
        record["errors"].append(repr(error))
        record["rescue"] = True
    finally:
        deadline = time.monotonic() + cleanup_seconds
        while True:
            try:
                pending = observe()
                # Include observed zombies until their actual parent/launchd reaps
                # them. They no longer have an active kernel coalition task.
                for state in observed.values():
                    current = api.same(state)
                    if current:
                        pending.setdefault(state["pid"], state)
                if not pending:
                    break
                if record["rescue"]:
                    for signum in (signal.SIGSTOP, signal.SIGKILL):
                        for state in pending.values():
                            api.send(state, signum)
                if time.monotonic() >= deadline:
                    break
                time.sleep(.02)
            except BaseException as error:
                record["errors"].append("macOS cleanup: " + repr(error))
                record["rescue"] = True
                pending = {"accounting_unresolved": True}
                break
        record["remaining_owned"] = pending
        # Remove only explicitly registered task jobs after process accounting.
        try:
            jobs = entries()
        except BaseException as error:
            record["errors"].append("macOS descendant job accounting: " + repr(error))
            jobs = []
        for value in jobs + ([{"label": label}] if job_started else []):
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("macOS shared cleanup deadline expired before job removal")
                launchctl("bootout", "gui/" + str(os.geteuid()) + "/" + value["label"],
                          missing_ok=True, timeout=min(5, remaining))
            except BaseException as error:
                record["errors"].append("macOS job removal: " + repr(error))
        (directory / "request.json").unlink(missing_ok=True)
        record["observed_identities"] = observed
        record["wait_owner"] = "bootstrap Popen for command; launchd for bootstrap and reparented descendants; caller Popen for guardian"


def bootstrap_main(directory):
    api = DarwinProcesses()
    path = directory / "request.json"
    request = json.loads(path.read_text())
    path.unlink()
    own = api.state(os.getpid())
    own["coalition"] = api.coalition(os.getpid())
    private_json(directory / "ready.json", {"nonce": request["nonce"], "identity": own})
    while not (directory / "gate.json").exists():
        if time.monotonic() >= request["bootstrap_deadline"] or not api.same(request["guardian"]):
            raise SystemExit(125)
        time.sleep(.02)
    gate = json.loads((directory / "gate.json").read_text())
    if gate["nonce"] != request["nonce"]:
        raise RuntimeError("macOS gate nonce mismatch")
    env = dict(request["env"], **{CHAIN: json.dumps(gate["chain"])})
    child = subprocess.Popen(request["argv"], cwd=request["cwd"], env=env, stdin=subprocess.DEVNULL)
    code = child.wait()  # Sole command Wait owner; guardian has the independent timeout.
    private_json(directory / "exit.json", {"nonce": request["nonce"], "exit": code})
    while not (directory / "release.json").exists():
        if time.monotonic() >= request["bootstrap_deadline"]:
            raise SystemExit(125)
        time.sleep(.02)
    if json.loads((directory / "release.json").read_text())["nonce"] != request["nonce"]:
        raise RuntimeError("macOS release nonce mismatch")
    raise SystemExit(0)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--bootstrap":
        raise SystemExit("private F1 macOS bootstrap")
    bootstrap_main(Path(sys.argv[2]))
