# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.

"""Short, owned descendants for the native-runner containment regression."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

mode, directory = sys.argv[1], Path(sys.argv[2])
if mode == "leaf":
    (directory / (str(os.getpid()) + ".json")).write_text(json.dumps({"pid": os.getpid(), "ppid": os.getppid(), "mode": mode}))
    time.sleep(20)  # Independent fixture limit, never the qualification cleanup.
    raise SystemExit(0)
if mode == "branch":
    options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    subprocess.Popen([sys.executable, __file__, "leaf", str(directory)], **options)
    # Leave the new-session child to the Linux subreaper / Windows Job Object.
    raise SystemExit(0)
child = subprocess.Popen([sys.executable, __file__, "branch", str(directory)])
child.wait()  # Sole owner of intermediate branch's Wait.
deadline = time.monotonic() + 5
while not list(directory.glob("[0-9]*.json")) and time.monotonic() < deadline:
    time.sleep(.01)
if mode == "timeout":
    time.sleep(20)
elif mode != "leak":
    raise SystemExit("unknown fixture mode")
