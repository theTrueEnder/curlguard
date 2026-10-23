"""Run curl in a process group and forward cancellation without orphaning it."""

import os
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path


class Interrupted(BaseException):
    def __init__(self, signum):
        self.signum = signum


class TransferBudgetError(OSError):
    pass


@contextmanager
def cancellation():
    previous = {}

    def interrupt(signum, frame):
        raise Interrupted(signum)

    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGHUP):
            previous[sig] = signal.signal(sig, interrupt)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def run(command, *, max_bytes=None, staged=None, deadline=None, **kwargs):
    # Preserve the controlling terminal for native interactive authentication.
    separate_group = not os.isatty(0)
    original = command
    if max_bytes is not None:
        if staged.stat().st_size > max_bytes:
            raise TransferBudgetError("staged_byte_limit")
        command = [
            sys.executable,
            "-I",
            str(Path(__file__).with_name("transfer_worker.py")),
            str(max_bytes),
            *command,
        ]
    child = subprocess.Popen(command, start_new_session=separate_group, **kwargs)
    previous = {}

    def forward(signum, frame):
        try:
            if separate_group:
                os.killpg(child.pid, signum)
            else:
                child.send_signal(signum)
        except ProcessLookupError:
            pass

    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[sig] = signal.signal(sig, forward)
    try:
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                forward(signal.SIGKILL, None)
                child.communicate()
                raise TransferBudgetError("transfer_time_limit")
            try:
                stdout, stderr = child.communicate(
                    timeout=0.05 if deadline is not None else None
                )
                break
            except subprocess.TimeoutExpired:
                continue
        if (
            max_bytes is not None
            and child.returncode
            and staged.stat().st_size >= max_bytes
        ):
            raise TransferBudgetError("staged_byte_limit")
        return subprocess.CompletedProcess(
            original,
            128 - child.returncode if child.returncode < 0 else child.returncode,
            stdout,
            stderr,
        )
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        if child.poll() is None:
            forward(signal.SIGTERM, None)
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                forward(signal.SIGKILL, None)
                child.wait()
