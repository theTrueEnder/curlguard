"""Run curl in a process group and forward cancellation without orphaning it."""

import os
import signal
import subprocess
import threading
from contextlib import contextmanager


class Interrupted(BaseException):
    def __init__(self, signum):
        self.signum = signum


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


def run(command, **kwargs):
    # Preserve the controlling terminal for native interactive authentication.
    separate_group = not os.isatty(0)
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
        stdout, stderr = child.communicate()
        return subprocess.CompletedProcess(
            command,
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
