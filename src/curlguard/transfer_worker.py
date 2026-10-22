"""Set a kernel file-size ceiling, then replace this process with real curl."""

import os
import resource
import signal
import sys

if __name__ == "__main__":
    limit = int(sys.argv[1])
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
    os.execv(sys.argv[2], sys.argv[2:])
