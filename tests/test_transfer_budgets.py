"""Real curl, hostile local streams and bounded staged files."""

import errno
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from curlguard.process import run


@pytest.fixture
def hostile_server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            if self.path == "/chunked":
                self.send_header("Transfer-Encoding", "chunked")
            elif self.path == "/misleading":
                self.send_header("Content-Length", "99999999")
            self.end_headers()
            try:
                if self.path == "/chunked":
                    while True:
                        self.wfile.write(b"1000\r\n" + b"x" * 4096 + b"\r\n")
                        self.wfile.flush()
                elif self.path == "/endless":
                    while True:
                        self.wfile.write(b"x" * 4096)
                        self.wfile.flush()
                else:
                    for _ in range(100):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.1)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.mark.parametrize(
    "path,budget",
    [
        ("/chunked", "bytes"),
        ("/endless", "bytes"),
        ("/trickle", "time"),
        ("/misleading", "time"),
    ],
)
def test_hostile_transfer_budgets(cli, hostile_server, tmp_path, path, budget):
    output, etag = tmp_path / "out", tmp_path / "etag"
    output.write_bytes(b"preserved")
    etag.write_bytes(b"old-etag")
    started = time.monotonic()
    result = cli(
        [hostile_server + path, "-o", output, "--etag-save", etag],
        overrides={
            "CURLGUARD_MAX_STAGED_BYTES": "4096",
            "CURLGUARD_TRANSFER_TIMEOUT_SECONDS": "1",
        },
    )
    assert result.returncode == 18
    assert time.monotonic() - started < 2.5
    assert output.read_bytes() == b"preserved" and etag.read_bytes() == b"old-etag"
    assert not result.stdout and not list(tmp_path.glob(".curlguard-*"))
    audit = json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])
    assert audit["decision_reason"] == (
        "staged_byte_limit" if budget == "bytes" else "transfer_time_limit"
    )


def test_decompression_and_resumed_prefix(cli, http_server, tmp_path):
    output = tmp_path / "out"
    output.write_bytes(b"preserved")
    result = cli(
        [http_server[0] + "/gzip", "--compressed", "-o", output],
        overrides={"CURLGUARD_MAX_STAGED_BYTES": "1024"},
    )
    assert result.returncode == 18 and output.read_bytes() == b"preserved"
    output.write_bytes(b"x" * 2048)
    requests = len(http_server[1])
    result = cli(
        [http_server[0] + "/artifact", "-C", "-", "-o", output],
        overrides={"CURLGUARD_MAX_STAGED_BYTES": "1024"},
    )
    assert result.returncode == 18
    assert len(http_server[1]) == requests and output.read_bytes() == b"x" * 2048
    from tests.conftest import PAYLOAD

    output.write_bytes(PAYLOAD[:512])
    result = cli(
        [http_server[0] + "/artifact", "-C", "-", "-o", output],
        overrides={"CURLGUARD_MAX_STAGED_BYTES": "1024"},
    )
    assert result.returncode == 18 and output.read_bytes() == PAYLOAD[:512]
    result = cli(
        [http_server[0] + "/retry", "--retry", "1", "--retry-delay", "0", "-o", output],
        overrides={"CURLGUARD_MAX_STAGED_BYTES": "1024"},
    )
    assert result.returncode == 18 and output.read_bytes() == PAYLOAD[:512]


def test_kernel_ceiling_has_zero_byte_overshoot(tmp_path):
    payload = tmp_path / "staged"
    payload.touch()
    # Real curl writes a large local inert file; the kernel enforces exact size.
    source = tmp_path / "source"
    source.write_bytes(b"x" * 1048576)
    from curlguard.process import TransferBudgetError

    with pytest.raises(TransferBudgetError):
        run(
            [
                os.environ.get("CURLGUARD_TEST_CURL", "/usr/bin/curl"),
                "--disable",
                "--silent",
                "file://" + str(source),
                "--output",
                str(payload),
            ],
            max_bytes=4096,
            staged=payload,
            deadline=time.monotonic() + 2,
            stdout=subprocess.PIPE,
        )
    assert payload.stat().st_size == 4096


def test_disk_exhaustion_preserves_outputs(monkeypatch, tmp_path):
    from curlguard.config import CurlGuardConfig
    from curlguard.logger import AuditLogger
    from curlguard.scanner import YaraScanner
    from curlguard.ssl_detector import SslBypassDetector
    from curlguard.wrapper import CurlWrapper

    output, etag = tmp_path / "out", tmp_path / "etag"
    output.write_bytes(b"old")
    etag.write_bytes(b"tag")
    cfg = CurlGuardConfig(
        "per-user",
        tmp_path / "audit",
        require_sha256=False,
        require_https=False,
        verify_certificates=False,
        min_tls=None,
        redirect_protocols=(),
        require_fresh_rules=False,
    )
    wrapper = CurlWrapper(
        cfg, YaraScanner(), AuditLogger(cfg.log_path), SslBypassDetector()
    )

    def exhausted(*args, **kwargs):
        raise OSError(errno.ENOSPC, "isolated simulated disk full")

    monkeypatch.setattr("curlguard.wrapper.run", exhausted)
    assert (
        wrapper.dispatch(
            [
                "--disable",
                "https://example.test/artifact",
                "-o",
                str(output),
                "--etag-save",
                str(etag),
            ]
        )
        == 16
    )
    assert output.read_bytes() == b"old" and etag.read_bytes() == b"tag"
    assert not list(tmp_path.glob(".curlguard-*"))


def test_real_isolated_disk_exhaustion(cli, http_server, tmp_path, monkeypatch):
    """A tiny private tmpfs; no live mount or host disk is filled."""
    mountpoint = tmp_path / "isolated-mount"
    mountpoint.mkdir()
    monkeypatch.setattr("tests.conftest.PAYLOAD", b"inert" * 65536)
    script = r"""
import errno, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
mounted = subprocess.run(["mount", "-t", "tmpfs", "-o", "size=16384", "tmpfs", str(root)], capture_output=True)
if mounted.returncode:
    print("isolated tmpfs unavailable")
    sys.exit(77)
output, etag = root / "out", root / "etag"
output.write_bytes(b"preserved")
etag.write_bytes(b"old-etag")
result = subprocess.run([sys.executable, "-m", "curlguard.cli", "--as-curl", "--disable", sys.argv[2], "-o", str(output), "--etag-save", str(etag)], capture_output=True, timeout=10)
assert result.returncode != 0, result
assert output.read_bytes() == b"preserved" and etag.read_bytes() == b"old-etag"
assert not list(root.glob(".curlguard-*"))
try:
    (root / "probe").write_bytes(b"x" * 65536)
except OSError as exc:
    assert exc.errno == errno.ENOSPC
else:
    raise AssertionError("tmpfs was not capacity-limited")
print("isolated ENOSPC verified")
"""
    result = subprocess.run(
        [
            "unshare",
            "--user",
            "--map-root-user",
            "--mount",
            sys.executable,
            "-c",
            script,
            str(mountpoint),
            http_server[0] + "/artifact",
        ],
        env=cli.env,
        capture_output=True,
        timeout=15,
    )
    if result.returncode == 77 or b"unshare failed" in result.stderr:
        pytest.skip("kernel/container does not permit isolated user-namespace tmpfs")
    assert result.returncode == 0, result.stderr.decode()
    assert b"isolated ENOSPC verified" in result.stdout
