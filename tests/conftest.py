"""Network-independent HTTP and HTTPS fixtures for differential curl checks."""

import gzip
import os
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
PAYLOAD = b"clean update artifact\x00\xff\n" * 100
MALWARE = b"#!/bin/sh\necho ZWNobyB1bnNhZmU= | base64 -d | bash\n"


@pytest.fixture
def http_server():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append((self.path, dict(self.headers)))
            path = self.path.split("?", 1)[0]
            if path == "/slow":
                time.sleep(3)
            body = PAYLOAD
            status = 200
            headers = {}
            if path == "/empty":
                body = b""
            elif path == "/malware":
                body = MALWARE
            elif path == "/redirect":
                status, body, headers = 302, b"", {"Location": "/artifact"}
            elif path == "/loop":
                status, body, headers = 302, b"", {"Location": "/loop"}
            elif path == "/missing":
                status, body = 404, b"missing"
            elif path == "/retry" and sum(p == "/retry" for p, _ in requests) % 2:
                status, body = 503, b"try again"
            elif path == "/gzip":
                body = gzip.compress(body)
                headers["Content-Encoding"] = "gzip"
            elif path == "/conditional":
                headers = {
                    "ETag": '"v1"',
                    "Last-Modified": "Wed, 01 Jan 2020 00:00:00 GMT",
                }
                if (
                    self.headers.get("If-Modified-Since")
                    or self.headers.get("If-None-Match") == '"v1"'
                ):
                    status, body = 304, b""
            if path in {"/artifact", "/malware", "/bad-range"} and self.headers.get(
                "Range"
            ):
                start = int(self.headers["Range"].split("=")[1].split("-")[0])
                whole = body
                if start >= len(whole):
                    status, body = 416, b""
                    headers["Content-Range"] = f"bytes */{len(whole)}"
                else:
                    status, body = 206, whole[start:]
                    headers["Content-Range"] = (
                        "garbage"
                        if path == "/bad-range"
                        else f"bytes {start}-{len(whole) - 1}/{len(whole)}"
                    )
            self.send_response(status)
            self.send_header(
                "Content-Length", str(len(body) + (100 if path == "/truncated" else 0))
            )
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            if path == "/truncated":
                self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", requests, server
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.fixture
def https_server(http_server, tmp_path):
    _, requests, server = http_server
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    yield f"https://127.0.0.1:{server.server_port}", cert


@pytest.fixture
def cli(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("CURLGUARD_")}
    env.update(
        HOME=str(home),
        CURL_HOME=str(home),
        XDG_CONFIG_HOME=str(home),
        PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
        CURLGUARD_MODE="per-user",
        CURLGUARD_LOG_PATH=str(tmp_path / "audit.log"),
        CURLGUARD_QUARANTINE=str(tmp_path / "quarantine"),
        CURLGUARD_SCAN_FAILURE_MODE="block",
        CURLGUARD_REQUIRE_SHA256="false",
        CURLGUARD_REQUIRE_HTTPS="false",
        CURLGUARD_VERIFY_CERTIFICATES="false",
        CURLGUARD_MIN_TLS="none",
        CURLGUARD_REDIRECT_PROTOCOLS="",
        CURLGUARD_REQUIRE_FRESH_RULES="false",
        CURLGUARD_UNSUPPORTED_POLICY="passthrough",
        CURLGUARD_REAL_CURL_PATH=os.environ.get("CURLGUARD_TEST_CURL", "/usr/bin/curl"),
    )

    def invoke(args, *, guarded=True, overrides=None, management=False):
        command = (
            [
                sys.executable,
                "-m",
                "curlguard.cli",
                *([] if management else ["--as-curl"]),
            ]
            if guarded
            else [env["CURLGUARD_REAL_CURL_PATH"]]
        )
        return subprocess.run(
            [*command, *map(str, args)],
            env={**env, **(overrides or {})},
            cwd=tmp_path,
            capture_output=True,
            timeout=15,
        )

    invoke.env = env
    return invoke
