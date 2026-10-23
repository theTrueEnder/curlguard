"""Isolated Linux network-namespace demonstration; no host policy changes."""

import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"inert")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/"
    env = {
        **os.environ,
        "CURLGUARD_REQUIRE_SHA256": "true",
        "CURLGUARD_MATCH_POLICY": "block",
        "http_proxy": "",
        "https_proxy": "",
        "ALL_PROXY": "",
        "NO_PROXY": "*",
    }
    clients = [
        ["/usr/bin/curl", "--disable", "--silent", "--fail", "--max-time", "1", url],
        [
            sys.executable,
            "-I",
            "-c",
            "import urllib.request; print(urllib.request.urlopen("
            + repr(url)
            + ", timeout=1).read())",
        ],
    ]
    try:
        for client in clients:
            direct = subprocess.run(client, env=env, capture_output=True, timeout=5)
            assert direct.returncode == 0 and b"inert" in direct.stdout
            isolated = subprocess.run(
                ["unshare", "--user", "--map-root-user", "--net", *client],
                env=env,
                capture_output=True,
                timeout=5,
            )
            if b"unshare failed" in isolated.stderr:
                raise SystemExit(
                    "Network namespaces unavailable; boundary demonstration was NOT verified."
                )
            assert isolated.returncode != 0 and b"inert" not in isolated.stdout
        print(
            "Absolute curl and another HTTP client bypass local wrapper policy. Both are blocked by an isolated network namespace independently of environment settings."
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
