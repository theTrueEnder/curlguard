#!/usr/bin/env python3
"""Serve a clean script for curlguard false-positive testing."""

import http.server
import os
import socketserver
import threading
import time

PORT = 8889
TTL_SECONDS = 180

SAFE_SCRIPT = b"""#!/bin/bash
set -e
echo "curlguard clean test script"
echo "This script is expected to pass without opening the review prompt."
"""


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/install.sh":
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(SAFE_SCRIPT)))
        self.end_headers()
        self.wfile.write(SAFE_SCRIPT)

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    with ReusableTCPServer(("127.0.0.1", PORT), QuietHandler) as listener:

        def expire() -> None:
            time.sleep(TTL_SECONDS)
            print(f"\n[Test server expired after {TTL_SECONDS} seconds]", flush=True)
            listener.shutdown()

        threading.Thread(target=expire, daemon=True).start()

        print(
            f"curlguard true-negative server is running on http://127.0.0.1:{PORT}",
            flush=True,
        )
        print("Serving: /install.sh", flush=True)
        print(
            "Expected result: the file downloads without a malware prompt.", flush=True
        )
        print(f"Server lifetime: {TTL_SECONDS} seconds", flush=True)
        print("", flush=True)
        print("Run in another terminal:", flush=True)
        print(
            "  curlguard http://127.0.0.1:8889/install.sh -o /tmp/curlguard-demo.sh",
            flush=True,
        )
        print("", flush=True)

        try:
            listener.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
