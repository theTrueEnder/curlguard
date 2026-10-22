"""Offline CI/container example: fetch declared inert data, never run artifacts."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PAYLOADS = {
    "/bootstrap": b"inert bootstrap example\n",
    "/secondary": b"inert secondary example\n",
}


def main():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            body = PAYLOADS[self.path]
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="curlguard-example-") as directory:
            root = Path(directory)
            env = {
                k: v for k, v in os.environ.items() if not k.startswith("CURLGUARD_")
            }
            env.update(
                HOME=directory,
                CURLGUARD_MODE="per-user",
                CURLGUARD_REAL_CURL_PATH="/usr/bin/curl",
                CURLGUARD_LOG_PATH=str(root / "audit.jsonl"),
                CURLGUARD_REQUIRE_HTTPS="false",
                CURLGUARD_REQUIRE_FRESH_RULES="false",
            )
            artifacts = []
            for path, body in PAYLOADS.items():
                artifacts.append(
                    {
                        "id": path[1:] + ".txt",
                        "role": path[1:],
                        "lock": {
                            "schema_version": 1,
                            "kind": "artifact_lock",
                            "source": f"http://127.0.0.1:{server.server_port}{path}",
                            "sha256": hashlib.sha256(body).hexdigest(),
                            "verification": {"scan_required": True},
                        },
                    }
                )
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "bootstrap_manifest",
                        "artifacts": artifacts,
                    }
                )
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "curlguard",
                    "bootstrap",
                    str(manifest),
                    "--output-dir",
                    str(root / "downloads"),
                    "--json",
                ],
                env=env,
                check=True,
            )
            for path, body in PAYLOADS.items():
                assert (root / "downloads" / (path[1:] + ".txt")).read_bytes() == body
            lock = root / "bootstrap.lock.json"
            lock.write_text(json.dumps(artifacts[0]["lock"]))
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "curlguard",
                    "fetch",
                    "--lock",
                    str(lock),
                    "--report",
                    str(root / "report.json"),
                ],
                env=env,
                check=True,
                capture_output=True,
            )
            assert result.stdout == PAYLOADS["/bootstrap"]
            assert (
                json.loads((root / "report.json").read_text())["evidence"]["integrity"]
                == "matched"
            )
            print(
                "Verified each declared artifact. Undeclared secondary downloads remain outside coverage."
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
