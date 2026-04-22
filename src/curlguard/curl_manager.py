"""Curl binary manager module for curlguard."""
import os
import shutil
from pathlib import Path


class CurlManager:
    def __init__(self, mode: str = "per-user") -> None:
        self._mode = mode
        if mode == "per-user":
            self._curl_path = Path.home() / ".local/bin" / "curl"
            self._curl_real = Path.home() / ".local/bin" / "curl.real"
        else:
            self._curl_path = Path("/usr/bin/curl")
            self._curl_real = Path("/usr/bin/curl.real")

    def is_installed(self) -> bool:
        return self._curl_real.exists() and self._curl_path.exists()

    def install(self) -> None:
        if self._curl_real.exists():
            return  # Already installed

        # Create local bin if needed
        self._curl_path.parent.mkdir(parents=True, exist_ok=True)

        # Rename original curl
        if self._curl_path.exists():
            shutil.move(str(self._curl_path), str(self._curl_real))

        # Create wrapper script
        self._curl_path.write_text(
            "#!/bin/sh\n"
            "exec curlguard \"$@\"\n"
        )
        os.chmod(self._curl_path, 0o755)

    def uninstall(self) -> None:
        if not self._curl_real.exists():
            return

        # Remove wrapper
        if self._curl_path.exists():
            self._curl_path.unlink()

        # Restore original
        shutil.move(str(self._curl_real), str(self._curl_path))

    def call_real_curl(self, args: list[str], env: dict) -> subprocess.CompletedProcess:
        import subprocess
        return subprocess.run(
            [str(self._curl_real)] + args,
            env={**os.environ, **env},
            capture_output=True,
        )