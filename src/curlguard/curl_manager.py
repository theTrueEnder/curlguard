"""Curl binary manager module for curlguard."""
import os
import shutil
import subprocess
from pathlib import Path


def _discover_system_curl() -> Path:
    for candidate in (
        Path("/usr/bin/curl.real"),
        Path("/usr/bin/curl"),
        Path("/usr/local/bin/curl"),
        Path("/bin/curl"),
    ):
        if candidate.exists():
            return candidate

    discovered = shutil.which("curl", path="/usr/bin:/usr/local/bin:/bin")
    if discovered:
        return Path(discovered)
    return Path("/usr/bin/curl")


class CurlManager:
    def __init__(self, mode: str = "per-user") -> None:
        self._mode = mode
        if mode == "per-user":
            self._curl_path = Path.home() / ".local/bin" / "curl"
            self._curl_real = _discover_system_curl()
        else:
            self._curl_path = Path("/usr/bin/curl")
            self._curl_real = Path("/usr/bin/curl.real")

    def is_installed(self) -> bool:
        return self._curl_real.exists() and self._curl_path.exists()

    def install(self) -> None:
        if self._mode == "per-user" and self._curl_path.exists():
            return  # Already installed
        if self._mode == "system-wide" and self._curl_real.exists():
            return  # Already installed

        # Create local bin if needed
        self._curl_path.parent.mkdir(parents=True, exist_ok=True)

        # Rename original curl for system-wide installs only
        if self._mode == "system-wide" and self._curl_path.exists():
            shutil.move(str(self._curl_path), str(self._curl_real))

        # Create wrapper script
        wrapper = (
            "#!/bin/sh\n"
            f"export CURLGUARD_MODE={self._mode}\n"
            f"export CURLGUARD_REAL_CURL_PATH=\"{self._curl_real}\"\n"
            "exec curlguard \"$@\"\n"
        )
        self._curl_path.write_text(wrapper, encoding="utf-8")
        os.chmod(self._curl_path, 0o755)

    def uninstall(self) -> None:
        if self._mode == "per-user":
            if self._curl_path.exists():
                self._curl_path.unlink()
            return

        if not self._curl_real.exists():
            return

        # Remove wrapper
        if self._curl_path.exists():
            self._curl_path.unlink()

        # Restore original
        shutil.move(str(self._curl_real), str(self._curl_path))

    def call_real_curl(self, args: list[str], env: dict | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self._curl_real)] + args,
            env={**os.environ, **(env or {})},
            capture_output=True,
        )
