"""Manage optional curl shims without modifying an OS-owned curl binary."""

import os
import shutil
import subprocess
from pathlib import Path

MANAGED_MARKER = "# Managed by curlguard; safe to remove."


def _discover_system_curl() -> Path:
    for candidate in (
        Path("/usr/bin/curl"),
        Path("/usr/local/bin/curl"),
        Path("/bin/curl"),
    ):
        if candidate.is_file():
            return candidate
    discovered = shutil.which("curl", path="/usr/bin:/usr/local/bin:/bin")
    return Path(discovered) if discovered else Path("/usr/bin/curl")


class CurlManager:
    """Install an opt-in shim directory which users may add to PATH explicitly."""

    def __init__(self, mode: str = "per-user") -> None:
        if mode not in {"per-user", "system-wide"}:
            raise ValueError("mode must be 'per-user' or 'system-wide'")
        self._mode = mode
        if mode == "per-user":
            self._curl_path = Path.home() / ".local/libexec/curlguard/bin/curl"
        else:
            self._curl_path = Path("/usr/local/libexec/curlguard/bin/curl")
        self._curl_real = _discover_system_curl()

    def is_installed(self) -> bool:
        return self._is_managed_shim(self._curl_path)

    def install(self) -> None:
        if self._curl_path.exists() and not self._is_managed_shim(self._curl_path):
            raise FileExistsError(
                f"refusing to overwrite unmanaged file: {self._curl_path}"
            )
        if not self._curl_real.is_file():
            raise FileNotFoundError(f"real curl was not found at {self._curl_real}")

        self._curl_path.parent.mkdir(parents=True, exist_ok=True)
        wrapper = (
            "#!/bin/sh\n"
            f"{MANAGED_MARKER}\n"
            ': "${CURLGUARD_MODE:=per-user}"\n'
            "export CURLGUARD_MODE\n"
            f'export CURLGUARD_REAL_CURL_PATH="{self._curl_real}"\n'
            "export CURLGUARD_SHIM_ACTIVE=1\n"
            'exec curlguard "$@"\n'
        )
        temporary = self._curl_path.with_name(".curl.tmp")
        temporary.write_text(wrapper, encoding="utf-8")
        os.chmod(temporary, 0o755)
        os.replace(temporary, self._curl_path)

    def uninstall(self) -> None:
        if not self._curl_path.exists():
            return
        if not self._is_managed_shim(self._curl_path):
            raise RuntimeError(f"refusing to remove unmanaged file: {self._curl_path}")
        self._curl_path.unlink()

    def _is_managed_shim(self, path: Path) -> bool:
        try:
            return MANAGED_MARKER in path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return False

    def call_real_curl(
        self, args: list[str], env: dict | None = None
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self._curl_real), *args],
            env={**os.environ, **(env or {})},
            capture_output=True,
        )
