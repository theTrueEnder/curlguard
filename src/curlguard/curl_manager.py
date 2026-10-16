"""Install owned PATH wrappers without replacing package-owned executables."""

import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

MARKER = "# curlguard managed wrapper v2"


def _owned(path):
    if path.is_symlink() or not path.is_file():
        return False
    with path.open("rb") as handle:
        data = handle.read(8192)
    return MARKER.encode() in data


def _legacy_wrapper(path):
    if not path.is_file() or path.is_symlink():
        return False
    data = path.read_bytes()[:8192]
    return (
        data.startswith(b"#!/bin/sh\n")
        and b"CURLGUARD_REAL_CURL_PATH=" in data
        and b'exec curlguard "$@"' in data
    )


def _discover_system_curl():
    for candidate in (Path("/usr/bin/curl"), Path("/bin/curl")):
        if candidate.is_file():
            return candidate
    raise ValueError("install the distro curl package before installing curlguard")


class CurlManager:
    def __init__(self, mode="per-user", *, root=Path("/")):
        if mode not in {"per-user", "system-wide"}:
            raise ValueError("invalid installation mode")
        self._mode, self._root = mode, Path(root)
        self._curl_path = (
            Path.home() / ".local/bin/curl"
            if mode == "per-user"
            else self._root / "usr/local/bin/curl"
        )
        self._curl_real = (
            _discover_system_curl()
            if mode == "per-user"
            else self._root / "usr/bin/curl"
        )

    def is_installed(self):
        return _owned(self._curl_path) and self._curl_real.is_file()

    def install(self, *, migrate_legacy=False):
        legacy = self._root / "usr/bin/curl.real"
        if self._mode == "system-wide" and legacy.exists():
            if not migrate_legacy:
                raise ValueError(
                    "legacy curl.real detected; rerun installer with --migrate-legacy"
                )
            self._migrate_legacy()
        if self._curl_path.exists() or self._curl_path.is_symlink():
            if not _owned(self._curl_path) and not (
                self._mode == "per-user" and _legacy_wrapper(self._curl_path)
            ):
                raise ValueError(
                    f"refusing to replace unrelated executable: {self._curl_path}"
                )
        if not self._curl_real.is_file():
            raise ValueError("real curl is missing; install the distro curl package")
        with self._curl_real.open("rb") as handle:
            if b"curlguard" in handle.read(8192):
                raise ValueError("real curl points to a curlguard wrapper")
        if self._curl_path.resolve() == self._curl_real.resolve():
            raise ValueError("wrapper and real curl paths overlap")
        self._curl_path.parent.mkdir(parents=True, exist_ok=True)
        script = (
            "#!/bin/sh\n" + MARKER + "\n"
            f"export CURLGUARD_MODE={self._mode}\n"
            f"export CURLGUARD_REAL_CURL_PATH={shlex.quote(str(self._curl_real))}\n"
            f'exec {shlex.quote(os.path.abspath(sys.executable))} -m curlguard.cli --as-curl "$@"\n'
        )
        fd, name = tempfile.mkstemp(
            prefix=".curlguard-install-", dir=self._curl_path.parent
        )
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(script)
            os.chmod(name, 0o755)
            os.replace(name, self._curl_path)
        finally:
            Path(name).unlink(missing_ok=True)

    def _migrate_legacy(self):
        system = self._root / "usr/bin/curl"
        legacy = self._root / "usr/bin/curl.real"
        if not (_legacy_wrapper(system) or system.read_bytes().startswith(b"\x7fELF")):
            raise ValueError("unrecognized legacy installation; no files changed")
        backup = (
            self._root / "var/lib/curlguard" / ("legacy-backup-" + uuid.uuid4().hex)
        )
        backup.mkdir(parents=True, mode=0o700)
        shutil.copy2(system, backup / "curl")
        shutil.copy2(legacy, backup / "curl.real")
        # No saved binary is ever restored. Obtain and validate the current package instead.
        if self._root != Path("/"):
            raise ValueError("legacy migration requires the real distro root")
        owner = subprocess.run(
            ["/usr/bin/dpkg-query", "-S", "/usr/bin/curl"],
            capture_output=True,
            text=True,
            check=True,
        )
        if not owner.stdout.startswith("curl:"):
            raise ValueError("cannot verify distro ownership of /usr/bin/curl")
        subprocess.run(
            ["/usr/bin/apt-get", "install", "--reinstall", "-y", "curl"], check=True
        )
        expected = None
        for line in Path("/var/lib/dpkg/info/curl.md5sums").read_text().splitlines():
            digest, filename = line.split(maxsplit=1)
            if filename.strip() == "usr/bin/curl":
                expected = digest
        actual = hashlib.md5(system.read_bytes(), usedforsecurity=False).hexdigest()
        if (
            not expected
            or actual != expected
            or not system.read_bytes().startswith(b"\x7fELF")
        ):
            raise ValueError(
                f"reinstalled curl failed integrity check; backups retained in {backup}"
            )
        legacy.unlink()

    def uninstall(self):
        if self._mode == "system-wide" and (self._root / "usr/bin/curl.real").exists():
            raise ValueError(
                "legacy installation requires migration; refusing to restore stale curl.real"
            )
        if self._curl_path.exists() or self._curl_path.is_symlink():
            if not _owned(self._curl_path) and not (
                self._mode == "per-user" and _legacy_wrapper(self._curl_path)
            ):
                raise ValueError(
                    f"refusing to remove unrelated executable: {self._curl_path}"
                )
            self._curl_path.unlink()

    def call_real_curl(self, args, env=None):
        return subprocess.run(
            [str(self._curl_real), *args],
            env={**os.environ, **(env or {})},
            capture_output=True,
        )
