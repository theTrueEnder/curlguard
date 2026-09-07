"""Validated, atomic YARA rule updates for curlguard."""

import hashlib
import os
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen


class AutoUpdater:
    MAX_RULE_BYTES = 2 * 1024 * 1024
    LOCK_STALE_SECONDS = 300

    def __init__(self, config, scanner) -> None:
        self._config = config
        self._scanner = scanner
        self._last_update_file = self._get_last_update_file()
        self._lock_file = self._last_update_file.with_name(".update.lock")

    def _get_last_update_file(self) -> Path:
        if self._config.mode == "per-user":
            return Path.home() / ".curlguard" / ".last_update"
        return Path("/var/lib/curlguard/.last_update")

    def should_update(self) -> bool:
        if not self._config.update_url:
            return False
        if not self._last_update_file.exists():
            return True
        age_hours = (time.time() - self._last_update_file.stat().st_mtime) / 3600
        return age_hours >= self._config.update_interval_hours

    def check_and_update(self) -> None:
        if not self.should_update():
            return
        acquired = False
        try:
            acquired = self._acquire_lock()
            if not acquired:
                return
            downloaded = self.fetch_rules(self._config.update_url)
            if not downloaded:
                raise RuntimeError("the update did not contain a rule file")
            self._scanner.reload_rules()
            self.update_timestamp()
        except Exception as exc:
            print(f"curlguard: rule update failed: {exc}", file=sys.stderr)
        finally:
            if acquired:
                self._lock_file.unlink(missing_ok=True)

    def _acquire_lock(self) -> bool:
        self._lock_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self._lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                age = time.time() - self._lock_file.stat().st_mtime
                if age <= self.LOCK_STALE_SECONDS:
                    return False
                self._lock_file.unlink()
            except OSError:
                return False
            return self._acquire_lock()
        else:
            os.close(fd)
            return True

    def fetch_rules(self, url: str) -> list[Path]:
        if urlparse(url).scheme.lower() != "https":
            raise ValueError("rule updates require an https:// URL")

        rules_dir = self._rules_dir()
        rules_dir.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=".auto_update.", suffix=".yar", dir=rules_dir
        )
        temporary_path = Path(temporary_name)
        try:
            digest = hashlib.sha256()
            with os.fdopen(fd, "wb") as handle:
                with urlopen(url, timeout=30) as response:
                    if urlparse(response.geturl()).scheme.lower() != "https":
                        raise ValueError("rule update redirected to a non-HTTPS URL")
                    total = 0
                    while chunk := response.read(64 * 1024):
                        total += len(chunk)
                        if total > self.MAX_RULE_BYTES:
                            raise ValueError("rule update exceeds the 2 MiB limit")
                        handle.write(chunk)
                        digest.update(chunk)
            if temporary_path.stat().st_size == 0:
                raise ValueError("rule update was empty")
            expected_digest = self._config.update_sha256
            if expected_digest and digest.hexdigest() != expected_digest.lower():
                raise ValueError(
                    "rule update SHA-256 did not match CURLGUARD_UPDATE_SHA256"
                )

            import yara

            yara.compile(filepath=str(temporary_path))
            destination = rules_dir / "auto_update.yar"
            os.replace(temporary_path, destination)
            return [destination]
        finally:
            temporary_path.unlink(missing_ok=True)

    def _rules_dir(self) -> Path:
        if self._config.rules_dirs:
            return Path(self._config.rules_dirs[0])
        return self._config.quarantine_dir.parent / "rules"

    def update_timestamp(self) -> None:
        self._last_update_file.parent.mkdir(parents=True, exist_ok=True)
        self._last_update_file.touch()
