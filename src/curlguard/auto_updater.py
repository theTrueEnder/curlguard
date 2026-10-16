"""Bounded, HTTPS-only, last-known-good rule updates with cross-process locking."""

import os
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit


class AutoUpdater:
    MAX_BYTES = 5 * 1024 * 1024

    def __init__(self, config, scanner):
        self._config, self._scanner = config, scanner
        self._base = config.quarantine_dir.parent
        self._last_update_file = self._base / ".last_update"
        self._failure_file = self._base / ".last_update_failure"

    def should_update(self):
        if not self._config.update_url:
            return False
        if (
            self._failure_file.exists()
            and time.time() - self._failure_file.stat().st_mtime < 300
        ):
            return False
        return (
            not self._last_update_file.exists()
            or time.time() - self._last_update_file.stat().st_mtime
            >= self._config.update_interval_hours * 3600
        )

    def check_and_update(self):
        if not self._config.update_url:
            return
        try:
            import fcntl

            self._base.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self._base / ".update.lock", os.O_CREAT | os.O_RDWR, 0o600)
            with os.fdopen(fd, "a") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return
                if not self.should_update():
                    return
                try:
                    self.fetch_rules(self._config.update_url)
                    self.update_timestamp()
                    self._failure_file.unlink(missing_ok=True)
                except Exception:
                    self._failure_file.touch(mode=0o600)
                    raise
        except Exception as exc:
            print(
                f"curlguard: rule update failed ({type(exc).__name__}); retaining active rules",
                file=sys.stderr,
            )

    def fetch_rules(self, url):
        import requests

        rules_dir = self._base / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, name = tempfile.mkstemp(prefix=".update-", suffix=".tmp", dir=rules_dir)
        staged = Path(name)
        target = rules_dir / "auto_update.yar"
        try:
            with os.fdopen(fd, "wb") as out, requests.Session() as session:
                for _ in range(6):
                    if urlsplit(url).scheme != "https":
                        raise ValueError(
                            "rule updates require HTTPS, including redirects"
                        )
                    response = session.get(
                        url, timeout=30, stream=True, allow_redirects=False
                    )
                    with response:
                        if response.is_redirect:
                            from urllib.parse import urljoin

                            url = urljoin(url, response.headers["Location"])
                            continue
                        response.raise_for_status()
                        if response.status_code != 200:
                            raise ValueError("rule update requires HTTP 200")
                        total = 0
                        for chunk in response.iter_content(65536):
                            total += len(chunk)
                            if total > self.MAX_BYTES:
                                raise ValueError("rule update exceeds 5 MiB")
                            out.write(chunk)
                        break
                else:
                    raise ValueError("too many rule update redirects")
            # Ensure the new file also participates in all subsequent reloads.
            paths = self._scanner._rules_paths
            original = list(paths)
            if rules_dir not in paths:
                paths.append(rules_dir)
            try:
                candidate = self._scanner.compile_candidate(staged, target)
                os.replace(staged, target)
                self._scanner.activate(candidate)
            except BaseException:
                paths[:] = original
                raise
            return [target]
        finally:
            staged.unlink(missing_ok=True)

    def update_timestamp(self):
        self._last_update_file.touch(mode=0o600)
