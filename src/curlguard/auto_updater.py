"""Auto-updater module for curlguard."""
from pathlib import Path
import time


class AutoUpdater:
    def __init__(self, config, scanner) -> None:
        self._config = config
        self._scanner = scanner
        self._last_update_file = self._get_last_update_file()

    def _get_last_update_file(self) -> Path:
        if self._config.mode == "per-user":
            return Path.home() / ".curlguard" / ".last_update"
        return Path("/var/lib/curlguard/.last_update")

    def should_update(self) -> bool:
        if not self._config.update_url:
            return False
        if not self._last_update_file.exists():
            return True

        # Check if update_interval_hours has passed
        age_hours = (time.time() - self._last_update_file.stat().st_mtime) / 3600
        return age_hours >= self._config.update_interval_hours

    def check_and_update(self) -> None:
        if not self.should_update():
            return

        try:
            self.fetch_rules(self._config.update_url)
            self.update_timestamp()
            self._scanner.reload_rules()
        except Exception as e:
            print(f"Rule update failed: {e}", file=__import__("sys").stderr)

    def fetch_rules(self, url: str) -> list[Path]:
        import requests
        downloaded = []
        rules_dir = self._config.quarantine_dir.parent / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)

        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            rule_file = rules_dir / "auto_update.yar"
            rule_file.write_bytes(resp.content)
            downloaded.append(rule_file)
        except Exception:
            pass
        return downloaded

    def update_timestamp(self) -> None:
        self._last_update_file.parent.mkdir(parents=True, exist_ok=True)
        self._last_update_file.touch()