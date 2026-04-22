"""Rules watcher module for curlguard."""
from pathlib import Path
from typing import Callable


class RulesWatcher:
    def __init__(self, rules_dirs: list[Path]) -> None:
        self._rules_dirs = rules_dirs
        self._last_mtimes = {}

    def load_all(self) -> dict[Path, object]:
        # Placeholder - returns empty dict until yara integration
        return {}

    def watch(self) -> list[Path]:
        changed = []
        for rules_dir in self._rules_dirs:
            if not rules_dir.is_dir():
                continue
            for yara_file in rules_dir.glob("*.yar"):
                mtime = yara_file.stat().st_mtime
                if yara_file not in self._last_mtimes or self._last_mtimes[yara_file] != mtime:
                    changed.append(yara_file)
                    self._last_mtimes[yara_file] = mtime
        return changed

    def auto_reload(self, callback: Callable) -> None:
        # Polling implementation - check every 5 seconds
        import time
        while True:
            changed = self.watch()
            if changed:
                callback()
            time.sleep(5)